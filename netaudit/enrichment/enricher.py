"""
enrichment/enricher.py — Phase 3 orchestrator.

WHAT THIS DOES
    Runs over a completed Scan (after Phase 1 scanning + Phase 2 credentialed
    collection) and *enriches* it in place, so your existing db.save_scan(scan)
    then persists everything with no schema change:

      1. CVE enrichment (Path A) — for findings that already carry a CVE ID
         (from Nuclei / Nmap NSE), look the CVE up in NVD and fill in the real
         CVSS score + severity. Confidence stays FIRM (a scanner matched it).
      2. End-of-life flags — for hosts whose OS was CONFIRMED by credentialed
         collection, flag it if it's out of support. Confidence CONFIRMED.
      3. Insecure-protocol flags — plaintext services (Telnet, FTP, plain HTTP)
         observed on the wire. Confidence FIRM.
      4. Patch currency — a conservative, clearly-hedged note when a host's
         newest recorded patch is very old. Deliberately low-severity because
         installed-hotfix data is an imperfect signal (honest-reporting rule).

    NOTE the function is called run_enrichment(), NOT enrich_scan() — your Phase 2
    orchestrator already owns enrich_scan(), so we avoid the name clash.

WHY IN-PLACE + IDEMPOTENT
    We mutate scan.hosts[*].findings directly, then let your normal save run.
    Re-running is safe: we first drop any findings this module generated last
    time (by their `source` tag) before regenerating, so nothing duplicates.

READ-ONLY: enrichment only reads already-collected data + public APIs.
"""
from __future__ import annotations

import re
from datetime import date, datetime
from typing import Optional

from .nvd import NvdClient
from .eol import EolClient, eol_finding
from ..core.models import Scan, Host, Finding, Severity, Confidence

# Findings this module creates. We clear these before regenerating (idempotency).
# Scanner findings (source "nuclei", "nmap-nse", ...) are NEVER cleared.
GENERATED_SOURCES = {"eol", "insecure-protocol", "patch-currency"}

# Plaintext / insecure services, keyed by nmap's service name (port as backup).
# severity chosen to avoid crying wolf: Telnet is serious, plain HTTP is a nudge.
INSECURE_SERVICES = {
    "telnet": (Severity.HIGH, "Telnet is enabled (credentials sent in plaintext)."),
    "ftp":    (Severity.MEDIUM, "FTP is enabled (credentials and data sent in plaintext)."),
    "rlogin": (Severity.HIGH, "rlogin is enabled (insecure legacy remote access)."),
    "rsh":    (Severity.HIGH, "rsh is enabled (insecure legacy remote access)."),
    "http":   (Severity.INFO, "Service serves plain HTTP (no transport encryption)."),
}
INSECURE_PORTS = {23: "telnet", 21: "ftp", 513: "rlogin", 514: "rsh"}

PATCH_STALE_DAYS = 180  # only flag genuinely stale machines


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------
def run_enrichment(
    scan: Scan,
    nvd_client: Optional[NvdClient] = None,
    eol_client: Optional[EolClient] = None,
    do_patch_currency: bool = True,
) -> Scan:
    """Enrich a scan in place and return it. Call this just before save_scan()."""
    nvd = nvd_client or NvdClient()
    eol = eol_client or EolClient()

    for host in scan.hosts:
        # 0. Remove findings we generated on a previous run (keeps re-runs clean).
        host.findings = [f for f in host.findings if f.source not in GENERATED_SOURCES]

        _enrich_cves(host, nvd)          # 1. Path A
        _check_eol(host, eol)            # 2. EOL
        _flag_insecure_protocols(host)   # 3. insecure services
        if do_patch_currency:
            _check_patch_currency(host)  # 4. patch currency

    return scan


# ---------------------------------------------------------------------------
# 1. CVE enrichment (Path A) — fill CVSS + severity on findings that have a CVE
# ---------------------------------------------------------------------------
def _enrich_cves(host: Host, nvd: NvdClient) -> None:
    for f in host.findings:
        if not f.cve:
            continue
        parsed = nvd.get_cve(f.cve)
        if parsed is None or parsed.cvss is None:
            continue  # unknown CVE, or NVD hasn't scored it yet (enrichment backlog)

        f.cvss = parsed.score
        f.severity = parsed.severity  # CVSS is authoritative — trust NVD's rating

        # Fold provenance into the existing description column (no schema change).
        note = f"CVSS {parsed.cvss.base_score} ({parsed.cvss.version}) {parsed.cvss.vector}".strip()
        f.description = (f.description + "  " if f.description else "") + note

        # Add NVD references without duplicating.
        for url in (parsed.references or []):
            if url and url not in f.references:
                f.references.append(url)


# ---------------------------------------------------------------------------
# 2. End-of-life — only from a CONFIRMED (credentialed) OS
# ---------------------------------------------------------------------------
def _check_eol(host: Host, eol: EolClient) -> None:
    cred = getattr(host, "credentialed", None)
    os_info = getattr(cred, "os", None) if cred else None
    if not os_info:
        return  # no confirmed OS -> we don't guess EOL (nmap fingerprints aren't precise enough)

    result = eol.check_os(os_info)
    finding = eol_finding(result, Confidence.CONFIRMED)
    if finding:
        host.findings.append(finding)


# ---------------------------------------------------------------------------
# 3. Insecure protocols — plaintext services seen on the wire
# ---------------------------------------------------------------------------
def _flag_insecure_protocols(host: Host) -> None:
    for svc in host.services:
        if svc.state != "open":
            continue
        name = (svc.name or "").lower()
        # HTTPS/SSL services share the "http" name sometimes — skip if encrypted.
        if name == "http" and ("ssl" in name or svc.port == 443):
            continue
        key = name if name in INSECURE_SERVICES else INSECURE_PORTS.get(svc.port, "")
        if not key or key not in INSECURE_SERVICES:
            continue
        severity, text = INSECURE_SERVICES[key]
        host.findings.append(Finding(
            source="insecure-protocol",
            title=f"Insecure service: {key} on port {svc.port}",
            severity=severity,
            confidence=Confidence.FIRM,   # directly observed, not credentialed
            port=svc.port,
            description=text + " Prefer an encrypted alternative (e.g. SSH/SFTP/HTTPS).",
        ))


# ---------------------------------------------------------------------------
# 4. Patch currency — conservative, hedged, from credentialed patch list
# ---------------------------------------------------------------------------
def _check_patch_currency(host: Host) -> None:
    cred = getattr(host, "credentialed", None)
    patches = getattr(cred, "patches", None) if cred else None
    if not patches:
        return

    dates = [d for d in (_parse_patch_date(p.installed_on) for p in patches) if d]
    if not dates:
        return  # couldn't parse any install date -> stay silent rather than false-alarm

    newest = max(dates)
    age = (date.today() - newest).days
    if age <= PATCH_STALE_DAYS:
        return

    host.findings.append(Finding(
        source="patch-currency",
        title="Patching may be out of date",
        severity=Severity.LOW,
        confidence=Confidence.FIRM,
        description=(f"Newest recorded patch is {age} days old (installed {newest}). "
                     f"This is a heuristic from installed-update data — verify the host's "
                     f"actual update status."),
    ))


def _parse_patch_date(raw: Optional[str]) -> Optional[date]:
    """Best-effort parse of a WMI/QuickFixEngineering InstalledOn string."""
    raw = (raw or "").strip()
    if not raw:
        return None
    # CIM datetime, e.g. "20211012000000.000000-000"
    if len(raw) >= 8 and raw[:8].isdigit():
        try:
            return date(int(raw[0:4]), int(raw[4:6]), int(raw[6:8]))
        except ValueError:
            pass
    for fmt in ("%Y-%m-%d", "%m/%d/%Y", "%d/%m/%Y", "%m/%d/%y", "%d-%m-%Y"):
        try:
            return datetime.strptime(raw, fmt).date()
        except ValueError:
            continue
    return None


# ---------------------------------------------------------------------------
# Demo: python -m netaudit.enrichment.enricher
# Builds a tiny fake scan and enriches it (the CVE lookup hits NVD once).
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    from ..core.models import Service, OSInfo, CredentialedData, CollectionStatus

    host = Host(ip="192.0.2.10")
    host.services = [Service(port=23, name="telnet"), Service(port=80, name="http")]
    host.findings = [Finding(source="nuclei", title="Log4Shell", cve="CVE-2021-44228",
                             confidence=Confidence.FIRM)]
    host.credentialed = CredentialedData(
        status=CollectionStatus.SUCCESS,
        os=OSInfo(family="windows", product="Windows 10 Pro", version="10.0.19045", build="19045"),
    )
    scan = Scan(targets="192.0.2.10")
    scan.hosts = [host]

    run_enrichment(scan)

    for f in host.findings:
        print(f"[{f.severity.value:<8}] [{f.confidence.value:<9}] {f.title}"
              + (f"  (CVSS {f.cvss})" if f.cvss else ""))
