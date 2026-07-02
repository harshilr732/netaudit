"""
scanners/nuclei_scanner.py — template-based vulnerability detector.

Nuclei matches a huge community library of templates (known CVEs, exposures,
misconfigurations) against targets and reports what it finds. Same pattern as
the nmap wrapper: run the binary, capture its output, normalize into Finding
objects. Nuclei emits one JSON object per finding ("JSON Lines"), which is easy
and robust to parse.

Two safety decisions, both to honor the build guide's "read-only, no DoS":
  1. We pass `-etags dos,fuzz` so denial-of-service and fuzzing templates never
     run. Nuclei is detection-oriented by default, but this makes it explicit.
  2. We only point Nuclei at web endpoints we actually DISCOVERED (from the nmap
     results), not at wide-open target ranges — narrower, faster, and it never
     probes services the client didn't expose.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from netaudit.core.models import Confidence, Finding, Host, Severity

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# Nuclei severity strings map straight onto our Severity enum.
_SEVERITY_MAP = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}

# Ports we'll treat as web endpoints worth handing to Nuclei.
_WEB_PORTS = {80, 443, 591, 2082, 2087, 2095, 2096, 3000, 8000, 8008, 8080,
              8081, 8443, 8888, 9000, 9090, 9443}
_TLS_PORTS = {443, 8443, 9443, 2083, 2087, 2096}


class NucleiError(RuntimeError):
    """Raised when nuclei is missing or the scan fails."""


def _require_nuclei() -> str:
    path = shutil.which("nuclei")
    if not path:
        raise NucleiError(
            "nuclei is not installed or not on your PATH.\n"
            "  Install (needs Go): go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest\n"
            "  or download a release binary from https://github.com/projectdiscovery/nuclei/releases\n"
            "  Then run `nuclei -update-templates` once."
        )
    return path


def build_web_targets(hosts: list[Host]) -> dict[str, str]:
    """
    From discovered services, build a {url: host_ip} map of web endpoints.

    A service counts as web if its nmap name contains 'http' OR it sits on a
    known web port. https/ssl services (or TLS ports) get an https:// URL.
    Returning the ip alongside each url lets us attach findings back to the
    right Host afterwards.
    """
    targets: dict[str, str] = {}
    for host in hosts:
        for svc in host.services:
            name = svc.name.lower()
            is_web = "http" in name or svc.port in _WEB_PORTS
            if not is_web:
                continue
            is_tls = ("https" in name or "ssl" in name or "tls" in name
                      or svc.port in _TLS_PORTS)
            scheme = "https" if is_tls else "http"
            targets[f"{scheme}://{host.ip}:{svc.port}"] = host.ip
    return targets


def _parse_jsonl(stdout: str) -> list[tuple[str, Finding]]:
    """Parse Nuclei's JSON-Lines output into (host_ip, Finding) pairs."""
    results: list[tuple[str, Finding]] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue  # skip any non-JSON banner line defensively

        info = obj.get("info", {})
        template_id = obj.get("template-id", "") or obj.get("templateID", "")
        sev_str = str(info.get("severity", "unknown")).lower()

        # References may be a list or a single string depending on template.
        refs = info.get("reference") or []
        if isinstance(refs, str):
            refs = [refs]

        # CVE: prefer an explicit classification, else scan id/tags/name.
        cve = ""
        haystack = " ".join([
            template_id,
            " ".join(info.get("tags", []) if isinstance(info.get("tags"), list) else [str(info.get("tags", ""))]),
            info.get("name", ""),
        ])
        m = _CVE_RE.search(haystack)
        if m:
            cve = m.group(0).upper()

        matched_at = obj.get("matched-at") or obj.get("matched") or ""
        host_ip = obj.get("ip") or obj.get("host") or ""
        # host field is often a URL like http://1.2.3.4:80 — pull the ip/host out.
        host_ip = re.sub(r"^\w+://", "", host_ip).split(":")[0].split("/")[0]

        # try to recover the port from matched-at for nicer reporting
        port = None
        pm = re.search(r":(\d{2,5})(?:/|$)", matched_at)
        if pm:
            port = int(pm.group(1))

        finding = Finding(
            source="nuclei",
            title=info.get("name") or template_id or "nuclei finding",
            severity=_SEVERITY_MAP.get(sev_str, Severity.UNKNOWN),
            confidence=Confidence.FIRM,  # a template matched; strong but not host-verified
            port=port,
            cve=cve,
            description=(info.get("description") or "").strip(),
            references=[r for r in refs if r],
        )
        results.append((host_ip, finding))
    return results


class NucleiScanner:
    """Thin, safe wrapper around the nuclei binary."""

    def __init__(self, timeout: int = 1800):
        self.nuclei_path = _require_nuclei()
        self.timeout = timeout

    def scan(self, urls: list[str]) -> list[tuple[str, Finding]]:
        """Run nuclei against the given URLs; return (host_ip, Finding) pairs."""
        if not urls:
            return []

        # Feed targets via a temp file (-l) — cleaner than a huge command line.
        tmp = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8")
        try:
            tmp.write("\n".join(urls))
            tmp.close()

            cmd = [
                self.nuclei_path,
                "-l", tmp.name,
                "-jsonl",                 # one JSON object per finding, to stdout
                "-silent",                # suppress the banner/progress noise
                "-disable-update-check",  # no network call to check for updates
                "-etags", "dos,fuzz",     # SAFETY: never run DoS or fuzzing templates
            ]
            try:
                proc = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=self.timeout, check=False
                )
            except subprocess.TimeoutExpired:
                raise NucleiError(f"nuclei timed out after {self.timeout}s. Try fewer targets.")

            # nuclei returns non-zero in some no-result situations; only treat it
            # as an error if we also got nothing usable on stdout.
            if proc.returncode not in (0,) and not proc.stdout.strip():
                raise NucleiError(f"nuclei failed:\n{proc.stderr.strip()}")

            return _parse_jsonl(proc.stdout)
        finally:
            Path(tmp.name).unlink(missing_ok=True)
