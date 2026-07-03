"""
collectors/orchestrator.py — Phase 2

The glue between Phase 1 (network scan) and the credentialed collectors.

Flow:
    scan = <built by your Phase 1 pipeline>
    enrich_scan(scan, store)        # <-- this module: logs in, merges, adds findings
    db.save_scan(scan)              # <-- your existing Phase 1 storage call

For every host the scan discovered, enrich_scan():
  1. resolves the credential whose subnet rule covers the host IP,
  2. picks the collector by that credential's transport (ssh -> Linux,
     winrm -> Windows),
  3. runs the collector (read-only) and attaches the result to host.credentialed,
  4. derives Finding objects from the result and appends them to host.findings
     so they persist and report through your EXISTING pipeline unchanged.

Design note — collector selection: transport comes from the credential rule, so
you configure "this subnet is Windows / this subnet is Linux" in your credentials
config. For mixed subnets you could later pick the collector from open ports
discovered in Phase 1 (5985/445 -> winrm, 22 -> ssh); not needed yet.

Scope note: findings here are FACT-ONLY (AV state, collection success). EOL and
missing-patch judgements need endoflife.date + NVD and belong to Phase 3.
"""

from __future__ import annotations

from ..core.credentials import CredentialStore, Transport
from ..core.models import (
    CollectionStatus,
    Confidence,
    CredentialedData,
    Finding,
    Host,
    Scan,
    Severity,
)
from .base import Collector
from .linux_ssh import LinuxSSHCollector
from .windows_winrm import WindowsWinRMCollector

# One instance each; collectors are stateless.
_COLLECTORS: dict[str, Collector] = {
    Transport.SSH.value: LinuxSSHCollector(),
    Transport.WINRM.value: WindowsWinRMCollector(),
}


def enrich_scan(scan: Scan, store: CredentialStore, timeout: int = 30) -> None:
    """Mutate `scan` in place. Call AFTER the Phase 1 scan is built and BEFORE
    db.save_scan(scan)."""
    for host in scan.hosts:
        credential = store.for_host(host.ip)
        if credential is None:
            continue  # no credential configured for this host's subnet
        collector = _COLLECTORS.get(credential.transport.value)
        if collector is None:
            continue
        data = collector.collect(host.ip, credential, timeout=timeout)
        host.credentialed = data
        _apply_to_host(host, data)


def _apply_to_host(host: Host, data: CredentialedData) -> None:
    # A host we couldn't fully assess must not look "clean" in a report.
    if data.status is not CollectionStatus.SUCCESS:
        host.findings.append(Finding(
            source="collector",
            title=f"Credentialed check incomplete ({data.status.value})",
            severity=Severity.INFO,
            confidence=Confidence.CONFIRMED,
            description=data.message or "No credentialed data collected.",
        ))
        return

    # Replace the inferred OS guess with the confirmed one.
    if data.os and data.os.product:
        host.os_name = data.os.product
        host.os_accuracy = 100  # confirmed by login, not an nmap inference

    host.findings.extend(_av_findings(data))


def _av_findings(data: CredentialedData) -> list[Finding]:
    findings: list[Finding] = []
    av_products = data.av_products

    if not av_products:
        findings.append(Finding(
            source="rule",
            title="No antivirus product detected",
            severity=Severity.MEDIUM,
            confidence=Confidence.FIRM,
            description=("No AV product was returned by the credentialed check. "
                         "On some Windows Server SKUs this can also mean AV state "
                         "could not be read; verify manually."),
        ))
        return findings

    # The passive-Defender guard: if ANY product has real-time protection on,
    # the host is protected and a separate disabled product (e.g. Defender in
    # passive mode behind Sophos) is NOT a finding.
    any_enabled = any(p.enabled for p in av_products)
    if not any_enabled:
        names = ", ".join(sorted({p.name for p in av_products})) or "unknown"
        findings.append(Finding(
            source="rule",
            title="Antivirus real-time protection disabled",
            severity=Severity.HIGH,
            confidence=Confidence.CONFIRMED,
            description=(f"No enabled AV real-time protection found. "
                         f"Products present: {names}."),
        ))

    # Stale signatures on a product that IS active.
    for product in av_products:
        if product.enabled and product.up_to_date is False:
            findings.append(Finding(
                source="rule",
                title=f"Antivirus signatures out of date ({product.name})",
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                description="The active AV product reports out-of-date definitions.",
            ))

    return findings
