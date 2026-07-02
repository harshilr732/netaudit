"""
reporting/export.py — Phase 1 output.

Phase 1's deliverable is a simple, honest inventory dump: JSON (full structure,
good for feeding other tools) and CSV (flat, one row per open service, good for
opening in Excel and eyeballing). The polished client-facing PDF + Excel reports
come in Phase 4 and will live in this same reporting/ package.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

from netaudit.core.models import Scan


def to_json(scan: Scan, path: str | Path) -> None:
    Path(path).write_text(json.dumps(scan.to_dict(), indent=2), encoding="utf-8")


def to_findings_csv(scan: Scan, path: str | Path) -> int:
    """One row per finding. Returns the number of findings written."""
    columns = ["ip", "hostname", "port", "source", "severity", "confidence",
               "title", "cve", "cvss", "description", "references"]
    count = 0
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=columns)
        writer.writeheader()
        for host in scan.hosts:
            for f in host.findings:
                writer.writerow({
                    "ip": host.ip,
                    "hostname": host.hostname or "",
                    "port": f.port if f.port is not None else "",
                    "source": f.source,
                    "severity": f.severity.value,
                    "confidence": f.confidence.value,
                    "title": f.title,
                    "cve": f.cve,
                    "cvss": f.cvss if f.cvss is not None else "",
                    "description": " ".join(f.description.split()),  # flatten newlines for CSV
                    "references": "; ".join(f.references),
                })
                count += 1
    return count


def to_csv(scan: Scan, path: str | Path) -> None:
    """Flat inventory: one row per (host, service). Hosts with no open ports still get a row."""
    columns = [
        "ip", "hostname", "os_name", "os_accuracy", "mac", "vendor",
        "port", "protocol", "service", "product", "version", "extra_info",
    ]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=columns)
        writer.writeheader()
        for host in scan.hosts:
            base = {
                "ip": host.ip,
                "hostname": host.hostname or "",
                "os_name": host.os_name or "",
                "os_accuracy": host.os_accuracy if host.os_accuracy is not None else "",
                "mac": host.mac or "",
                "vendor": host.vendor or "",
            }
            if not host.services:
                writer.writerow({**base, "port": "", "protocol": "", "service": "",
                                 "product": "", "version": "", "extra_info": ""})
            for svc in host.services:
                writer.writerow({
                    **base,
                    "port": svc.port,
                    "protocol": svc.protocol,
                    "service": svc.name,
                    "product": svc.product,
                    "version": svc.version,
                    "extra_info": svc.extra_info,
                })
