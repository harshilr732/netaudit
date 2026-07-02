"""
__main__.py — the command-line entry point that ties Phase 1 together.

Run it with:   python -m netaudit scan --targets 127.0.0.1 --out out/

Flow:  parse args -> NmapScanner.scan() -> build a Scan object -> save to SQLite
       -> export JSON + CSV -> print a human summary.

Everything here is orchestration only. The real work lives in the scanners/,
core/, and reporting/ modules so each piece stays testable on its own.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

from netaudit.core.models import Scan
from netaudit.core.storage import Database
from netaudit.reporting import export
from netaudit.scanners.nmap_scanner import NmapScanner, NmapError
from netaudit.scanners.nuclei_scanner import NucleiScanner, NucleiError, build_web_targets


def _cmd_scan(args: argparse.Namespace) -> int:
    targets = [t.strip() for t in args.targets.split(",") if t.strip()]
    print(f"[*] Targets: {', '.join(targets)}")
    print(f"[*] Mode: {'discovery-only' if args.discovery_only else 'service detection'}"
          f"{' + OS detection' if args.os else ''}"
          f"{' + default NSE scripts' if args.scripts else ''}"
          f"{' + NSE vuln scripts' if args.vuln else ''}"
          f"{' + Nuclei' if args.nuclei else ''}")

    scan = Scan(targets=args.targets)

    try:
        scanner = NmapScanner(timeout=args.timeout)
        hosts, nmap_version = scanner.scan(
            targets=targets,
            ports=args.ports,
            service_detection=not args.discovery_only,
            os_detection=args.os,
            default_scripts=args.scripts,
            vuln_scripts=args.vuln,
            discovery_only=args.discovery_only,
        )
    except NmapError as e:
        print(f"[!] {e}", file=sys.stderr)
        return 1

    scan.hosts = hosts
    scan.nmap_version = nmap_version

    # Optional: Nuclei against the web endpoints we just discovered
    if args.nuclei:
        web_targets = build_web_targets(scan.hosts)
        if not web_targets:
            print("[*] Nuclei: no web endpoints discovered, skipping.")
        else:
            print(f"[*] Nuclei: scanning {len(web_targets)} web endpoint(s)...")
            try:
                by_ip = {h.ip: h for h in scan.hosts}
                results = NucleiScanner(timeout=args.timeout).scan(list(web_targets))
                attached = 0
                for host_ip, finding in results:
                    host = by_ip.get(host_ip) or by_ip.get(web_targets.get(host_ip, ""))
                    if host is not None:
                        host.findings.append(finding)
                        attached += 1
                print(f"[*] Nuclei: {attached} finding(s).")
            except NucleiError as e:
                print(f"[!] Nuclei skipped: {e}", file=sys.stderr)

    scan.finished_at = datetime.now(timezone.utc).isoformat()

    # Persist (findings save automatically via the host records)
    db = Database(args.db)
    scan_id = db.save_scan(scan)
    db.close()

    # Export
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    json_path = out_dir / f"scan-{stamp}.json"
    csv_path = out_dir / f"scan-{stamp}.csv"
    export.to_json(scan, json_path)
    export.to_csv(scan, csv_path)

    total_findings = sum(len(h.findings) for h in scan.hosts)
    if total_findings:
        findings_path = out_dir / f"findings-{stamp}.csv"
        export.to_findings_csv(scan, findings_path)
        print(f"[+] {total_findings} finding(s) also written to {findings_path}")

    # Summary — use the rich renderer if available, else fall back to plain text
    try:
        from netaudit.reporting.console import render_summary
        render_summary(scan, scan_id, json_path, csv_path, args.db)
    except ImportError:
        _print_summary_plain(scan, scan_id, json_path, csv_path, args.db)
    return 0


def _print_summary_plain(scan: Scan, scan_id, json_path, csv_path, db_path) -> None:
    """Fallback summary used only if `rich` isn't installed (pip install -r requirements.txt)."""
    total_ports = sum(len(h.services) for h in scan.hosts)
    print(f"\n[+] Scan complete (nmap {scan.nmap_version}, scan_id={scan_id})")
    print(f"[+] Hosts up: {len(scan.hosts)}   Open services: {total_ports}")
    for h in scan.hosts:
        label = h.hostname or h.ip
        os_part = f"  [{h.os_name}]" if h.os_name else ""
        print(f"    - {h.ip} ({label}){os_part}: {len(h.services)} open")
        for s in sorted(h.services, key=lambda x: x.port):
            desc = " ".join(x for x in (s.product, s.version, s.extra_info) if x)
            print(f"        {s.port}/{s.protocol}  {s.name:<12} {desc}")
    print(f"\n[+] Saved: {json_path}")
    print(f"[+] Saved: {csv_path}")
    print(f"[+] Database: {db_path}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="netaudit",
        description="Read-only network asset discovery & auditing tool (Phase 1: discovery).",
    )
    sub = p.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Discover hosts and services on authorized targets.")
    scan.add_argument("--targets", required=True,
                      help="Comma-separated IPs / hostnames / CIDR you are AUTHORIZED to scan "
                           "(e.g. 127.0.0.1 or 192.168.1.0/24).")
    scan.add_argument("--ports", default=None, help="Port spec, e.g. '1-1000' or '22,80,443'. Default: nmap's top 1000.")
    scan.add_argument("--os", action="store_true", help="Attempt OS detection (needs admin/root).")
    scan.add_argument("--scripts", action="store_true", help="Run nmap's default safe NSE scripts (-sC).")
    scan.add_argument("--vuln", action="store_true",
                      help="Run nmap's NSE vulnerability scripts (safe subset only — no DoS/intrusive).")
    scan.add_argument("--nuclei", action="store_true",
                      help="Run Nuclei against discovered web endpoints (DoS/fuzz templates excluded).")
    scan.add_argument("--discovery-only", action="store_true", help="Ping scan only (who's up), no port scan.")
    scan.add_argument("--db", default="netaudit.db", help="SQLite database path. Default: netaudit.db")
    scan.add_argument("--out", default="out", help="Directory for JSON/CSV output. Default: out/")
    scan.add_argument("--timeout", type=int, default=900, help="Max seconds for the scan. Default: 900.")
    scan.set_defaults(func=_cmd_scan)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
