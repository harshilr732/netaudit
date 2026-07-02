"""
reporting/console.py — pretty terminal output for a scan.

Uses `rich` to render the scan summary as panels + tables instead of plain
print() lines. Lives in reporting/ (not __main__.py) on purpose: all output
formats — JSON, CSV, and now the terminal — belong together, and __main__.py
stays pure orchestration.

Note on scope: this module only *displays* what the scan found. It deliberately
does NOT decide which services are "insecure" — that judgement is the vuln
layer's job (Nmap NSE + Nuclei -> Finding objects). Keeping display and
judgement separate means either can change without touching the other.
"""

from __future__ import annotations

from pathlib import Path

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from netaudit.core.models import Scan, Severity

# Colour + ordering per severity, worst first.
_SEV_STYLE = {
    Severity.CRITICAL: ("bold white on red", 5),
    Severity.HIGH: ("bold red", 4),
    Severity.MEDIUM: ("yellow", 3),
    Severity.LOW: ("cyan", 2),
    Severity.INFO: ("dim", 1),
    Severity.UNKNOWN: ("magenta", 0),
}


def _sev_rank(sev: Severity) -> int:
    return _SEV_STYLE.get(sev, ("", 0))[1]


def _sev_style(sev: Severity) -> str:
    return _SEV_STYLE.get(sev, ("", 0))[0]


def render_summary(
    scan: Scan,
    scan_id: int,
    json_path: str | Path,
    csv_path: str | Path,
    db_path: str | Path,
    console: Console | None = None,
) -> None:
    console = console or Console()
    total_services = sum(len(h.services) for h in scan.hosts)

    # --- header panel: the scan's metadata at a glance ---
    header = (
        f"[bold]nmap[/] {scan.nmap_version or '?'}    "
        f"[bold]scan_id[/] {scan_id}\n"
        f"[bold]targets[/] {scan.targets}\n"
        f"[bold]hosts up[/] {len(scan.hosts)}    "
        f"[bold]open services[/] {total_services}"
    )
    console.print(Panel(header, title="[bold green]Scan complete[/]",
                        border_style="green", box=box.ROUNDED, expand=False))

    if not scan.hosts:
        console.print("[yellow]No live hosts found.[/]")
        return

    # --- one table per host: its open services ---
    for host in scan.hosts:
        label = host.hostname or host.ip
        title = f"[bold]{host.ip}[/]  ([cyan]{label}[/])"
        if host.os_name:
            acc = f" {host.os_accuracy}%" if host.os_accuracy is not None else ""
            title += f"   ·   [magenta]{host.os_name}[/]{acc}"

        table = Table(title=title, title_justify="left", box=box.SIMPLE_HEAD,
                      header_style="bold", pad_edge=False, expand=False)
        table.add_column("Port", justify="right", style="yellow", no_wrap=True)
        table.add_column("Proto", style="dim")
        table.add_column("Service", style="cyan")
        table.add_column("Product / Version")

        if not host.services:
            console.print(table)
            console.print("    [dim]no open ports[/]")
            continue

        for s in sorted(host.services, key=lambda x: x.port):
            version = " ".join(x for x in (s.product, s.version, s.extra_info) if x)
            table.add_row(
                str(s.port),
                s.protocol,
                s.name or "[dim]—[/]",
                version or "[dim]—[/]",
            )
        console.print(table)

    # --- findings table (only if the vuln layer produced any) ---
    _render_findings(scan, console)

    # --- where everything was written ---
    console.print()
    console.print(f"  [green]JSON[/]  {json_path}")
    console.print(f"  [green]CSV [/]  {csv_path}")
    console.print(f"  [green]DB  [/]  {db_path}")


def _render_findings(scan: Scan, console: Console) -> None:
    rows = []
    for host in scan.hosts:
        for f in host.findings:
            rows.append((host, f))
    if not rows:
        return

    # worst severity first; within a severity, confirmed before tentative
    conf_rank = {"confirmed": 2, "firm": 1, "tentative": 0}
    rows.sort(key=lambda r: (_sev_rank(r[1].severity),
                             conf_rank.get(r[1].confidence.value, 0)), reverse=True)

    console.print()
    table = Table(title="[bold]Findings[/]", title_justify="left", box=box.SIMPLE_HEAD,
                  header_style="bold", pad_edge=False, expand=False)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Host", style="cyan", no_wrap=True)
    table.add_column("Port", justify="right", style="yellow")
    table.add_column("Source", style="dim")
    table.add_column("Finding")
    table.add_column("CVE", style="magenta")
    table.add_column("Conf.", style="dim")

    for host, f in rows:
        sev = f.severity
        sev_cell = f"[{_sev_style(sev)}] {sev.value.upper()} [/]"
        table.add_row(
            sev_cell,
            host.ip,
            str(f.port) if f.port else "-",
            f.source,
            f.title,
            f.cve or "-",
            f.confidence.value,
        )
    console.print(table)

    # quick severity tally
    counts: dict[Severity, int] = {}
    for _, f in rows:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    tally = "   ".join(
        f"[{_sev_style(s)}]{s.value}: {counts[s]}[/]"
        for s in sorted(counts, key=_sev_rank, reverse=True)
    )
    console.print(f"  {len(rows)} finding(s):   {tally}")
