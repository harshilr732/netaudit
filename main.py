# main.py — entry point for NetAudit.
# Run it with:  python main.py

from rich.console import Console
from rich.panel import Panel

import config

console = Console()


def main():
    banner = (
        f"[bold cyan]{config.APP_NAME}[/bold cyan]  v{config.VERSION}\n"
        "Automated Vulnerability Assessment & Asset Auditing Tool"
    )
    console.print(Panel(banner, expand=False))
    console.print("[green]Environment setup complete. Ready for Phase 1.[/green]")


if __name__ == "__main__":
    main()