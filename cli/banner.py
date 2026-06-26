"""
cli/banner.py
──────────────────────────────────────────────────────────────
Styled ASCII art banner for GhostTrace CLI.
"""

from __future__ import annotations

from rich.console import Console
from rich.text import Text
from rich.panel import Panel

BANNER = r"""
   _____ _               _   _____
  / ____| |             | | |_   _|
 | |  __| |__   ___  ___| |_  | |  _ __ __ _  ___ ___
 | | |_ | '_ \ / _ \/ __| __| | | | '__/ _` |/ __/ _ \
 | |__| | | | | (_) \__ \ |_ _| |_| | | (_| | (_|  __/
  \_____|_| |_|\___/|___/\__|_____|_|  \__,_|\___\___|
"""

VERSION = "1.0.0"
TAGLINE = "AI-Powered Memory Forensics · Fileless Malware Detection"


def print_banner(console: Console | None = None) -> None:
    """Print the styled GhostTrace banner."""
    if console is None:
        console = Console()

    banner_text = Text(BANNER, style="bold cyan")
    info = (
        f"[dim cyan]Version:[/] [bold white]{VERSION}[/]  |  "
        f"[dim cyan]Mode:[/] [bold green]Interactive[/]  |  "
        f"[dim cyan]{TAGLINE}[/]"
    )
    console.print(banner_text)
    console.print(info, justify="center")
    console.print()


def print_section(console: Console, title: str, style: str = "bold blue") -> None:
    """Print a styled section header."""
    console.print(Panel(f"[{style}]{title}[/]", expand=False))
