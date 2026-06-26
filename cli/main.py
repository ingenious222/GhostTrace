"""
cli/main.py
──────────────────────────────────────────────────────────────
GhostTrace CLI entry point.
Provides commands: analyze, interactive, score, report, verify-dump
"""

from __future__ import annotations

import json
import logging
import os
import pathlib
import sys

import click
from dotenv import load_dotenv
from rich.console import Console

# Load .env before anything else
load_dotenv()

console = Console()


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def _set_mock_mode(mock: bool) -> None:
    if mock:
        os.environ["MEMFORENSIC_MOCK"] = "1"
        console.print("[yellow]⚠ MOCK MODE ENABLED — using fixture data (no real Volatility runs)[/]")


# ── CLI Group ──────────────────────────────────────────────────────────────

@click.group()
@click.version_option("1.0.0", prog_name="GhostTrace")
def cli() -> None:
    """
    \b
    GhostTrace — Fileless Malware Memory Forensics Tool
    Semi-automated AI-driven memory forensic investigation platform.
    """
    pass


# ── interactive ────────────────────────────────────────────────────────────

@cli.command()
@click.option("--dump",   "-d", default=None, help="Path to memory dump file (.mem/.raw/.dmp)")
@click.option("--output", "-o", default="./output", show_default=True, help="Output directory for reports")
@click.option("--mock",   is_flag=True, default=False, help="Use mock fixture data (no real Volatility)")
@click.option("--verbose","-v", is_flag=True, default=False, help="Enable verbose/debug logging")
def interactive(dump: str | None, output: str, mock: bool, verbose: bool) -> None:
    """Start an interactive forensic investigation REPL."""
    _setup_logging(verbose)
    _set_mock_mode(mock)

    from cli.interactive import InteractiveSession
    session = InteractiveSession(dump_path=dump, output_dir=output)
    session.run()


# ── analyze ────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--dump",   "-d", required=True, help="Path to memory dump file")
@click.option("--query",  "-q",
    default="Run a complete forensic analysis: check processes, injections, PowerShell, "
            "network connections, score threats, build timeline, and generate a report.",
    show_default=True,
    help="Forensic investigation prompt"
)
@click.option("--output", "-o", default="./output", show_default=True, help="Output directory")
@click.option("--mock",   is_flag=True, default=False, help="Use mock fixture data")
@click.option("--verbose","-v", is_flag=True, default=False, help="Verbose logging")
def analyze(dump: str, query: str, output: str, mock: bool, verbose: bool) -> None:
    """
    Run a one-shot forensic analysis on a memory dump.

    The AI investigator will execute the analysis, score threats,
    reconstruct the timeline, and generate a PDF forensic report.
    """
    _setup_logging(verbose)
    _set_mock_mode(mock)

    from cli.banner import print_banner
    from core.agent import MemForensicAgent

    print_banner(console)
    console.print(f"[cyan]Memory dump:[/] {dump}")
    console.print(f"[cyan]Query:[/] {query}\n")

    agent = MemForensicAgent()

    # Augment query with dump path and output dir
    full_query = (
        f"{query}\n\n"
        f"[Context: memory_dump_path={dump}, output_dir={output}]"
    )

    with console.status("[bold cyan]Running forensic investigation…", spinner="dots"):
        answer = agent.run(full_query)

    console.print("\n[bold green]═══ Final Forensic Assessment ═══[/]")
    from rich.markdown import Markdown
    console.print(Markdown(answer))
    console.print()

    # Save session
    session_file = pathlib.Path(output) / "last_session.json"
    session_file.parent.mkdir(parents=True, exist_ok=True)
    session_file.write_text(json.dumps(agent.get_session_data(), indent=2, default=str))
    console.print(f"[dim]Session saved to: {session_file}[/]")


# ── score ──────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--artifacts", "-a", required=True, help="Path to JSON file with collected artefacts")
@click.option("--verbose",   "-v", is_flag=True)
def score(artifacts: str, verbose: bool) -> None:
    """Score threats from a pre-collected artefacts JSON file."""
    _setup_logging(verbose)

    from tools.threat_scorer import score_threats

    try:
        data = json.loads(pathlib.Path(artifacts).read_text())
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        console.print(f"[red]Error reading artefacts file: {exc}[/]")
        sys.exit(1)

    result = score_threats(**data)
    console.print_json(json.dumps(result, indent=2))


# ── report ─────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--session", "-s", required=True, help="Path to saved session JSON file")
@click.option("--output",  "-o", default="./output", show_default=True)
@click.option("--verbose", "-v", is_flag=True)
def report(session: str, output: str, verbose: bool) -> None:
    """Generate a forensic report from a saved session JSON file."""
    _setup_logging(verbose)

    from reporting.report_generator import generate_report

    try:
        session_data = json.loads(pathlib.Path(session).read_text())
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        console.print(f"[red]Error reading session file: {exc}[/]")
        sys.exit(1)

    console.print("[cyan]Generating forensic report…[/]")
    # Extract tool results from session
    tool_results = _extract_tool_results(session_data.get("tool_calls", []))

    result = generate_report(
        dump_path=tool_results.get("dump_path", "session_analysis"),
        threat_score=tool_results.get("threat_score", {"score": 0, "level": "UNKNOWN"}),
        output_dir=output,
        **{k: v for k, v in tool_results.items() if k not in ("dump_path", "threat_score")},
    )

    console.print(f"\n[bold green]✓ Report generated![/]")
    console.print(f"  PDF:  [bold]{result.get('pdf', 'N/A')}[/]")
    console.print(f"  HTML: {result.get('html', 'N/A')}")
    console.print(f"  JSON: {result.get('json', 'N/A')}")


# ── verify-dump ────────────────────────────────────────────────────────────

@cli.command("verify-dump")
@click.argument("dump_path")
@click.option("--hash", "-H", "expected_hash", default=None, help="Expected SHA-256 hash")
@click.option("--verbose", "-v", is_flag=True)
def verify_dump(dump_path: str, expected_hash: str | None, verbose: bool) -> None:
    """Verify the integrity of a memory dump file (SHA-256 hash)."""
    _setup_logging(verbose)

    from tools.acquisition import verify_dump_integrity

    console.print(f"[cyan]Verifying:[/] {dump_path}")
    result = verify_dump_integrity(dump_path, expected_hash)
    console.print_json(json.dumps(result, indent=2))

    if result.get("integrity_verified") is False:
        console.print("[bold red]❌ HASH MISMATCH — dump integrity FAILED[/]")
        sys.exit(1)
    elif result.get("integrity_verified") is True:
        console.print("[bold green]✓ Hash verified — dump integrity confirmed.[/]")


# ── Helpers ────────────────────────────────────────────────────────────────

def _extract_tool_results(tool_calls: list[dict]) -> dict:
    """Extract relevant data from session tool call log."""
    results: dict = {}
    tool_map = {
        "run_pslist": "pslist_data",
        "run_malfind": "malfind_data",
        "run_netscan": "netscan_data",
        "run_cmdline": "cmdline_data",
        "detect_process_anomalies": "process_anomalies",
        "detect_suspicious_connections": "network_anomalies",
        "decode_powershell_commands": "powershell_findings",
        "extract_iocs": "iocs",
        "score_threats": "threat_score",
        "build_attack_timeline": "timeline",
        "verify_dump_integrity": "dump_info",
    }
    for call in tool_calls:
        tool = call.get("tool", "")
        result_str = call.get("result", "{}")
        try:
            result = json.loads(result_str)
            data = result.get("result", {})
            key = tool_map.get(tool)
            if key:
                results[key] = data
            if tool == "verify_dump_integrity" and isinstance(data, dict):
                results["dump_path"] = data.get("file", "")
        except (json.JSONDecodeError, AttributeError):
            pass

    if "threat_score" not in results:
        results["threat_score"] = {"score": 0, "level": "UNKNOWN", "breakdown": {}, "recommendations": []}
    return results


if __name__ == "__main__":
    cli()
