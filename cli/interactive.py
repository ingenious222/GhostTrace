"""
cli/interactive.py
──────────────────────────────────────────────────────────────
Rich-powered interactive REPL for GhostTrace.
Users type forensic investigation prompts; the agent runs the
full tool-calling loop and displays results in-terminal.
"""

from __future__ import annotations

import json
import os
import pathlib
from datetime import datetime
from typing import Any

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.syntax import Syntax
from rich.table import Table
from rich import box

from core.agent import MemForensicAgent
from cli.banner import print_banner, print_section

console = Console()

HELP_TEXT = """
[bold cyan]GhostTrace Interactive Commands[/]

  [bold]Any text[/]          → Send prompt to the AI forensic investigator
  [bold]!help[/]             → Show this help
  [bold]!status[/]           → Show current session status
  [bold]!save[/]             → Save current session to JSON
  [bold]!report[/]           → Generate PDF/HTML/JSON report from current session
  [bold]!reset[/]            → Start a new investigation (clears history)
  [bold]!tools[/]            → List all available forensic tools
  [bold]!quit[/] / [bold]!exit[/]      → Exit the tool
"""

SUGGESTED_PROMPTS = [
    "Verify the integrity of this memory dump and provide file metadata.",
    "Run a complete process analysis including pslist and pstree, then flag anomalies.",
    "Check for memory injection and shellcode using malfind.",
    "Extract all PowerShell command lines and decode any encoded payloads.",
    "Scan for suspicious network connections and identify potential C2 communications.",
    "Run a full forensic analysis, score the threats, reconstruct the timeline, and generate a report.",
]


class InteractiveSession:
    """Manages an interactive forensic investigation session."""

    def __init__(self, dump_path: str | None = None, output_dir: str = "./output") -> None:
        self.agent = MemForensicAgent()
        self.dump_path = dump_path
        self.output_dir = output_dir
        self.session_id = datetime.now().strftime("%Y%m%d-%H%M%S")
        self.prompt_count = 0

    def run(self) -> None:
        """Start the interactive REPL."""
        print_banner(console)

        # Display session info
        info_table = Table(box=box.SIMPLE, show_header=False)
        info_table.add_column("Key", style="dim cyan", width=18)
        info_table.add_column("Value", style="bold white")
        info_table.add_row("Session ID", self.session_id)
        info_table.add_row("Memory Dump", self.dump_path or "[dim]Not set — specify in prompt[/]")
        info_table.add_row("Output Dir", self.output_dir)
        info_table.add_row("LLM Provider", os.getenv("LLM_PROVIDER", "openai").upper())
        info_table.add_row("Model", os.getenv("OPENROUTER_MODEL") or os.getenv("LLM_MODEL") or os.getenv("OLLAMA_MODEL", "meta-llama/llama-3.1-8b-instruct:free"))
        info_table.add_row("Mock Mode", "[yellow]ON[/]" if os.getenv("MEMFORENSIC_MOCK") == "1" else "[green]OFF[/]")
        console.print(Panel(info_table, title="[bold]Session Info[/]", border_style="cyan"))

        console.print("\n[dim]Type [bold]!help[/] for commands, or start with a forensic investigation prompt.[/]\n")
        console.print("[dim cyan]Suggested:[/]")
        for i, prompt in enumerate(SUGGESTED_PROMPTS[:3], 1):
            console.print(f"  [dim]{i}.[/] {prompt}")
        console.print()

        # Main REPL loop
        while True:
            try:
                user_input = console.input("[bold cyan]🔬 investigate>[/] ").strip()
            except (KeyboardInterrupt, EOFError):
                console.print("\n[dim]Session interrupted. Use !quit to exit properly.[/]")
                continue

            if not user_input:
                continue

            # ── Commands ──────────────────────────────────────────────────
            if user_input.startswith("!"):
                self._handle_command(user_input)
                continue

            # ── Investigation prompt ──────────────────────────────────────
            self._run_investigation(user_input)

    def _run_investigation(self, prompt: str) -> None:
        """Send a prompt to the agent and stream results."""
        self.prompt_count += 1

        # Inject dump_path into prompt if available and not already mentioned
        if self.dump_path and "dump" not in prompt.lower() and ".mem" not in prompt.lower():
            augmented = f"{prompt}\n\n[Context: Memory dump path = {self.dump_path}]"
        else:
            augmented = prompt

        console.print()
        console.rule("[dim cyan]Investigation Running[/]")

        with Progress(
            SpinnerColumn(style="cyan"),
            TextColumn("[cyan]{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task("Agent thinking…", total=None)

            for event in self.agent.stream(augmented):
                event_type = event.get("type")

                if event_type == "thinking":
                    progress.update(task, description="Agent reasoning…")
                    # Show thinking in a collapsible style
                    if event["content"].strip():
                        console.print(
                            Panel(
                                Markdown(event["content"]),
                                title="[dim]🤔 Agent Reasoning[/]",
                                border_style="dim",
                                expand=False,
                            )
                        )

                elif event_type == "tool_call":
                    tool = event["tool"]
                    args_preview = json.dumps(event.get("args", {}), default=str)[:120]
                    progress.update(task, description=f"Calling tool: {tool}")
                    console.print(
                        f"  [bold cyan]⚙ Tool:[/] [white]{tool}[/]  "
                        f"[dim]{args_preview}[/]"
                    )

                elif event_type == "tool_result":
                    tool = event["tool"]
                    result_str = event.get("result", "{}")
                    try:
                        result = json.loads(result_str)
                        status = result.get("status", "ok")
                        if status == "error":
                            console.print(f"  [bold red]✗[/] {tool}: {result.get('error', 'Unknown error')}")
                        else:
                            # Show compact summary
                            result_data = result.get("result", {})
                            if isinstance(result_data, list):
                                console.print(f"  [bold green]✓[/] {tool}: returned {len(result_data)} items.")
                            elif isinstance(result_data, dict):
                                summary = {k: v for k, v in list(result_data.items())[:3]}
                                console.print(f"  [bold green]✓[/] {tool}: {json.dumps(summary, default=str)[:100]}")
                            else:
                                console.print(f"  [bold green]✓[/] {tool}: {str(result_data)[:100]}")
                    except json.JSONDecodeError:
                        console.print(f"  [bold green]✓[/] {tool}: completed.")

                elif event_type == "final_answer":
                    progress.stop()
                    console.print()
                    console.rule("[bold green]🔬 Forensic Assessment[/]")
                    console.print(Markdown(event["content"]))
                    console.rule()

                elif event_type == "error":
                    progress.stop()
                    console.print(f"\n[bold red]❌ Error:[/] {event['content']}")

    def _handle_command(self, cmd: str) -> None:
        """Handle REPL special commands."""
        cmd_lower = cmd.lower().strip()

        if cmd_lower in ("!quit", "!exit"):
            console.print("[dim cyan]Ending session. Goodbye.[/]")
            raise SystemExit(0)

        elif cmd_lower == "!help":
            console.print(Panel(HELP_TEXT, title="[bold cyan]Help[/]", border_style="cyan"))

        elif cmd_lower == "!status":
            self._show_status()

        elif cmd_lower == "!reset":
            self.agent.reset()
            self.prompt_count = 0
            console.print("[green]✓[/] Session reset — investigation history cleared.")

        elif cmd_lower == "!save":
            self._save_session()

        elif cmd_lower == "!report":
            self._generate_report_command()

        elif cmd_lower == "!tools":
            from core.tool_registry import get_tool_names
            console.print(Panel(
                "\n".join(f"  • [cyan]{t}[/]" for t in get_tool_names()),
                title="[bold]Available Forensic Tools[/]",
                border_style="blue",
            ))

        else:
            console.print(f"[dim red]Unknown command: {cmd}. Type !help for help.[/]")

    def _show_status(self) -> None:
        t = Table(box=box.SIMPLE, show_header=False)
        t.add_column("Key", style="dim cyan", width=22)
        t.add_column("Value", style="white")
        t.add_row("Session ID", self.session_id)
        t.add_row("Prompts sent", str(self.prompt_count))
        t.add_row("Tool calls made", str(len(self.agent.tool_call_log)))
        t.add_row("Memory dump", self.dump_path or "[dim]not set[/]")
        console.print(Panel(t, title="[bold]Session Status[/]", border_style="blue"))

    def _save_session(self) -> None:
        out = pathlib.Path(self.output_dir)
        out.mkdir(parents=True, exist_ok=True)
        session_file = out / f"session_{self.session_id}.json"
        data = self.agent.get_session_data()
        session_file.write_text(json.dumps(data, indent=2, default=str))
        console.print(f"[green]✓[/] Session saved to: [bold]{session_file}[/]")

    def _generate_report_command(self) -> None:
        """Generate a report from the current session tool call log."""
        console.print("[cyan]Generating report from current session…[/]")
        # Ask agent to generate report with all accumulated context
        self._run_investigation(
            "Based on all findings in this session, run score_threats and build_attack_timeline "
            "with the data collected, then generate_report to produce the PDF forensic report. "
            f"Use dump_path='{self.dump_path or 'session_analysis'}' and output_dir='{self.output_dir}'."
        )
