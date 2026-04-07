"""
LSIM Terminal Reporter — rich-formatted output for scan results.
"""

import json
from datetime import datetime

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from lsim.config import (
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_INFO,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
)
from lsim.finding import sort_findings

_console = Console()

_SEVERITY_STYLES = {
    SEVERITY_CRITICAL: "bold red",
    SEVERITY_HIGH:     "red",
    SEVERITY_MEDIUM:   "yellow",
    SEVERITY_LOW:      "cyan",
    SEVERITY_INFO:     "white",
}

_STATE_STYLES = {
    "LOCKDOWN": ("bold white on red",   "LOCKDOWN ACTIVATED"),
    "AT_RISK":  ("bold black on yellow", "AT RISK"),
    "SECURE":   ("bold white on green",  "SECURE"),
}

_STATE_ICONS = {
    "LOCKDOWN": "[!]",
    "AT_RISK":  "[~]",
    "SECURE":   "[OK]",
}


class Reporter:
    def display(
        self,
        state: str,
        findings: list,
        actions_taken: list,
        verbose: bool = False,
        as_json: bool = False,
    ):
        if as_json:
            self._display_json(state, findings, actions_taken)
            return
        self._display_rich(state, findings, actions_taken, verbose)

    # ------------------------------------------------------------------
    # JSON output (for scripting / SIEM integration)
    # ------------------------------------------------------------------
    def _display_json(self, state: str, findings: list, actions_taken: list):
        output = {
            "state": state,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "findings_count": len(findings),
            "findings": [f.to_dict() for f in findings],
            "actions_taken": actions_taken,
        }
        print(json.dumps(output, indent=2))

    # ------------------------------------------------------------------
    # Rich terminal output
    # ------------------------------------------------------------------
    def _display_rich(self, state: str, findings: list, actions_taken: list, verbose: bool):
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        style, label = _STATE_STYLES.get(state, ("white", state))

        # Header banner
        _console.print()
        _console.print(Panel(
            f"[bold]Linux System Integrity Monitor v2.0[/bold]\n"
            f"Scan completed: {now}",
            border_style="blue",
        ))

        # State banner
        icon = _STATE_ICONS.get(state, "")
        _console.print()
        _console.print(Panel(
            f"[{style}] {icon}  SYSTEM STATE: {label} [/{style}]",
            border_style=style,
        ))

        # Findings
        sorted_findings = sort_findings(findings)
        if not verbose:
            sorted_findings = [
                f for f in sorted_findings
                if f.severity != SEVERITY_INFO
            ]

        if not sorted_findings:
            _console.print("\n[bold green]  No significant findings detected.[/bold green]\n")
        else:
            self._print_findings_table(sorted_findings)

        # Actions taken
        if actions_taken:
            self._print_actions(actions_taken)

        # Log file reminder
        _console.print()
        _console.print(
            f"[dim]Logs saved to: /var/log/lsim/lsim.log  |  "
            f"JSON events: /var/log/lsim/lsim_events.jsonl[/dim]"
        )
        _console.print()

    def _print_findings_table(self, findings: list):
        table = Table(
            title=f"Findings ({len(findings)} total)",
            show_header=True,
            header_style="bold",
            border_style="dim",
            expand=True,
        )
        table.add_column("Severity", width=10, no_wrap=True)
        table.add_column("Category", width=14, no_wrap=True)
        table.add_column("Title", no_wrap=False)
        table.add_column("Recommendation", no_wrap=False)

        for f in findings:
            sev_style = _SEVERITY_STYLES.get(f.severity, "white")
            sev_text = Text(f.severity, style=sev_style)
            table.add_row(
                sev_text,
                f.category,
                f"{f.title}\n[dim]{f.detail[:120]}{'...' if len(f.detail) > 120 else ''}[/dim]",
                f.recommendation[:100] + ("..." if len(f.recommendation) > 100 else ""),
            )

        _console.print()
        _console.print(table)

    def _print_actions(self, actions: list):
        _console.print()
        _console.print(Panel(
            "\n".join(f"  {a}" for a in actions),
            title="[bold]Automated Response Actions Taken[/bold]",
            border_style="yellow",
        ))

    def print_lockdown_warning(self):
        _console.print()
        _console.print(Panel(
            "[yellow]RECOMMENDATION: Boot into recovery mode and audit your system\n"
            "before running --unlock to release the network lockdown.[/yellow]",
            border_style="yellow",
        ))
