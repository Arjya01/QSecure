"""
Entry points for Q-Secure scanner package.

  py -m scanner          → runs all 5 mock profiles, prints summary table
  py -m scanner.cli      → starts the interactive terminal UI
"""

from __future__ import annotations

import sys

# If invoked as `python -m scanner.cli`, this file won't run.
# When invoked as `python -m scanner`, we show the quick summary table.

import scanner
from rich.console import Console
from rich.table import Table
from rich import box

console = Console(highlight=False, legacy_windows=False)


def run_summary() -> None:
    """Run all 5 mock profiles and print a summary table (quick demo mode)."""
    console.rule("[bold cyan]Q-Secure | Quantum-Proof Systems Scanner[/]")
    console.print(
        "[dim]  Team Cyber Sentinels | NFSU Gandhinagar | NIST FIPS-203/204/205[/]\n"
    )
    console.print("[dim]Running all 5 mock profiles...[/]\n")

    results = scanner.scan_all_mock_profiles()

    table = Table(
        title="Quantum Safety Summary — PNB Infrastructure Mock Assessment",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold white on dark_blue",
        min_width=100,
    )
    table.add_column("Hostname",        style="cyan",   min_width=30)
    table.add_column("Score",           justify="right", style="white")
    table.add_column("Grade",           justify="center")
    table.add_column("Label",           min_width=18)
    table.add_column("Tier",            min_width=12)
    table.add_column("Cyber Rating",    justify="right")
    table.add_column("Vulns",           justify="right")
    table.add_column("CBOM Entries",    justify="right")
    table.add_column("Duration (s)",    justify="right")

    LABEL_COLORS = {
        "QUANTUM_SAFE":     "bold green",
        "PQC_READY":        "bold yellow",
        "NOT_QUANTUM_SAFE": "bold red",
    }

    for r in results:
        if r.quantum_score:
            qs = r.quantum_score
            lc = LABEL_COLORS.get(qs.label.value, "white")
            table.add_row(
                r.target.hostname,
                f"{qs.overall_score:.1f}",
                qs.grade,
                f"[{lc}]{qs.label.value}[/]",
                qs.tier.value,
                f"{qs.cyber_rating:.0f}",
                str(len(r.vulnerabilities)),
                str(len(r.cbom)),
                f"{r.scan_duration_seconds:.2f}",
            )
        else:
            table.add_row(
                r.target.hostname, "N/A", "F",
                "[red]FAILED[/]", "CRITICAL",
                "0", "0", "0", f"{r.scan_duration_seconds:.2f}",
            )

    console.print(table)
    console.print()

    # Aggregate stats
    valid = [r for r in results if r.quantum_score]
    avg = sum(r.quantum_score.overall_score for r in valid) / len(valid) if valid else 0
    avg_color = "green" if avg >= 70 else ("yellow" if avg >= 40 else "red")

    all_vulns = sum(len(r.vulnerabilities) for r in results)
    console.print(
        f"  Assets assessed:  [bold]{len(results)}[/]\n"
        f"  Average score:    [{avg_color}]{avg:.1f}/100[/]\n"
        f"  Total vulns:      [bold]{all_vulns}[/]\n"
        f"\n[dim]  Run [bold]py -m scanner.cli[/] for the full interactive interface.[/]\n"
    )


if __name__ == "__main__":
    run_summary()
