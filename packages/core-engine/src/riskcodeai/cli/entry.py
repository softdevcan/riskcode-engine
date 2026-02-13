"""RiskCodeAI CLI — Command Line Interface.

Usage:
    riskcodeai scan [DIRECTORY]     Scan a project for dependencies
    riskcodeai config init|show     Manage configuration
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from riskcode_shared.constants.constants import (
    EXIT_CONFIG_ERROR,
    EXIT_GENERAL_ERROR,
    EXIT_SUCCESS,
    SUPPORTED_FORMATS,
)

from riskcodeai.analysis.orchestrator import AnalysisOrchestrator
from riskcodeai.config import RiskCodeConfig, load_config, save_config

# ─── App Setup ─────────────────────────────────────────────────────────────────

app = typer.Typer(
    name="riskcodeai",
    help="RiskCodeAI -- AI-powered dependency risk analysis engine",
    add_completion=False,
    rich_markup_mode="rich",
)

config_app = typer.Typer(
    name="config",
    help="Manage RiskCodeAI configuration",
)
app.add_typer(config_app, name="config")

import os as _os
import sys as _sys

# Fix Windows console encoding (cp1254 Turkish can't handle Rich's Unicode chars)
if _os.name == "nt":
    if hasattr(_sys.stdout, "reconfigure"):
        _sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(_sys.stderr, "reconfigure"):
        _sys.stderr.reconfigure(encoding="utf-8", errors="replace")

console = Console()
error_console = Console(stderr=True)


# ─── Scan Command ─────────────────────────────────────────────────────────────

@app.command()
def scan(
    directory: Optional[str] = typer.Argument(
        None,
        help="Project directory to scan (default: current directory)",
    ),
    manifest: Optional[str] = typer.Option(
        None,
        "--manifest",
        "-m",
        help="Specific manifest file to parse (e.g., package.json)",
    ),
    ecosystem: Optional[str] = typer.Option(
        None,
        "--ecosystem",
        "-e",
        help="Force ecosystem (npm, pypi, maven, go)",
    ),
    output: Optional[str] = typer.Option(
        None,
        "--output",
        "-o",
        help="Save results to file",
    ),
    format: str = typer.Option(
        "json",
        "--format",
        "-f",
        help="Output format (json, html, pdf, sarif)",
    ),
    osv: bool = typer.Option(
        True,
        "--osv/--no-osv",
        help="Query OSV.dev for vulnerabilities",
    ),
    ai: bool = typer.Option(
        True,
        "--ai/--no-ai",
        help="Generate AI summaries via Ollama",
    ),
    reachability: bool = typer.Option(
        True,
        "--reachability/--no-reachability",
        help="Enable reachability analysis",
    ),
) -> None:
    """Scan a project for dependency vulnerabilities."""
    target_dir = directory or str(Path.cwd())
    target_path = Path(target_dir)

    if not target_path.is_dir():
        error_console.print(f"[red]Error:[/red] Directory not found: {target_dir}")
        raise typer.Exit(code=EXIT_GENERAL_ERROR)

    scan_modes = []
    if osv:
        scan_modes.append("OSV")
    if ai:
        scan_modes.append("AI")
    modes_str = " + ".join(scan_modes) if scan_modes else "parse only"

    console.print(
        Panel(
            f"[bold blue]Scanning:[/bold blue] {target_path.resolve()}\n"
            f"[dim]Format: {format} | Mode: {modes_str}[/dim]",
            title="[bold]RiskCodeAI[/bold]",
            border_style="blue",
        )
    )

    try:
        config = load_config(target_dir)
        orchestrator = AnalysisOrchestrator(config=config)

        with console.status("[bold green]Analyzing dependencies...[/bold green]"):
            result = orchestrator.analyze(
                directory=target_dir,
                manifest=manifest,
                ecosystem=ecosystem,
                enable_osv=osv,
                enable_ai=ai,
            )

        # Display results
        graph = result.dependency_graph
        if graph:
            _display_dependency_table(graph)

            # Display vulnerabilities if found
            if result.vulnerabilities:
                _display_vulnerability_table(result.vulnerabilities)
            elif osv:
                console.print("\n[green]>[/green] No known vulnerabilities found")

            # Generate report
            report = orchestrator.generate_report(
                result=result,
                format=format,
                output_path=output,
            )

            if output:
                console.print(f"\n[green]>[/green] Report saved to: [bold]{output}[/bold]")
            else:
                if format == "json":
                    console.print("\n[bold]Report (JSON):[/bold]")
                    console.print_json(report)

        console.print(f"\n[green]>[/green] Scan completed successfully")

    except FileNotFoundError as e:
        error_console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(code=EXIT_GENERAL_ERROR)
    except Exception as e:
        error_console.print(f"[red]Unexpected error:[/red] {e}")
        raise typer.Exit(code=EXIT_GENERAL_ERROR)


def _display_dependency_table(graph) -> None:
    """Display a rich table of dependencies."""
    table = Table(title=f"Dependencies ({graph.ecosystem.value})")
    table.add_column("Package", style="cyan", no_wrap=True)
    table.add_column("Version", style="green")
    table.add_column("Type", style="yellow")
    table.add_column("Depth", justify="center")

    for dep in graph.dependencies:
        dep_type = "dev" if dep.is_dev else ("direct" if dep.is_direct else "transitive")
        style = "dim" if dep.is_dev else ("bold" if dep.is_direct else "")
        table.add_row(
            dep.name,
            dep.version_constraint.raw,
            dep_type,
            str(dep.depth),
            style=style,
        )

    console.print(table)

    # Summary
    summary = graph.to_summary()
    console.print(
        f"\n[bold]Total:[/bold] {summary['total_dependencies']} dependencies "
        f"([green]{summary['direct']}[/green] direct, "
        f"[yellow]{summary['transitive']}[/yellow] transitive, "
        f"[dim]{summary['dev']}[/dim] dev)"
    )


def _display_vulnerability_table(vulnerabilities) -> None:
    """Display a rich table of vulnerabilities with severity coloring."""
    _SEVERITY_STYLES = {
        "critical": "bold red",
        "high": "bright_red",
        "medium": "yellow",
        "low": "dim",
        "unknown": "dim italic",
    }

    table = Table(title=f"Vulnerabilities ({len(vulnerabilities)} found)")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Severity", justify="center")
    table.add_column("CVSS", justify="center")
    table.add_column("Package", style="white")
    table.add_column("Fixed In", style="green")
    table.add_column("Summary", max_width=50)

    for vuln in vulnerabilities:
        sev = vuln.severity.value
        style = _SEVERITY_STYLES.get(sev.lower(), "")
        display_id = vuln.cve_id or vuln.osv_id
        fixed = vuln.fixed_version or "-"
        summary = vuln.summary[:50] + "..." if len(vuln.summary) > 50 else vuln.summary

        table.add_row(
            display_id,
            f"[{style}]{sev.upper()}[/{style}]",
            f"{vuln.cvss_score:.1f}",
            vuln.affected_dependency or "-",
            fixed,
            summary,
        )

    console.print(table)

    # Vulnerability summary
    from collections import Counter
    sev_counts = Counter(v.severity.value.lower() for v in vulnerabilities)
    parts = []
    for sev_name, color in [("critical", "red"), ("high", "bright_red"), ("medium", "yellow"), ("low", "dim")]:
        count = sev_counts.get(sev_name, 0)
        if count:
            parts.append(f"[{color}]{count} {sev_name}[/{color}]")

    fixable = sum(1 for v in vulnerabilities if v.fixed_version)
    console.print(
        f"\n[bold]Vulnerabilities:[/bold] {', '.join(parts)}"
        f" | [green]{fixable}[/green] fixable"
    )

    # Show AI summaries if available
    ai_vulns = [v for v in vulnerabilities if v.ai_summary]
    if ai_vulns:
        console.print(f"\n[bold]AI Summaries ({len(ai_vulns)}):[/bold]")
        for v in ai_vulns[:5]:
            console.print(f"  [{_SEVERITY_STYLES.get(v.severity.value.lower(), '')}]{v.osv_id}[/]: {v.ai_summary}")


# ─── Config Commands ──────────────────────────────────────────────────────────

@config_app.command("init")
def config_init(
    directory: Optional[str] = typer.Argument(
        None,
        help="Directory to create config in (default: current directory)",
    ),
) -> None:
    """Create .riskcodeai.yaml configuration file."""
    target_dir = directory or str(Path.cwd())

    try:
        config_path = save_config(target_dir)
        console.print(
            f"[green]>[/green] Config file created: [bold]{config_path}[/bold]"
        )
    except Exception as e:
        error_console.print(f"[red]Error:[/red] Failed to create config: {e}")
        raise typer.Exit(code=EXIT_CONFIG_ERROR)


@config_app.command("show")
def config_show(
    directory: Optional[str] = typer.Argument(
        None,
        help="Directory to load config from",
    ),
) -> None:
    """Display current configuration."""
    target_dir = directory or str(Path.cwd())
    config = load_config(target_dir)

    console.print(Panel("[bold]Current Configuration[/bold]", border_style="blue"))
    console.print_json(json.dumps(config.to_dict()))


@config_app.command("set")
def config_set(
    key: str = typer.Argument(help="Config key (dot notation, e.g., llm.model)"),
    value: str = typer.Argument(help="Config value"),
    directory: Optional[str] = typer.Option(
        None, "--dir", "-d", help="Directory with config file"
    ),
) -> None:
    """Set a configuration value."""
    target_dir = directory or str(Path.cwd())
    config = load_config(target_dir)

    # Try to parse value as JSON for booleans/numbers
    try:
        parsed_value = json.loads(value)
    except (json.JSONDecodeError, ValueError):
        parsed_value = value

    config.set(key, parsed_value)
    save_config(target_dir, config)
    console.print(f"[green]>[/green] Set [bold]{key}[/bold] = {parsed_value}")


# ─── Main Entry Point ─────────────────────────────────────────────────────────

def main() -> None:
    """CLI entry point for Poetry script."""
    app()


if __name__ == "__main__":
    main()
