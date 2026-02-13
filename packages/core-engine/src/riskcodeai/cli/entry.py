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
    help="🛡️ RiskCodeAI — AI-powered dependency risk analysis engine",
    add_completion=False,
    rich_markup_mode="rich",
)

config_app = typer.Typer(
    name="config",
    help="Manage RiskCodeAI configuration",
)
app.add_typer(config_app, name="config")

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
    reachability: bool = typer.Option(
        True,
        "--reachability/--no-reachability",
        help="Enable reachability analysis",
    ),
    ai_changelog: bool = typer.Option(
        True,
        "--ai-changelog/--no-ai-changelog",
        help="Generate AI changelogs",
    ),
) -> None:
    """🔍 Scan a project for dependency vulnerabilities."""
    target_dir = directory or str(Path.cwd())
    target_path = Path(target_dir)

    if not target_path.is_dir():
        error_console.print(f"[red]Error:[/red] Directory not found: {target_dir}")
        raise typer.Exit(code=EXIT_GENERAL_ERROR)

    console.print(
        Panel(
            f"[bold blue]Scanning:[/bold blue] {target_path.resolve()}\n"
            f"[dim]Format: {format}[/dim]",
            title="🛡️ RiskCodeAI",
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
            )

        # Display results
        graph = result.dependency_graph
        if graph:
            _display_dependency_table(graph)

            # Generate report
            report = orchestrator.generate_report(
                result=result,
                format=format,
                output_path=output,
            )

            if output:
                console.print(f"\n[green]✓[/green] Report saved to: [bold]{output}[/bold]")
            else:
                if format == "json":
                    console.print("\n[bold]Report (JSON):[/bold]")
                    console.print_json(report)

        console.print(f"\n[green]✓[/green] Scan completed successfully")

    except FileNotFoundError as e:
        error_console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(code=EXIT_GENERAL_ERROR)
    except Exception as e:
        error_console.print(f"[red]Unexpected error:[/red] {e}")
        raise typer.Exit(code=EXIT_GENERAL_ERROR)


def _display_dependency_table(graph) -> None:
    """Display a rich table of dependencies."""
    table = Table(title=f"📦 Dependencies ({graph.ecosystem.value})")
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


# ─── Config Commands ──────────────────────────────────────────────────────────

@config_app.command("init")
def config_init(
    directory: Optional[str] = typer.Argument(
        None,
        help="Directory to create config in (default: current directory)",
    ),
) -> None:
    """📝 Create .riskcodeai.yaml configuration file."""
    target_dir = directory or str(Path.cwd())

    try:
        config_path = save_config(target_dir)
        console.print(
            f"[green]✓[/green] Config file created: [bold]{config_path}[/bold]"
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
    """📋 Display current configuration."""
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
    """⚙️ Set a configuration value."""
    target_dir = directory or str(Path.cwd())
    config = load_config(target_dir)

    # Try to parse value as JSON for booleans/numbers
    try:
        parsed_value = json.loads(value)
    except (json.JSONDecodeError, ValueError):
        parsed_value = value

    config.set(key, parsed_value)
    save_config(target_dir, config)
    console.print(f"[green]✓[/green] Set [bold]{key}[/bold] = {parsed_value}")


# ─── Main Entry Point ─────────────────────────────────────────────────────────

def main() -> None:
    """CLI entry point for Poetry script."""
    app()


if __name__ == "__main__":
    main()
