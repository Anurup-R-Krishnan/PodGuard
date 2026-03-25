"""
EPSS-Triage CLI Application.

Command-line interface for the EPSS-Augmented CVE Prioritization Framework.

Usage:
    epss-triage scan <image>          Scan and triage a container image
    epss-triage enrich <json-file>    Enrich existing scan results with EPSS
    epss-triage info                  Show framework information
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()
app = typer.Typer(
    name="epss-triage",
    help="EPSS-Augmented CVE Prioritization Framework for Docker Container Security",
    add_completion=False,
    rich_markup_mode="rich",
)


@app.command()
def scan(
    image: str = typer.Argument(..., help="Container image to scan (e.g., nginx:latest)"),
    output_dir: str = typer.Option("./epss-reports", "--output", "-o", help="Output directory for reports"),
    output_format: str = typer.Option("json,html", "--format", "-f", help="Output formats (comma-separated: json,html)"),
    weights: str = typer.Option("0.4,0.4,0.2", "--weights", "-w", help="Scoring weights: cvss,epss,reachability"),
    top_n: int = typer.Option(10, "--top", "-n", help="Show top N vulnerabilities"),
    json_output: bool = typer.Option(False, "--json", help="Output raw JSON to stdout (for piping)"),
) -> None:
    """
    🔍 Scan a container image and generate an EPSS-augmented vulnerability triage report.
    """
    from epss_framework.config.settings import FrameworkConfig, ScoringConfig, PipelineConfig
    from epss_framework.pipeline.enrichment_pipeline import EnrichmentPipeline
    from epss_framework.reports.report_generator import ReportGenerator

    # Parse weights
    try:
        w1, w2, w3 = [float(x.strip()) for x in weights.split(",")]
    except ValueError:
        console.print("[red]Error: weights must be three comma-separated numbers (e.g., 0.4,0.4,0.2)[/red]")
        raise typer.Exit(1)

    # Configure while preserving environment-derived defaults (e.g., EPSS_TRIVY_PATH).
    config = FrameworkConfig.from_env()
    config.scoring = ScoringConfig(
        weight_cvss=w1,
        weight_epss=w2,
        weight_reachability=w3,
    )
    config.pipeline = PipelineConfig(
        output_dir=Path(output_dir),
        output_format=output_format.split(","),
    )

    # Run pipeline
    pipeline = EnrichmentPipeline(config)

    try:
        result = asyncio.run(pipeline.run(image))
    except Exception as e:
        console.print(f"[red bold]✗ Pipeline failed:[/red bold] {e}")
        raise typer.Exit(1)

    # Generate reports
    formats = [f.strip().lower() for f in output_format.split(",")]
    report_gen = ReportGenerator(output_dir)

    if "json" in formats:
        json_path = report_gen.generate_json(result)
        console.print(f"  📄 JSON: {json_path}")

    if "html" in formats:
        html_path = report_gen.generate_html(result)
        console.print(f"  🌐 HTML: {html_path}")

    # Display top N
    if not json_output:
        _display_top_results(result, top_n)
    else:
        # Raw JSON to stdout for piping
        data = {
            "image": result.image_name,
            "total_vulns": result.total_vulns,
            "top_vulnerabilities": [
                {
                    "cve_id": v.cve_id,
                    "composite_score": v.composite_score,
                    "cvss_score": v.cvss_v3_score,
                    "epss_score": v.epss_score,
                    "severity": v.composite_severity.value,
                    "package": v.affected_package,
                }
                for v in result.top_n(top_n)
            ],
        }
        print(json.dumps(data, indent=2))


def _display_top_results(result, top_n: int) -> None:
    """Display top N vulnerabilities in a Rich table."""
    table = Table(
        title=f"\n🏆 Top {top_n} Prioritized Vulnerabilities",
        show_header=True,
        header_style="bold cyan",
        border_style="dim",
        pad_edge=True,
    )

    table.add_column("#", style="dim", width=4, justify="right")
    table.add_column("CVE ID", style="bold", width=18)
    table.add_column("Composite", justify="right", width=10)
    table.add_column("Severity", width=10)
    table.add_column("CVSS", justify="right", width=6)
    table.add_column("EPSS", justify="right", width=8)
    table.add_column("Package", width=20)
    table.add_column("Fix Available", width=12)

    severity_colors = {
        "CRITICAL": "bold red",
        "HIGH": "bold yellow",
        "MEDIUM": "yellow",
        "LOW": "green",
    }

    for i, v in enumerate(result.top_n(top_n)):
        sev = v.composite_severity.value
        sev_style = severity_colors.get(sev, "white")
        fix_status = "✓ " + v.fixed_version if v.has_fix else "[red]✗ No fix[/red]"

        table.add_row(
            str(i + 1),
            v.cve_id,
            f"{v.composite_score:.4f}",
            f"[{sev_style}]{sev}[/{sev_style}]",
            f"{v.cvss_v3_score:.1f}",
            f"{v.epss_score:.4f}",
            v.affected_package[:20],
            fix_status,
        )

    console.print(table)

    # Summary panel
    fatigue = result.alert_fatigue_reduction()
    summary_text = (
        f"[bold]Total CVEs:[/bold] {result.total_vulns}\n"
        f"[bold]Severity:[/bold] {result.severity_summary()}\n"
        f"[bold]Alert Reduction:[/bold] {fatigue.get('alert_reduction_pct', 0):.1f}% "
        f"(CVSS critical/high: {fatigue.get('cvss_critical_high', 0)} → "
        f"Composite critical/high: {fatigue.get('composite_critical_high', 0)})"
    )
    console.print(Panel(summary_text, title="📊 Summary", border_style="blue"))


@app.command()
def info() -> None:
    """ℹ️ Show framework information and configuration."""
    from epss_framework.config.settings import get_config

    config = get_config()
    console.print(Panel(
        "[bold cyan]EPSS-Augmented CVE Prioritization Framework[/bold cyan]\n"
        f"Version: 0.1.0\n"
        f"\n[bold]Scoring Weights:[/bold]\n"
        f"  CVSS (w₁):          {config.scoring.weight_cvss}\n"
        f"  EPSS (w₂):          {config.scoring.weight_epss}\n"
        f"  Reachability (w₃):  {config.scoring.weight_reachability}\n"
        f"\n[bold]Thresholds:[/bold]\n"
        f"  Critical: ≥ {config.scoring.threshold_critical}\n"
        f"  High:     ≥ {config.scoring.threshold_high}\n"
        f"  Medium:   ≥ {config.scoring.threshold_medium}\n"
        f"\n[bold]EPSS API:[/bold]\n"
        f"  Endpoint: {config.epss.api_base_url}\n"
        f"  Batch size: {config.epss.batch_size}\n"
        f"  Cache TTL: {config.epss.cache_ttl_hours}h\n",
        title="🛡️ Framework Info",
        border_style="blue",
    ))


if __name__ == "__main__":
    app()
