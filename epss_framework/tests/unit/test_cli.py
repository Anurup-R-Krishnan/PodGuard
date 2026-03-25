"""
Unit tests for CLI commands.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

from typer.testing import CliRunner

from epss_framework.cli import app
from epss_framework.utils.models import (
    CompositeSeverity,
    EnrichedScanResult,
    EnrichedVulnerability,
    Severity,
)


def _sample_enriched_result() -> EnrichedScanResult:
    return EnrichedScanResult(
        image_name="nginx:latest",
        scoring_weights={"cvss": 0.4, "epss": 0.4, "reachability": 0.2},
        vulnerabilities=[
            EnrichedVulnerability(
                cve_id="CVE-2024-0001",
                cvss_v3_score=9.8,
                cvss_severity=Severity.CRITICAL,
                epss_score=0.9,
                composite_score=0.92,
                composite_severity=CompositeSeverity.CRITICAL,
                affected_package="openssl",
                fixed_version="3.0.1",
            ),
            EnrichedVulnerability(
                cve_id="CVE-2024-0002",
                cvss_v3_score=5.0,
                cvss_severity=Severity.MEDIUM,
                epss_score=0.1,
                composite_score=0.34,
                composite_severity=CompositeSeverity.LOW,
                affected_package="curl",
            ),
        ],
    )


class TestCLI:
    """CLI behavior tests."""

    def test_scan_rejects_invalid_weights(self) -> None:
        runner = CliRunner()
        result = runner.invoke(app, ["scan", "nginx:latest", "--weights", "abc"])
        assert result.exit_code == 1
        assert "weights must be three comma-separated numbers" in result.stdout

    def test_scan_json_output(self) -> None:
        runner = CliRunner()
        sample = _sample_enriched_result()

        with (
            patch("epss_framework.pipeline.enrichment_pipeline.EnrichmentPipeline") as pipeline_cls,
            patch("epss_framework.reports.report_generator.ReportGenerator") as report_cls,
        ):
            pipeline = pipeline_cls.return_value
            pipeline.run = AsyncMock(return_value=sample)
            report = report_cls.return_value
            report.generate_json = MagicMock()
            report.generate_html = MagicMock()

            result = runner.invoke(
                app,
                ["scan", "nginx:latest", "--json", "--format", "json"],
            )

        assert result.exit_code == 0
        json_start = result.stdout.find("{")
        payload = json.loads(result.stdout[json_start:])
        assert payload["image"] == "nginx:latest"
        assert payload["total_vulns"] == 2
        assert payload["top_vulnerabilities"][0]["cve_id"] == "CVE-2024-0001"

    def test_scan_generates_reports_and_table(self) -> None:
        runner = CliRunner()
        sample = _sample_enriched_result()

        with (
            patch("epss_framework.pipeline.enrichment_pipeline.EnrichmentPipeline") as pipeline_cls,
            patch("epss_framework.reports.report_generator.ReportGenerator") as report_cls,
        ):
            pipeline = pipeline_cls.return_value
            pipeline.run = AsyncMock(return_value=sample)
            report = report_cls.return_value
            report.generate_json = MagicMock(return_value="report.json")
            report.generate_html = MagicMock(return_value="report.html")

            result = runner.invoke(
                app,
                ["scan", "nginx:latest", "--format", "json,html", "--top", "1"],
            )

        assert result.exit_code == 0
        assert "Top 1 Prioritized Vulnerabilities" in result.stdout
        assert "CVE-2024-0001" in result.stdout
        report.generate_json.assert_called_once()
        report.generate_html.assert_called_once()

    def test_info_command(self) -> None:
        runner = CliRunner()
        result = runner.invoke(app, ["info"])
        assert result.exit_code == 0
        assert "EPSS-Augmented CVE Prioritization Framework" in result.stdout
