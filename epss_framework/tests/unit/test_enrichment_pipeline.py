"""
Unit tests for enrichment pipeline orchestration.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from epss_framework.pipeline.enrichment_pipeline import EnrichmentPipeline, PipelineError
from epss_framework.utils.models import (
    CompositeSeverity,
    EnrichedVulnerability,
    ScanResult,
    Severity,
    Vulnerability,
)


@pytest.fixture
def sample_scan_result() -> ScanResult:
    return ScanResult(
        image_name="nginx:latest",
        vulnerabilities=[
            Vulnerability(
                cve_id="CVE-2024-0001",
                cvss_v3_score=9.8,
                severity=Severity.CRITICAL,
                affected_package="openssl",
            )
        ],
    )


class TestEnrichmentPipeline:
    """Tests for step execution and error handling in pipeline."""

    @pytest.mark.asyncio
    async def test_enrich_with_epss_skips_when_no_cves(self) -> None:
        pipeline = EnrichmentPipeline()
        pipeline._epss_client = AsyncMock()

        empty_scan = ScanResult(image_name="empty:latest", vulnerabilities=[])
        scores = await pipeline.enrich_with_epss(empty_scan)
        assert scores == {}

    @pytest.mark.asyncio
    async def test_run_executes_steps_and_closes_client(self, sample_scan_result: ScanResult) -> None:
        pipeline = EnrichmentPipeline()
        pipeline._scanner = AsyncMock()
        pipeline._scanner.scan = AsyncMock(return_value=sample_scan_result)

        pipeline._epss_client = AsyncMock()
        pipeline._epss_client.get_scores = AsyncMock(return_value={})
        pipeline._epss_client.close = AsyncMock()

        ranked = [
            EnrichedVulnerability(
                cve_id="CVE-2024-0001",
                cvss_v3_score=9.8,
                cvss_severity=Severity.CRITICAL,
                epss_score=0.0,
                composite_score=0.59,
                composite_severity=CompositeSeverity.MEDIUM,
            )
        ]
        pipeline._scorer = MagicMock()
        pipeline._scorer.weights.w_cvss = 0.4
        pipeline._scorer.weights.w_epss = 0.4
        pipeline._scorer.weights.w_reachability = 0.2
        pipeline._scorer.score_vulnerability = MagicMock(return_value=ranked[0])
        pipeline._scorer.rank_vulnerabilities = MagicMock(return_value=ranked)

        result = await pipeline.run("nginx:latest")
        assert result.image_name == "nginx:latest"
        assert result.total_vulns == 1
        pipeline._epss_client.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_run_wraps_errors_and_still_closes_client(self) -> None:
        pipeline = EnrichmentPipeline()
        pipeline._scanner = AsyncMock()
        pipeline._scanner.scan = AsyncMock(side_effect=RuntimeError("scan failed"))

        pipeline._epss_client = AsyncMock()
        pipeline._epss_client.close = AsyncMock()

        with pytest.raises(PipelineError):
            await pipeline.run("nginx:latest")

        pipeline._epss_client.close.assert_called_once()
