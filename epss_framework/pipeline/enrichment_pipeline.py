"""
Enrichment Pipeline Orchestrator.

Orchestrates the full scan → enrich → score → report pipeline:
1. Scan container image with Trivy
2. Fetch EPSS scores for discovered CVEs
3. Compute composite risk scores
4. Generate ranked output
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Optional

from epss_framework.config.settings import FrameworkConfig, get_config
from epss_framework.enrichment.epss_client import EPSSClient
from epss_framework.scanner.trivy_scanner import ImageScanner
from epss_framework.scoring.composite_scorer import CompositeScorer
from epss_framework.utils.logging import get_logger
from epss_framework.utils.models import (
    EnrichedScanResult,
    EnrichedVulnerability,
    ScanResult,
)

logger = get_logger()


class PipelineError(Exception):
    """Raised when the enrichment pipeline fails."""
    pass


class EnrichmentPipeline:
    """
    End-to-end CVE prioritization pipeline.

    Orchestrates: Scan → EPSS Enrich → Score → Rank → Output

    Usage:
        pipeline = EnrichmentPipeline()
        result = await pipeline.run("nginx:latest")
        for vuln in result.top_n(10):
            print(f"{vuln.cve_id}: composite={vuln.composite_score:.4f}")
    """

    def __init__(self, config: Optional[FrameworkConfig] = None):
        self.config = config or get_config()
        self._scanner: Optional[ImageScanner] = None
        self._epss_client: Optional[EPSSClient] = None
        self._scorer: Optional[CompositeScorer] = None

    @property
    def scanner(self) -> ImageScanner:
        if self._scanner is None:
            self._scanner = ImageScanner(self.config.trivy)
        return self._scanner

    @property
    def epss_client(self) -> EPSSClient:
        if self._epss_client is None:
            self._epss_client = EPSSClient(self.config.epss)
        return self._epss_client

    @property
    def scorer(self) -> CompositeScorer:
        if self._scorer is None:
            self._scorer = CompositeScorer(self.config.scoring)
        return self._scorer

    async def scan_image(self, image: str) -> ScanResult:
        """Step 1: Scan container image with Trivy."""
        logger.info(f"[bold]═══ Step 1/4: Scanning Image ═══[/bold]")
        return await self.scanner.scan(image)

    async def enrich_with_epss(self, scan_result: ScanResult) -> dict:
        """Step 2: Fetch EPSS scores for all discovered CVEs."""
        logger.info(f"[bold]═══ Step 2/4: EPSS Enrichment ═══[/bold]")

        cve_ids = [v.cve_id for v in scan_result.vulnerabilities]
        if not cve_ids:
            logger.warning("No CVEs found, skipping EPSS enrichment.")
            return {}

        epss_scores = await self.epss_client.get_scores(cve_ids)
        return epss_scores

    def compute_scores(
        self, scan_result: ScanResult, epss_scores: dict
    ) -> list[EnrichedVulnerability]:
        """Step 3: Compute composite risk scores."""
        logger.info(f"[bold]═══ Step 3/4: Composite Scoring ═══[/bold]")

        enriched: list[EnrichedVulnerability] = []
        for vuln in scan_result.vulnerabilities:
            epss = epss_scores.get(vuln.cve_id)
            enriched_vuln = self.scorer.score_vulnerability(
                vuln=vuln,
                epss=epss,
                reachability=None,  # Phase 2: Add reachability analysis
            )
            enriched.append(enriched_vuln)

        return enriched

    def rank_and_package(
        self,
        image: str,
        scan_result: ScanResult,
        enriched_vulns: list[EnrichedVulnerability],
    ) -> EnrichedScanResult:
        """Step 4: Rank vulnerabilities and package results."""
        logger.info(f"[bold]═══ Step 4/4: Ranking & Packaging ═══[/bold]")

        ranked = self.scorer.rank_vulnerabilities(enriched_vulns)

        result = EnrichedScanResult(
            image_name=image,
            image_digest=scan_result.image_digest,
            scan_timestamp=scan_result.scan_timestamp,
            enrichment_timestamp=datetime.now(),
            scanner_version=scan_result.scanner_version,
            framework_version="0.1.0",
            os_family=scan_result.os_family,
            os_name=scan_result.os_name,
            scoring_weights={
                "cvss": self.scorer.weights.w_cvss,
                "epss": self.scorer.weights.w_epss,
                "reachability": self.scorer.weights.w_reachability,
            },
            scoring_method="heuristic",
            vulnerabilities=ranked,
        )

        # Log summary
        summary = result.severity_summary()
        fatigue = result.alert_fatigue_reduction()
        logger.info(
            f"[green bold]✓ Pipeline complete![/green bold] "
            f"{result.total_vulns} CVEs scored and ranked"
        )
        logger.info(f"  Composite severity breakdown: {summary}")
        logger.info(
            f"  Alert fatigue reduction: {fatigue.get('alert_reduction_pct', 0):.1f}%"
        )

        return result

    async def run(self, image: str) -> EnrichedScanResult:
        """
        Execute the full pipeline for a container image.

        Args:
            image: Container image reference (e.g., "nginx:latest")

        Returns:
            EnrichedScanResult with ranked, scored vulnerabilities.
        """
        logger.info(
            f"\n[bold magenta]╔══════════════════════════════════════════════════╗[/bold magenta]"
            f"\n[bold magenta]║  EPSS-Augmented CVE Prioritization Pipeline     ║[/bold magenta]"
            f"\n[bold magenta]╚══════════════════════════════════════════════════╝[/bold magenta]"
            f"\n[bold]Image:[/bold] {image}\n"
        )

        try:
            # Step 1: Scan
            scan_result = await self.scan_image(image)

            # Step 2: Enrich
            epss_scores = await self.enrich_with_epss(scan_result)

            # Step 3: Score
            enriched_vulns = self.compute_scores(scan_result, epss_scores)

            # Step 4: Rank & Package
            result = self.rank_and_package(image, scan_result, enriched_vulns)

            return result

        except Exception as e:
            logger.error(f"[red bold]Pipeline failed:[/red bold] {e}")
            raise PipelineError(f"Pipeline execution failed: {e}") from e

        finally:
            await self.epss_client.close()

    def run_sync(self, image: str) -> EnrichedScanResult:
        """Synchronous wrapper for run()."""
        return asyncio.run(self.run(image))
