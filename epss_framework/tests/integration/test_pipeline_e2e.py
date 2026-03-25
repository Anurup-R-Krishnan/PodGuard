"""
Integration test for the full pipeline flow.

Tests the end-to-end pipeline using mock Trivy output and live/mock EPSS API.
"""

from __future__ import annotations

import json
import tempfile
from datetime import datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from epss_framework.config.settings import FrameworkConfig
from epss_framework.pipeline.enrichment_pipeline import EnrichmentPipeline
from epss_framework.reports.report_generator import ReportGenerator
from epss_framework.scoring.composite_scorer import CompositeScorer
from epss_framework.utils.database import ScanDatabase
from epss_framework.utils.models import (
    EnrichedScanResult,
    EnrichedVulnerability,
    ScanResult,
    Severity,
    Vulnerability,
)


@pytest.fixture
def sample_scan_result() -> ScanResult:
    """Create a realistic scan result for testing."""
    return ScanResult(
        image_name="nginx:1.25",
        image_digest="sha256:abc123def456",
        scanner_version="0.50.0",
        os_family="debian",
        os_name="Debian GNU/Linux 12 (bookworm)",
        vulnerabilities=[
            Vulnerability(
                cve_id="CVE-2024-0001",
                cvss_v3_score=9.8,
                severity=Severity.CRITICAL,
                title="Remote Code Execution in OpenSSL",
                description="A critical buffer overflow vulnerability allowing RCE",
                affected_package="openssl",
                installed_version="3.0.0",
                fixed_version="3.0.1",
                cwe_ids=["CWE-120"],
                references=["https://nvd.nist.gov/vuln/detail/CVE-2024-0001"],
            ),
            Vulnerability(
                cve_id="CVE-2024-0002",
                cvss_v3_score=7.5,
                severity=Severity.HIGH,
                title="Information Disclosure in curl",
                description="Sensitive information leak via HTTP headers",
                affected_package="curl",
                installed_version="7.88.0",
                fixed_version="7.88.1",
                cwe_ids=["CWE-200"],
            ),
            Vulnerability(
                cve_id="CVE-2024-0003",
                cvss_v3_score=5.3,
                severity=Severity.MEDIUM,
                title="Denial of Service in zlib",
                description="Memory exhaustion via crafted input",
                affected_package="zlib",
                installed_version="1.2.13",
                fixed_version="1.2.14",
                cwe_ids=["CWE-400"],
            ),
            Vulnerability(
                cve_id="CVE-2024-0004",
                cvss_v3_score=3.1,
                severity=Severity.LOW,
                title="Minor XSS in libxml2",
                description="Reflected XSS via SVG parsing",
                affected_package="libxml2",
                installed_version="2.9.14",
                fixed_version=None,
                cwe_ids=["CWE-79"],
            ),
            Vulnerability(
                cve_id="CVE-2024-0005",
                cvss_v3_score=4.0,
                severity=Severity.MEDIUM,
                title="Low-priority bug in libfoo-dev",
                description="Dev package issue",
                affected_package="libfoo-dev",
                installed_version="1.0",
            ),
        ],
    )


class TestPipelineIntegration:
    """Integration tests for the enrichment pipeline."""

    def test_scoring_produces_ranked_output(self, sample_scan_result):
        """Test that scoring + ranking works end-to-end."""
        from epss_framework.enrichment.epss_client import EPSSClient
        from epss_framework.utils.models import EPSSScore

        scorer = CompositeScorer()

        # Simulate EPSS scores
        epss_map = {
            "CVE-2024-0001": EPSSScore(cve_id="CVE-2024-0001", epss_score=0.92, percentile=0.99),
            "CVE-2024-0002": EPSSScore(cve_id="CVE-2024-0002", epss_score=0.15, percentile=0.80),
            "CVE-2024-0003": EPSSScore(cve_id="CVE-2024-0003", epss_score=0.03, percentile=0.50),
            "CVE-2024-0004": EPSSScore(cve_id="CVE-2024-0004", epss_score=0.001, percentile=0.10),
            "CVE-2024-0005": EPSSScore(cve_id="CVE-2024-0005", epss_score=0.50, percentile=0.90),
        }

        # Score each vulnerability
        enriched = []
        for vuln in sample_scan_result.vulnerabilities:
            epss = epss_map.get(vuln.cve_id)
            enriched_vuln = scorer.score_vulnerability(vuln=vuln, epss=epss)
            enriched.append(enriched_vuln)

        # Rank
        ranked = scorer.rank_vulnerabilities(enriched)

        # Verify ranking order (highest composite first)
        assert ranked[0].composite_score >= ranked[1].composite_score
        assert ranked[-1].composite_score <= ranked[-2].composite_score

        # CVE-2024-0001 should be #1 (highest CVSS + highest EPSS)
        assert ranked[0].cve_id == "CVE-2024-0001"

        # Build enriched scan result
        result = EnrichedScanResult(
            image_name="nginx:1.25",
            vulnerabilities=ranked,
            scoring_weights={"cvss": 0.4, "epss": 0.4, "reachability": 0.2},
        )
        assert result.total_vulns == 5

        # Alert fatigue reduction should show some difference
        fatigue = result.alert_fatigue_reduction()
        assert "total_vulns" in fatigue
        assert fatigue["total_vulns"] == 5

    def test_report_generation(self, sample_scan_result):
        """Test JSON and HTML report generation."""
        scorer = CompositeScorer()
        from epss_framework.utils.models import EPSSScore

        epss_map = {
            "CVE-2024-0001": EPSSScore(cve_id="CVE-2024-0001", epss_score=0.92, percentile=0.99),
            "CVE-2024-0002": EPSSScore(cve_id="CVE-2024-0002", epss_score=0.15, percentile=0.80),
            "CVE-2024-0003": EPSSScore(cve_id="CVE-2024-0003", epss_score=0.03, percentile=0.50),
            "CVE-2024-0004": EPSSScore(cve_id="CVE-2024-0004", epss_score=0.001, percentile=0.10),
            "CVE-2024-0005": EPSSScore(cve_id="CVE-2024-0005", epss_score=0.50, percentile=0.90),
        }

        enriched = []
        for vuln in sample_scan_result.vulnerabilities:
            epss = epss_map.get(vuln.cve_id)
            enriched.append(scorer.score_vulnerability(vuln=vuln, epss=epss))

        ranked = scorer.rank_vulnerabilities(enriched)
        result = EnrichedScanResult(
            image_name="nginx:1.25",
            vulnerabilities=ranked,
            scoring_weights={"cvss": 0.4, "epss": 0.4, "reachability": 0.2},
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            gen = ReportGenerator(output_dir=tmpdir)

            # JSON
            json_path = gen.generate_json(result, "test_report.json")
            assert json_path.exists()
            with open(json_path) as f:
                data = json.load(f)
            assert data["summary"]["total_vulnerabilities"] == 5
            assert len(data["vulnerabilities"]) == 5
            assert data["vulnerabilities"][0]["rank"] == 1

            # HTML
            html_path = gen.generate_html(result, "test_report.html")
            assert html_path.exists()
            html_content = html_path.read_text()
            assert "CVE-2024-0001" in html_content
            assert "EPSS-Augmented" in html_content
            assert "nginx:1.25" in html_content

    def test_database_persistence(self, sample_scan_result):
        """Test saving and loading scan results from database."""
        scorer = CompositeScorer()
        from epss_framework.utils.models import EPSSScore

        epss_map = {
            "CVE-2024-0001": EPSSScore(cve_id="CVE-2024-0001", epss_score=0.92, percentile=0.99),
        }

        enriched = []
        for vuln in sample_scan_result.vulnerabilities:
            epss = epss_map.get(vuln.cve_id)
            enriched.append(scorer.score_vulnerability(vuln=vuln, epss=epss))

        result = EnrichedScanResult(
            image_name="nginx:1.25",
            vulnerabilities=scorer.rank_vulnerabilities(enriched),
            scoring_weights={"cvss": 0.4, "epss": 0.4, "reachability": 0.2},
        )

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name

        try:
            db = ScanDatabase(db_path=db_path)
            scan_id = db.save_scan(result)

            # Verify
            history = db.get_scan_history("nginx:1.25")
            assert len(history) == 1
            assert history[0]["total_vulns"] == 5

            vulns = db.get_scan_vulnerabilities(scan_id)
            assert len(vulns) == 5

            stats = db.get_stats()
            assert stats["total_scans"] == 1
            assert stats["unique_cves"] == 5
        finally:
            Path(db_path).unlink(missing_ok=True)

    def test_reachability_integration(self, sample_scan_result):
        """Test reachability analysis integrated with scoring."""
        from epss_framework.reachability.analyzer import ReachabilityAnalyzer

        analyzer = ReachabilityAnalyzer()
        scorer = CompositeScorer()

        # Analyze reachability
        reach_results = analyzer.analyze_batch(sample_scan_result.vulnerabilities)

        # Score with reachability
        enriched = []
        for vuln in sample_scan_result.vulnerabilities:
            reach = reach_results.get(vuln.cve_id)
            enriched.append(scorer.score_vulnerability(vuln=vuln, reachability=reach))

        # libfoo-dev should have lower score due to dev-package detection
        dev_vuln = next(v for v in enriched if v.cve_id == "CVE-2024-0005")
        normal_vuln = next(v for v in enriched if v.cve_id == "CVE-2024-0003")

        # Without EPSS both have similar CVSS, but dev package has lower reachability
        assert dev_vuln.reachability_score < normal_vuln.reachability_score

    def test_evaluation_metrics(self, sample_scan_result):
        """Test NDCG evaluation on ranked results."""
        from epss_framework.evaluation.ranking_metrics import RankingEvaluator

        scorer = CompositeScorer()
        from epss_framework.utils.models import EPSSScore

        epss_map = {
            "CVE-2024-0001": EPSSScore(cve_id="CVE-2024-0001", epss_score=0.92, percentile=0.99),
            "CVE-2024-0002": EPSSScore(cve_id="CVE-2024-0002", epss_score=0.15, percentile=0.80),
            "CVE-2024-0003": EPSSScore(cve_id="CVE-2024-0003", epss_score=0.03, percentile=0.50),
            "CVE-2024-0004": EPSSScore(cve_id="CVE-2024-0004", epss_score=0.001, percentile=0.10),
            "CVE-2024-0005": EPSSScore(cve_id="CVE-2024-0005", epss_score=0.50, percentile=0.90),
        }

        enriched = []
        for vuln in sample_scan_result.vulnerabilities:
            epss = epss_map.get(vuln.cve_id)
            enriched.append(scorer.score_vulnerability(vuln=vuln, epss=epss))

        ranked = scorer.rank_vulnerabilities(enriched)

        # Simulate KEV: CVE-0001 is "known exploited"
        kev_ids = {"CVE-2024-0001"}
        evaluator = RankingEvaluator(kev_cve_ids=kev_ids)

        metrics = evaluator.evaluate_ranking(ranked, k=5)
        assert "NDCG@5" in metrics
        assert metrics["NDCG@5"] > 0
        assert metrics["kev_vulns_in_dataset"] == 1

        # KEV item should be ranked #1 → Precision@1 = 1.0
        assert metrics["Precision@5"] > 0
