"""
Unit tests for the Composite Risk Scoring Engine.
"""

from __future__ import annotations

import pytest

from epss_framework.config.settings import ScoringConfig
from epss_framework.scoring.composite_scorer import CompositeScorer, WeightProfile
from epss_framework.utils.models import (
    CompositeSeverity,
    EPSSScore,
    ReachabilityResult,
    Severity,
    Vulnerability,
)


@pytest.fixture
def sample_vulnerability() -> Vulnerability:
    """Create a sample vulnerability for testing."""
    return Vulnerability(
        cve_id="CVE-2024-1234",
        cvss_v3_score=9.8,
        severity=Severity.CRITICAL,
        title="Critical RCE in libfoo",
        description="A remote code execution vulnerability in libfoo",
        affected_package="libfoo",
        installed_version="1.2.3",
        fixed_version="1.2.4",
        cwe_ids=["CWE-79"],
    )


@pytest.fixture
def sample_epss() -> EPSSScore:
    """Create a sample EPSS score."""
    return EPSSScore(
        cve_id="CVE-2024-1234",
        epss_score=0.85,
        percentile=0.99,
    )


@pytest.fixture
def sample_reachability() -> ReachabilityResult:
    """Create a sample reachability result."""
    return ReachabilityResult(
        cve_id="CVE-2024-1234",
        package_name="libfoo",
        is_reachable=True,
        reachability_score=1.0,
        analysis_method="static",
    )


@pytest.fixture
def scorer() -> CompositeScorer:
    """Create a scorer with default heuristic weights."""
    return CompositeScorer(
        weight_profile=WeightProfile.heuristic()
    )


class TestWeightProfile:
    """Tests for WeightProfile configurations."""

    def test_heuristic_weights_sum_to_one(self):
        profile = WeightProfile.heuristic()
        total = profile.w_cvss + profile.w_epss + profile.w_reachability
        assert abs(total - 1.0) < 0.001

    def test_auto_normalization(self):
        profile = WeightProfile(w_cvss=2.0, w_epss=2.0, w_reachability=1.0)
        total = profile.w_cvss + profile.w_epss + profile.w_reachability
        assert abs(total - 1.0) < 0.001

    def test_cvss_heavy_profile(self):
        profile = WeightProfile.cvss_heavy()
        assert profile.w_cvss > profile.w_epss
        assert profile.w_cvss > profile.w_reachability

    def test_epss_heavy_profile(self):
        profile = WeightProfile.epss_heavy()
        assert profile.w_epss > profile.w_cvss
        assert profile.w_epss > profile.w_reachability

    def test_equal_profile(self):
        profile = WeightProfile.equal()
        assert abs(profile.w_cvss - profile.w_epss) < 0.001
        assert abs(profile.w_epss - profile.w_reachability) < 0.001


class TestCompositeScorer:
    """Tests for the CompositeScorer scoring engine."""

    def test_score_with_all_signals(self, scorer, sample_vulnerability, sample_epss, sample_reachability):
        """Test scoring with CVSS + EPSS + Reachability."""
        result = scorer.score_vulnerability(
            vuln=sample_vulnerability,
            epss=sample_epss,
            reachability=sample_reachability,
        )
        # CVSS=9.8 → normalized=0.98, EPSS=0.85, Reachability=1.0
        # Score = 0.4*0.98 + 0.4*0.85 + 0.2*1.0 = 0.392 + 0.34 + 0.2 = 0.932
        expected = 0.4 * 0.98 + 0.4 * 0.85 + 0.2 * 1.0
        assert abs(result.composite_score - expected) < 0.001
        assert result.composite_severity == CompositeSeverity.CRITICAL

    def test_score_without_epss(self, scorer, sample_vulnerability):
        """Test scoring when EPSS data is missing."""
        result = scorer.score_vulnerability(vuln=sample_vulnerability)
        # CVSS=9.8 → 0.98, EPSS=0 (default), Reachability=1.0 (default)
        expected = 0.4 * 0.98 + 0.4 * 0.0 + 0.2 * 1.0
        assert abs(result.composite_score - expected) < 0.001

    def test_score_unreachable_vuln(self, scorer, sample_vulnerability, sample_epss):
        """Test that unreachable vulns get lower scores."""
        unreachable = ReachabilityResult(
            cve_id="CVE-2024-1234",
            is_reachable=False,
            reachability_score=0.0,
            analysis_method="static",
        )
        result = scorer.score_vulnerability(
            vuln=sample_vulnerability,
            epss=sample_epss,
            reachability=unreachable,
        )
        # Without reachability weight contribution
        expected = 0.4 * 0.98 + 0.4 * 0.85 + 0.2 * 0.0
        assert abs(result.composite_score - expected) < 0.001

    def test_low_cvss_high_epss_gets_promoted(self, scorer):
        """A low-CVSS but high-EPSS vuln should rank higher than CVSS-only would suggest."""
        low_cvss_vuln = Vulnerability(
            cve_id="CVE-2024-LOW",
            cvss_v3_score=4.0,
            severity=Severity.MEDIUM,
            affected_package="libbar",
        )
        high_epss = EPSSScore(cve_id="CVE-2024-LOW", epss_score=0.9, percentile=0.99)

        result = scorer.score_vulnerability(vuln=low_cvss_vuln, epss=high_epss)
        # 0.4*0.4 + 0.4*0.9 + 0.2*1.0 = 0.16+0.36+0.2 = 0.72
        assert result.composite_score > 0.7
        assert result.composite_severity == CompositeSeverity.HIGH

    def test_severity_classification(self, scorer):
        """Test score-to-severity bucket mapping."""
        config = ScoringConfig()
        assert scorer._classify_severity(0.9) == CompositeSeverity.CRITICAL
        assert scorer._classify_severity(0.7) == CompositeSeverity.HIGH
        assert scorer._classify_severity(0.5) == CompositeSeverity.MEDIUM
        assert scorer._classify_severity(0.2) == CompositeSeverity.LOW

    def test_score_zero_cvss(self, scorer):
        """Test CVE with CVSS=0."""
        vuln = Vulnerability(
            cve_id="CVE-2024-ZERO",
            cvss_v3_score=0.0,
            severity=Severity.UNKNOWN,
            affected_package="unknown-pkg",
        )
        result = scorer.score_vulnerability(vuln=vuln)
        assert result.composite_score >= 0.0
        assert result.composite_score <= 1.0

    def test_ranking_order(self, scorer):
        """Test that ranking sorts by composite score descending."""
        from epss_framework.utils.models import EnrichedVulnerability

        vulns = [
            EnrichedVulnerability(cve_id="LOW", composite_score=0.2),
            EnrichedVulnerability(cve_id="HIGH", composite_score=0.8),
            EnrichedVulnerability(cve_id="MED", composite_score=0.5),
        ]
        ranked = scorer.rank_vulnerabilities(vulns)
        assert ranked[0].cve_id == "HIGH"
        assert ranked[1].cve_id == "MED"
        assert ranked[2].cve_id == "LOW"

    def test_compare_rankings(self, scorer):
        """Test CVSS-only vs composite ranking comparison."""
        from epss_framework.utils.models import EnrichedVulnerability

        vulns = [
            EnrichedVulnerability(
                cve_id="A", cvss_v3_score=9.0, epss_score=0.01, composite_score=0.38
            ),
            EnrichedVulnerability(
                cve_id="B", cvss_v3_score=5.0, epss_score=0.95, composite_score=0.78
            ),
        ]
        comparison = scorer.compare_rankings(vulns)
        assert comparison["total_vulns"] == 2
        assert comparison["promoted"] + comparison["demoted"] + comparison["unchanged"] == 2

    def test_score_explanation_generated(self, scorer, sample_vulnerability, sample_epss):
        """Test that score explanation is non-empty and descriptive."""
        result = scorer.score_vulnerability(vuln=sample_vulnerability, epss=sample_epss)
        assert result.score_explanation != ""
        assert "CVSS" in result.score_explanation
        assert "EPSS" in result.score_explanation


class TestDataModels:
    """Tests for the core data models."""

    def test_severity_from_cvss(self):
        assert Severity.from_cvss(9.5) == Severity.CRITICAL
        assert Severity.from_cvss(7.5) == Severity.HIGH
        assert Severity.from_cvss(5.0) == Severity.MEDIUM
        assert Severity.from_cvss(2.0) == Severity.LOW
        assert Severity.from_cvss(0.0) == Severity.UNKNOWN

    def test_enriched_vuln_has_fix(self):
        from epss_framework.utils.models import EnrichedVulnerability

        with_fix = EnrichedVulnerability(cve_id="CVE-1", fixed_version="2.0")
        assert with_fix.has_fix

        without_fix = EnrichedVulnerability(cve_id="CVE-2", fixed_version=None)
        assert not without_fix.has_fix

    def test_scan_result_severity_summary(self):
        from epss_framework.utils.models import ScanResult

        result = ScanResult(
            image_name="test:latest",
            vulnerabilities=[
                Vulnerability(cve_id="1", severity=Severity.CRITICAL),
                Vulnerability(cve_id="2", severity=Severity.CRITICAL),
                Vulnerability(cve_id="3", severity=Severity.HIGH),
                Vulnerability(cve_id="4", severity=Severity.LOW),
            ],
        )
        summary = result.severity_summary()
        assert summary["CRITICAL"] == 2
        assert summary["HIGH"] == 1
        assert summary["LOW"] == 1

    def test_enriched_scan_result_top_n(self):
        from epss_framework.utils.models import EnrichedScanResult, EnrichedVulnerability

        result = EnrichedScanResult(
            image_name="test:latest",
            vulnerabilities=[
                EnrichedVulnerability(cve_id=f"CVE-{i}", composite_score=i * 0.1)
                for i in range(10)
            ],
        )
        top3 = result.top_n(3)
        assert len(top3) == 3
        assert top3[0].composite_score > top3[1].composite_score
