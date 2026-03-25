"""
Unit tests for Reachability Analyzer.
"""

from __future__ import annotations

import pytest

from epss_framework.reachability.analyzer import ReachabilityAnalyzer
from epss_framework.utils.models import Severity, Vulnerability


@pytest.fixture
def analyzer() -> ReachabilityAnalyzer:
    return ReachabilityAnalyzer()


class TestReachabilityAnalyzer:
    """Tests for Phase 1 reachability analysis."""

    def test_os_package_is_reachable(self, analyzer):
        """System-level packages should be marked reachable."""
        vuln = Vulnerability(
            cve_id="CVE-2024-OS",
            cvss_v3_score=7.5,
            severity=Severity.HIGH,
            affected_package="openssl",
            installed_version="1.1.1",
        )
        result = analyzer.analyze_vulnerability(vuln)
        assert result.is_reachable
        assert result.reachability_score == 1.0
        assert "system-level" in result.evidence[0].lower() or "reachable" in result.evidence[0].lower()

    def test_dev_package_low_reachability(self, analyzer):
        """Dev/debug packages should have low reachability."""
        vuln = Vulnerability(
            cve_id="CVE-2024-DEV",
            cvss_v3_score=5.0,
            severity=Severity.MEDIUM,
            affected_package="libfoo-dev",
            installed_version="2.0",
        )
        result = analyzer.analyze_vulnerability(vuln)
        assert not result.is_reachable
        assert result.reachability_score < 0.5

    def test_missing_version_unreachable(self, analyzer):
        """Packages with no installed version should be unreachable."""
        vuln = Vulnerability(
            cve_id="CVE-2024-PHANTOM",
            cvss_v3_score=4.0,
            severity=Severity.MEDIUM,
            affected_package="ghost-pkg",
            installed_version="",
        )
        result = analyzer.analyze_vulnerability(vuln)
        assert not result.is_reachable
        assert result.reachability_score == 0.0

    def test_normal_package_assumed_reachable(self, analyzer):
        """Regular packages default to assumed reachable."""
        vuln = Vulnerability(
            cve_id="CVE-2024-NORMAL",
            cvss_v3_score=6.0,
            severity=Severity.MEDIUM,
            affected_package="express",
            installed_version="4.18.2",
        )
        result = analyzer.analyze_vulnerability(vuln)
        assert result.is_reachable
        assert result.reachability_score == 1.0
        assert result.analysis_method == "assumed"

    def test_batch_analysis(self, analyzer):
        """Test batch analysis returns results for all vulns."""
        vulns = [
            Vulnerability(cve_id=f"CVE-{i}", affected_package=f"pkg-{i}", installed_version="1.0")
            for i in range(5)
        ]
        results = analyzer.analyze_batch(vulns)
        assert len(results) == 5
        assert all(cve_id in results for cve_id in [f"CVE-{i}" for i in range(5)])
