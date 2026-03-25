"""
Unit tests for the Data Storage layer.
"""

from __future__ import annotations

import pytest
import tempfile
from pathlib import Path

from epss_framework.utils.database import ScanDatabase
from epss_framework.utils.models import (
    CompositeSeverity,
    EnrichedScanResult,
    EnrichedVulnerability,
    Severity,
)


@pytest.fixture
def db():
    """Create a temporary database for testing."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    database = ScanDatabase(db_path=db_path)
    yield database
    Path(db_path).unlink(missing_ok=True)


@pytest.fixture
def sample_result() -> EnrichedScanResult:
    """Create a sample enriched scan result."""
    return EnrichedScanResult(
        image_name="nginx:latest",
        image_digest="sha256:abc123",
        scanner_version="0.50.0",
        framework_version="0.1.0",
        os_family="debian",
        os_name="Debian GNU/Linux 12",
        scoring_weights={"cvss": 0.4, "epss": 0.4, "reachability": 0.2},
        scoring_method="heuristic",
        vulnerabilities=[
            EnrichedVulnerability(
                cve_id="CVE-2024-0001",
                cvss_v3_score=9.8,
                cvss_severity=Severity.CRITICAL,
                epss_score=0.95,
                composite_score=0.93,
                composite_severity=CompositeSeverity.CRITICAL,
                affected_package="openssl",
                installed_version="3.0.0",
                fixed_version="3.0.1",
                title="Critical OpenSSL RCE",
            ),
            EnrichedVulnerability(
                cve_id="CVE-2024-0002",
                cvss_v3_score=5.0,
                cvss_severity=Severity.MEDIUM,
                epss_score=0.02,
                composite_score=0.28,
                composite_severity=CompositeSeverity.LOW,
                affected_package="curl",
                installed_version="7.88.0",
                title="Medium curl info leak",
            ),
        ],
    )


class TestScanDatabase:
    """Tests for the SQLite scan database."""

    def test_save_and_retrieve_scan(self, db, sample_result):
        """Test saving and retrieving a scan."""
        scan_id = db.save_scan(sample_result)
        assert scan_id is not None
        assert scan_id > 0

        history = db.get_scan_history("nginx:latest")
        assert len(history) == 1
        assert history[0]["total_vulns"] == 2

    def test_retrieve_vulnerabilities(self, db, sample_result):
        """Test retrieving vulnerabilities for a scan."""
        scan_id = db.save_scan(sample_result)
        vulns = db.get_scan_vulnerabilities(scan_id)
        assert len(vulns) == 2
        # Should be ordered by composite_score DESC
        assert vulns[0]["composite_score"] >= vulns[1]["composite_score"]

    def test_cve_history(self, db, sample_result):
        """Test CVE history across scans."""
        db.save_scan(sample_result)
        history = db.get_cve_history("CVE-2024-0001")
        assert len(history) == 1
        assert history[0]["cvss_v3_score"] == 9.8

    def test_stats(self, db, sample_result):
        """Test database statistics."""
        db.save_scan(sample_result)
        stats = db.get_stats()
        assert stats["total_scans"] == 1
        assert stats["total_vulnerability_records"] == 2
        assert stats["unique_cves"] == 2

    def test_multiple_scans_same_image(self, db, sample_result):
        """Test multiple scans of the same image."""
        db.save_scan(sample_result)
        db.save_scan(sample_result)
        history = db.get_scan_history("nginx:latest")
        assert len(history) == 2

    def test_no_history_for_unknown_image(self, db):
        """Test querying history for an unscanned image."""
        history = db.get_scan_history("unknown:image")
        assert len(history) == 0
