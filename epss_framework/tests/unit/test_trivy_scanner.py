"""
Unit tests for Trivy scanner integration.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from epss_framework.scanner.trivy_scanner import (
    ImageScanner,
    TrivyNotFoundError,
    TrivyScanError,
)
from epss_framework.utils.models import Severity


@pytest.fixture
def scanner() -> ImageScanner:
    config = SimpleNamespace(
        binary_path="trivy",
        timeout_seconds=30,
        severity_filter=["HIGH", "CRITICAL"],
        skip_db_update=False,
        max_retries=1,
    )
    with patch("epss_framework.scanner.trivy_scanner.shutil.which", return_value="/usr/bin/trivy"):
        return ImageScanner(config=config)


class TestTrivyScanner:
    """Tests for scanner command construction, parsing, and execution flow."""

    def test_verify_trivy_missing_binary_raises(self) -> None:
        config = SimpleNamespace(
            binary_path="trivy",
            timeout_seconds=30,
            severity_filter=["HIGH"],
            skip_db_update=False,
            max_retries=0,
        )
        with patch("epss_framework.scanner.trivy_scanner.shutil.which", return_value=None):
            with pytest.raises(TrivyNotFoundError):
                ImageScanner(config=config)

    def test_build_scan_command(self, scanner: ImageScanner) -> None:
        command = scanner._build_scan_command("nginx:latest")
        assert command[:3] == ["trivy", "image", "--format"]
        assert "--severity" in command
        assert "nginx:latest" in command

    def test_build_scan_command_with_skip_db_update(self, scanner: ImageScanner) -> None:
        scanner.config.skip_db_update = True
        command = scanner._build_scan_command("nginx:latest")
        assert "--skip-db-update" in command

    def test_parse_vulnerability_with_cvss_and_dates(self, scanner: ImageScanner) -> None:
        vuln = scanner._parse_vulnerability(
            {
                "VulnerabilityID": "CVE-2024-0001",
                "Severity": "CRITICAL",
                "CVSS": {"nvd": {"V3Score": 9.8}},
                "PublishedDate": "2024-01-10T00:00:00Z",
                "LastModifiedDate": "2024-01-11T00:00:00Z",
                "PkgName": "openssl",
            }
        )
        assert vuln.cve_id == "CVE-2024-0001"
        assert vuln.cvss_v3_score == 9.8
        assert vuln.severity == Severity.CRITICAL
        assert vuln.published_date is not None
        assert vuln.last_modified_date is not None

    def test_parse_vulnerability_falls_back_to_severity_map(self, scanner: ImageScanner) -> None:
        vuln = scanner._parse_vulnerability(
            {
                "VulnerabilityID": "CVE-2024-0002",
                "Severity": "HIGH",
                "PkgName": "curl",
            }
        )
        assert vuln.cvss_v3_score == 7.5
        assert vuln.severity == Severity.HIGH

    def test_parse_scan_output_deduplicates(self, scanner: ImageScanner) -> None:
        raw = """
        {
          "Metadata": {
            "ImageID": "sha256:test",
            "OS": {"Family": "debian", "Name": "Debian 12"}
          },
          "Results": [
            {
              "Target": "debian:12 (debian 12.5)",
              "Class": "os-pkgs",
              "Type": "debian",
              "Vulnerabilities": [
                {"VulnerabilityID": "CVE-2024-0001", "Severity": "HIGH", "PkgName": "openssl"},
                {"VulnerabilityID": "CVE-2024-0001", "Severity": "HIGH", "PkgName": "openssl"}
              ]
            }
          ]
        }
        """
        result = scanner._parse_scan_output("nginx:latest", raw)
        assert result.image_name == "nginx:latest"
        assert result.image_digest == "sha256:test"
        assert result.os_family == "debian"
        assert result.os_name == "Debian 12"
        assert len(result.vulnerabilities) == 1

    def test_parse_scan_output_invalid_json_raises(self, scanner: ImageScanner) -> None:
        with pytest.raises(TrivyScanError):
            scanner._parse_scan_output("nginx:latest", "{bad-json")

    @pytest.mark.asyncio
    async def test_scan_success(self, scanner: ImageScanner) -> None:
        process = AsyncMock()
        process.communicate = AsyncMock(return_value=(b'{"Results": []}', b""))
        process.returncode = 0

        with (
            patch("epss_framework.scanner.trivy_scanner.asyncio.create_subprocess_exec", return_value=process),
            patch.object(scanner, "_parse_scan_output") as parse_output,
        ):
            parse_output.return_value = MagicMock(total_vulns=0, critical_count=0, high_count=0)
            result = await scanner.scan("nginx:latest")

        assert result.total_vulns == 0
        parse_output.assert_called_once()

    @pytest.mark.asyncio
    async def test_scan_nonzero_exit_raises(self, scanner: ImageScanner) -> None:
        process = AsyncMock()
        process.communicate = AsyncMock(return_value=(b"", b"scan failed"))
        process.returncode = 1

        with patch("epss_framework.scanner.trivy_scanner.asyncio.create_subprocess_exec", return_value=process):
            with pytest.raises(TrivyScanError):
                await scanner.scan("nginx:latest")

    def test_get_trivy_version_unknown_on_error(self, scanner: ImageScanner) -> None:
        with patch("epss_framework.scanner.trivy_scanner.subprocess.run", side_effect=RuntimeError("boom")):
            assert scanner._get_trivy_version() == "unknown"

    def test_get_trivy_version_parses_json(self, scanner: ImageScanner) -> None:
        completed = SimpleNamespace(returncode=0, stdout='{"Version":"0.51.0"}')
        with patch("epss_framework.scanner.trivy_scanner.subprocess.run", return_value=completed):
            assert scanner._get_trivy_version() == "0.51.0"
