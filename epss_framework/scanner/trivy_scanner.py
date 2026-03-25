"""
Trivy Scanner Integration Module.

Wraps the Trivy vulnerability scanner to scan Docker container images
and extract structured vulnerability data (CVEs + CVSS scores).
"""

from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional

from epss_framework.config.settings import get_config
from epss_framework.utils.logging import get_logger
from epss_framework.utils.models import ScanResult, Severity, Vulnerability

logger = get_logger()


class TrivyScanError(Exception):
    """Raised when Trivy scanning fails."""
    pass


class TrivyNotFoundError(TrivyScanError):
    """Raised when Trivy binary is not found."""
    pass


class ImageScanner:
    """
    Scans container images using Trivy and extracts CVE data.

    Usage:
        scanner = ImageScanner()
        result = await scanner.scan("nginx:latest")
        for vuln in result.vulnerabilities:
            print(f"{vuln.cve_id}: CVSS={vuln.cvss_v3_score}")
    """

    def __init__(self, config: Optional[object] = None):
        self.config = config or get_config().trivy
        self._verify_trivy()

    def _verify_trivy(self) -> None:
        """Verify Trivy binary is available."""
        trivy_path = shutil.which(self.config.binary_path)
        if trivy_path is None:
            raise TrivyNotFoundError(
                f"Trivy binary not found at '{self.config.binary_path}'. "
                "Install Trivy: https://aquasecurity.github.io/trivy/latest/getting-started/installation/"
            )
        logger.info(f"[green]✓[/green] Trivy found at: {trivy_path}")

    def _get_trivy_version(self) -> str:
        """Get the installed Trivy version."""
        try:
            result = subprocess.run(
                [self.config.binary_path, "version", "--format", "json"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                version_data = json.loads(result.stdout)
                return version_data.get("Version", "unknown")
        except Exception:
            pass
        return "unknown"

    def _build_scan_command(self, image: str) -> list[str]:
        """Build the Trivy scan command with proper arguments."""
        cmd = [
            self.config.binary_path,
            "image",
            "--format", "json",
            "--severity", ",".join(self.config.severity_filter),
            "--timeout", f"{self.config.timeout_seconds}s",
        ]

        if self.config.skip_db_update:
            cmd.append("--skip-db-update")

        cmd.append(image)
        return cmd

    def _parse_vulnerability(self, vuln_data: dict, pkg_name: str = "") -> Vulnerability:
        """Parse a single vulnerability from Trivy JSON output."""
        # Extract CVSS v3 score
        cvss_score = 0.0
        if "CVSS" in vuln_data:
            for vendor_cvss in vuln_data["CVSS"].values():
                if "V3Score" in vendor_cvss:
                    cvss_score = float(vendor_cvss["V3Score"])
                    break

        # Fallback to the severity-based score if V3Score not in CVSS block
        if cvss_score == 0.0 and "Severity" in vuln_data:
            severity_map = {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.5}
            cvss_score = severity_map.get(vuln_data["Severity"].upper(), 0.0)

        severity_str = vuln_data.get("Severity", "UNKNOWN").upper()
        try:
            severity = Severity(severity_str)
        except ValueError:
            severity = Severity.from_cvss(cvss_score)

        # Parse dates
        published = None
        if "PublishedDate" in vuln_data:
            try:
                published = datetime.fromisoformat(
                    vuln_data["PublishedDate"].replace("Z", "+00:00")
                )
            except (ValueError, TypeError):
                pass

        last_modified = None
        if "LastModifiedDate" in vuln_data:
            try:
                last_modified = datetime.fromisoformat(
                    vuln_data["LastModifiedDate"].replace("Z", "+00:00")
                )
            except (ValueError, TypeError):
                pass

        return Vulnerability(
            cve_id=vuln_data.get("VulnerabilityID", "UNKNOWN"),
            cvss_v3_score=cvss_score,
            severity=severity,
            title=vuln_data.get("Title", ""),
            description=vuln_data.get("Description", ""),
            affected_package=vuln_data.get("PkgName", pkg_name),
            installed_version=vuln_data.get("InstalledVersion", ""),
            fixed_version=vuln_data.get("FixedVersion"),
            cwe_ids=vuln_data.get("CweIDs", []),
            references=vuln_data.get("References", []),
            published_date=published,
            last_modified_date=last_modified,
            data_source="trivy",
        )

    def _parse_scan_output(self, image: str, raw_output: str) -> ScanResult:
        """Parse the full Trivy JSON output into a ScanResult."""
        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError as e:
            raise TrivyScanError(f"Failed to parse Trivy output: {e}") from e

        vulnerabilities: list[Vulnerability] = []
        os_family = ""
        os_name = ""

        # Handle Trivy JSON structure
        if "Results" in data:
            for result_block in data["Results"]:
                target = result_block.get("Target", "")

                # Extract OS info from OS-level results
                if result_block.get("Class") == "os-pkgs" or "os-pkgs" in target:
                    os_family = result_block.get("Type", os_family)

                for vuln_data in result_block.get("Vulnerabilities", []):
                    pkg = vuln_data.get("PkgName", "")
                    vuln = self._parse_vulnerability(vuln_data, pkg)
                    vulnerabilities.append(vuln)

        # Extract metadata
        if "Metadata" in data:
            metadata = data["Metadata"]
            if "OS" in metadata:
                os_family = metadata["OS"].get("Family", os_family)
                os_name = metadata["OS"].get("Name", os_name)

        # Deduplicate by CVE ID + package
        seen = set()
        unique_vulns = []
        for v in vulnerabilities:
            key = (v.cve_id, v.affected_package)
            if key not in seen:
                seen.add(key)
                unique_vulns.append(v)

        return ScanResult(
            image_name=image,
            image_digest=data.get("Metadata", {}).get("ImageID", ""),
            scan_timestamp=datetime.now(),
            scanner_version=self._get_trivy_version(),
            os_family=os_family,
            os_name=os_name,
            vulnerabilities=unique_vulns,
        )

    async def scan(self, image: str) -> ScanResult:
        """
        Scan a container image for vulnerabilities.

        Args:
            image: Container image reference (e.g., "nginx:latest", "ubuntu:22.04")

        Returns:
            ScanResult with all discovered vulnerabilities.

        Raises:
            TrivyScanError: If the scan fails.
        """
        cmd = self._build_scan_command(image)
        logger.info(f"[bold blue]🔍 Scanning image:[/bold blue] {image}")
        logger.debug(f"Command: {' '.join(cmd)}")

        retries = 0
        last_error: Optional[Exception] = None

        while retries <= self.config.max_retries:
            try:
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=self.config.timeout_seconds,
                )

                if process.returncode != 0:
                    error_msg = stderr.decode().strip()
                    raise TrivyScanError(
                        f"Trivy scan failed (exit code {process.returncode}): {error_msg}"
                    )

                result = self._parse_scan_output(image, stdout.decode())
                logger.info(
                    f"[green]✓ Scan complete:[/green] {result.total_vulns} vulnerabilities found "
                    f"(C:{result.critical_count} H:{result.high_count})"
                )
                return result

            except asyncio.TimeoutError:
                last_error = TrivyScanError(
                    f"Scan timed out after {self.config.timeout_seconds}s"
                )
                retries += 1
                if retries <= self.config.max_retries:
                    logger.warning(
                        f"Scan timeout, retry {retries}/{self.config.max_retries}..."
                    )
            except TrivyScanError:
                raise
            except Exception as e:
                last_error = TrivyScanError(f"Unexpected error during scan: {e}")
                retries += 1
                if retries <= self.config.max_retries:
                    logger.warning(
                        f"Scan error, retry {retries}/{self.config.max_retries}: {e}"
                    )

        raise last_error or TrivyScanError("Scan failed after all retries")

    def scan_sync(self, image: str) -> ScanResult:
        """Synchronous wrapper for scan()."""
        return asyncio.run(self.scan(image))
