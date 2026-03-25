"""
Core data models for the EPSS-Augmented CVE Prioritization Framework.

All vulnerability, scan result, and scoring data structures are defined here
using Pydantic models for validation and serialization.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """CVE severity levels based on CVSS score ranges."""

    UNKNOWN = "UNKNOWN"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @classmethod
    def from_cvss(cls, score: float) -> Severity:
        """Derive severity from CVSS v3.1 base score."""
        if score >= 9.0:
            return cls.CRITICAL
        elif score >= 7.0:
            return cls.HIGH
        elif score >= 4.0:
            return cls.MEDIUM
        elif score > 0.0:
            return cls.LOW
        return cls.UNKNOWN


class CompositeSeverity(str, Enum):
    """Severity based on composite risk score."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Vulnerability(BaseModel):
    """A single vulnerability extracted from a container scan."""

    cve_id: str = Field(..., description="CVE identifier (e.g., CVE-2024-1234)")
    cvss_v3_score: float = Field(
        default=0.0, ge=0.0, le=10.0, description="CVSS v3.1 base score"
    )
    severity: Severity = Field(default=Severity.UNKNOWN, description="CVSS-based severity")
    title: str = Field(default="", description="Vulnerability title/summary")
    description: str = Field(default="", description="Detailed description")
    affected_package: str = Field(default="", description="Name of the affected package")
    installed_version: str = Field(default="", description="Currently installed version")
    fixed_version: Optional[str] = Field(
        default=None, description="Version that fixes this vulnerability"
    )
    cwe_ids: list[str] = Field(default_factory=list, description="Related CWE identifiers")
    references: list[str] = Field(default_factory=list, description="Reference URLs")
    published_date: Optional[datetime] = Field(
        default=None, description="CVE publication date"
    )
    last_modified_date: Optional[datetime] = Field(
        default=None, description="Last modification date"
    )
    data_source: str = Field(default="trivy", description="Source of this vulnerability data")


class EPSSScore(BaseModel):
    """EPSS (Exploit Prediction Scoring System) data for a CVE."""

    cve_id: str = Field(..., description="CVE identifier")
    epss_score: float = Field(
        ..., ge=0.0, le=1.0, description="Probability of exploitation (0-1)"
    )
    percentile: float = Field(
        default=0.0, ge=0.0, le=1.0, description="EPSS percentile ranking"
    )
    model_version: str = Field(default="v2023.03.01", description="EPSS model version")
    score_date: Optional[datetime] = Field(
        default=None, description="Date the EPSS score was calculated"
    )


class ReachabilityResult(BaseModel):
    """Reachability analysis result for a vulnerability."""

    cve_id: str = Field(..., description="CVE identifier")
    package_name: str = Field(default="", description="Affected package")
    is_reachable: bool = Field(
        default=True,
        description="Whether the vulnerable component is reachable at runtime",
    )
    reachability_score: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description="Reachability score (0=unreachable, 1=fully reachable)",
    )
    analysis_method: str = Field(
        default="assumed",
        description="Method used: 'static', 'dynamic', 'dependency', 'assumed'",
    )
    evidence: list[str] = Field(
        default_factory=list,
        description="Evidence for the reachability determination",
    )


class EnrichedVulnerability(BaseModel):
    """A vulnerability enriched with EPSS scores, reachability, and composite scoring."""

    # Core CVE data
    cve_id: str = Field(..., description="CVE identifier")
    cvss_v3_score: float = Field(default=0.0, ge=0.0, le=10.0)
    cvss_severity: Severity = Field(default=Severity.UNKNOWN)
    title: str = Field(default="")
    description: str = Field(default="")

    # Package info
    affected_package: str = Field(default="")
    installed_version: str = Field(default="")
    fixed_version: Optional[str] = None

    # EPSS enrichment
    epss_score: float = Field(default=0.0, ge=0.0, le=1.0)
    epss_percentile: float = Field(default=0.0, ge=0.0, le=1.0)

    # Reachability
    reachability_score: float = Field(default=1.0, ge=0.0, le=1.0)
    reachability_method: str = Field(default="assumed")

    # Composite scoring
    composite_score: float = Field(default=0.0, ge=0.0, le=1.0)
    composite_severity: CompositeSeverity = Field(default=CompositeSeverity.LOW)
    score_explanation: str = Field(
        default="",
        description="Human-readable explanation of the composite score",
    )

    # Metadata
    cwe_ids: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    published_date: Optional[datetime] = None
    is_in_kev: bool = Field(
        default=False, description="Whether this CVE is in the CISA KEV catalog"
    )

    @property
    def cvss_normalized(self) -> float:
        """Normalize CVSS score from 0-10 to 0-1 range."""
        return self.cvss_v3_score / 10.0

    @property
    def has_fix(self) -> bool:
        """Whether a fix version is available."""
        return self.fixed_version is not None and self.fixed_version != ""


class ScanResult(BaseModel):
    """Complete scan result for a container image."""

    image_name: str = Field(..., description="Container image name (e.g., nginx:latest)")
    image_digest: str = Field(default="", description="Image SHA256 digest")
    scan_timestamp: datetime = Field(
        default_factory=datetime.now, description="When the scan was performed"
    )
    scanner_version: str = Field(default="", description="Trivy version used")
    os_family: str = Field(default="", description="OS family (e.g., debian, alpine)")
    os_name: str = Field(default="", description="OS name (e.g., Debian GNU/Linux 12)")
    vulnerabilities: list[Vulnerability] = Field(
        default_factory=list, description="List of discovered vulnerabilities"
    )

    @property
    def total_vulns(self) -> int:
        return len(self.vulnerabilities)

    @property
    def critical_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.HIGH)

    def severity_summary(self) -> dict[str, int]:
        """Get vulnerability count by severity."""
        summary: dict[str, int] = {}
        for v in self.vulnerabilities:
            key = v.severity.value
            summary[key] = summary.get(key, 0) + 1
        return summary


class EnrichedScanResult(BaseModel):
    """Complete enriched scan result with composite scoring."""

    image_name: str = Field(..., description="Container image name")
    image_digest: str = Field(default="")
    scan_timestamp: datetime = Field(default_factory=datetime.now)
    enrichment_timestamp: datetime = Field(default_factory=datetime.now)
    scanner_version: str = Field(default="")
    framework_version: str = Field(default="0.1.0")
    os_family: str = Field(default="")
    os_name: str = Field(default="")

    # Scoring configuration used
    scoring_weights: dict[str, float] = Field(default_factory=dict)
    scoring_method: str = Field(
        default="heuristic", description="'heuristic' or 'ml-optimized'"
    )

    # Enriched vulnerabilities ranked by composite score
    vulnerabilities: list[EnrichedVulnerability] = Field(default_factory=list)

    @property
    def total_vulns(self) -> int:
        return len(self.vulnerabilities)

    def top_n(self, n: int = 10) -> list[EnrichedVulnerability]:
        """Get top N vulnerabilities by composite score."""
        sorted_vulns = sorted(
            self.vulnerabilities, key=lambda v: v.composite_score, reverse=True
        )
        return sorted_vulns[:n]

    def severity_summary(self) -> dict[str, int]:
        """Get count by composite severity."""
        summary: dict[str, int] = {}
        for v in self.vulnerabilities:
            key = v.composite_severity.value
            summary[key] = summary.get(key, 0) + 1
        return summary

    def alert_fatigue_reduction(self) -> dict[str, float]:
        """Calculate alert fatigue reduction metrics."""
        total = len(self.vulnerabilities)
        if total == 0:
            return {"total": 0, "actionable": 0, "reduction_pct": 0.0}

        # CVEs rated CRITICAL/HIGH by CVSS
        cvss_critical_high = sum(
            1
            for v in self.vulnerabilities
            if v.cvss_severity in (Severity.CRITICAL, Severity.HIGH)
        )
        # CVEs rated CRITICAL/HIGH by composite score
        composite_critical_high = sum(
            1
            for v in self.vulnerabilities
            if v.composite_severity
            in (CompositeSeverity.CRITICAL, CompositeSeverity.HIGH)
        )

        reduction = (
            (cvss_critical_high - composite_critical_high) / cvss_critical_high * 100
            if cvss_critical_high > 0
            else 0.0
        )

        return {
            "total_vulns": total,
            "cvss_critical_high": cvss_critical_high,
            "composite_critical_high": composite_critical_high,
            "alert_reduction_pct": round(reduction, 2),
        }
