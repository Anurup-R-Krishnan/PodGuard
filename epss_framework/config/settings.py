"""
EPSS Framework Configuration Settings.

Centralized configuration management using Pydantic models.
All configurable parameters are defined here with sensible defaults.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field


class TrivyConfig(BaseModel):
    """Configuration for the Trivy vulnerability scanner."""

    binary_path: str = Field(
        default="trivy",
        description="Path to the Trivy binary. Defaults to system PATH.",
    )
    timeout_seconds: int = Field(
        default=600,
        description="Maximum time (seconds) for a single scan operation.",
    )
    cache_dir: Path = Field(
        default=Path.home() / ".cache" / "epss-triage" / "trivy",
        description="Directory for Trivy database cache.",
    )
    severity_filter: list[str] = Field(
        default=["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
        description="Severity levels to include in scan results.",
    )
    skip_db_update: bool = Field(
        default=False,
        description="Skip vulnerability database update before scanning.",
    )
    max_retries: int = Field(default=3, description="Max retries for failed scans.")


class EPSSConfig(BaseModel):
    """Configuration for the EPSS score enrichment module."""

    api_base_url: str = Field(
        default="https://api.first.org/data/v1/epss",
        description="Base URL for the FIRST EPSS API.",
    )
    bulk_csv_url_template: str = Field(
        default="https://epss.cyentia.com/epss_scores-{date}.csv.gz",
        description="URL template for bulk EPSS CSV download. Use {date} placeholder.",
    )
    batch_size: int = Field(
        default=100,
        description="Number of CVEs per batch API request.",
    )
    cache_ttl_hours: int = Field(
        default=24,
        description="Time-to-live for cached EPSS scores (hours).",
    )
    rate_limit_requests_per_second: float = Field(
        default=5.0,
        description="Max API requests per second.",
    )
    cache_dir: Path = Field(
        default=Path.home() / ".cache" / "epss-triage" / "epss",
        description="Directory for EPSS score cache.",
    )
    fallback_score: float = Field(
        default=0.0,
        description="EPSS score to use when a CVE has no EPSS data.",
    )


class ScoringConfig(BaseModel):
    """Configuration for composite risk scoring."""

    # Heuristic weights (Phase 1)
    weight_cvss: float = Field(
        default=0.4,
        description="Weight for CVSS severity score (w1).",
    )
    weight_epss: float = Field(
        default=0.4,
        description="Weight for EPSS exploit probability (w2).",
    )
    weight_reachability: float = Field(
        default=0.2,
        description="Weight for reachability score (w3).",
    )
    use_ml_weights: bool = Field(
        default=False,
        description="Use ML-optimized weights instead of heuristic weights.",
    )
    ml_model_path: Optional[Path] = Field(
        default=None,
        description="Path to trained XGBoost model for ML-optimized scoring.",
    )

    # Score thresholds for severity bucketing
    threshold_critical: float = Field(default=0.8, description="Score >= this → CRITICAL")
    threshold_high: float = Field(default=0.6, description="Score >= this → HIGH")
    threshold_medium: float = Field(default=0.4, description="Score >= this → MEDIUM")
    # Below medium → LOW


class PipelineConfig(BaseModel):
    """Configuration for the overall pipeline execution."""

    output_dir: Path = Field(
        default=Path("./epss-reports"),
        description="Directory for output reports.",
    )
    output_format: list[str] = Field(
        default=["json", "html"],
        description="Output report formats to generate.",
    )
    database_path: Path = Field(
        default=Path.home() / ".cache" / "epss-triage" / "scan_history.db",
        description="Path to the SQLite database for scan history.",
    )
    log_level: str = Field(
        default="INFO",
        description="Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL).",
    )
    log_format: str = Field(
        default="json",
        description="Log output format (json or text).",
    )
    max_concurrent_scans: int = Field(
        default=4,
        description="Maximum number of concurrent scan operations.",
    )


class FrameworkConfig(BaseModel):
    """Root configuration for the EPSS-Augmented CVE Prioritization Framework."""

    trivy: TrivyConfig = Field(default_factory=TrivyConfig)
    epss: EPSSConfig = Field(default_factory=EPSSConfig)
    scoring: ScoringConfig = Field(default_factory=ScoringConfig)
    pipeline: PipelineConfig = Field(default_factory=PipelineConfig)

    @classmethod
    def from_env(cls) -> FrameworkConfig:
        """Create configuration from environment variables."""
        config = cls()

        if trivy_path := os.environ.get("EPSS_TRIVY_PATH"):
            config.trivy.binary_path = trivy_path
        if log_level := os.environ.get("EPSS_LOG_LEVEL"):
            config.pipeline.log_level = log_level
        if w1 := os.environ.get("EPSS_WEIGHT_CVSS"):
            config.scoring.weight_cvss = float(w1)
        if w2 := os.environ.get("EPSS_WEIGHT_EPSS"):
            config.scoring.weight_epss = float(w2)
        if w3 := os.environ.get("EPSS_WEIGHT_REACHABILITY"):
            config.scoring.weight_reachability = float(w3)

        return config


# Global singleton (lazy-initialized)
_config: Optional[FrameworkConfig] = None


def get_config() -> FrameworkConfig:
    """Get the global framework configuration (singleton)."""
    global _config
    if _config is None:
        _config = FrameworkConfig.from_env()
    return _config


def set_config(config: FrameworkConfig) -> None:
    """Override the global framework configuration."""
    global _config
    _config = config
