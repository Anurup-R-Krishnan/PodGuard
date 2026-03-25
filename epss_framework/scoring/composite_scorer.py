"""
Composite Risk Scoring Engine.

Implements the multi-factor CVE prioritization scoring system using
configurable weights for CVSS, EPSS, and Reachability signals.

Phase 1: Heuristic weight assignment
Phase 2: ML-optimized weights (via XGBoost, implemented later)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from epss_framework.config.settings import ScoringConfig, get_config
from epss_framework.utils.logging import get_logger
from epss_framework.utils.models import (
    CompositeSeverity,
    EnrichedVulnerability,
    EPSSScore,
    ReachabilityResult,
    Vulnerability,
)

logger = get_logger()


@dataclass
class WeightProfile:
    """A set of weights for composite scoring."""

    w_cvss: float
    w_epss: float
    w_reachability: float
    name: str = "custom"

    def __post_init__(self) -> None:
        total = self.w_cvss + self.w_epss + self.w_reachability
        if abs(total - 1.0) > 0.001:
            # Normalize weights to sum to 1.0
            self.w_cvss /= total
            self.w_epss /= total
            self.w_reachability /= total

    @classmethod
    def heuristic(cls) -> WeightProfile:
        """Default heuristic weights from research."""
        return cls(w_cvss=0.4, w_epss=0.4, w_reachability=0.2, name="heuristic")

    @classmethod
    def cvss_heavy(cls) -> WeightProfile:
        """CVSS-dominant weighting (traditional approach)."""
        return cls(w_cvss=0.7, w_epss=0.2, w_reachability=0.1, name="cvss-heavy")

    @classmethod
    def epss_heavy(cls) -> WeightProfile:
        """EPSS-dominant weighting (threat-informed approach)."""
        return cls(w_cvss=0.2, w_epss=0.6, w_reachability=0.2, name="epss-heavy")

    @classmethod
    def equal(cls) -> WeightProfile:
        """Equal weights for all three factors."""
        return cls(w_cvss=1 / 3, w_epss=1 / 3, w_reachability=1 / 3, name="equal")


class CompositeScorer:
    """
    Computes composite risk scores for vulnerabilities.

    The composite score combines:
    - CVSS score (severity: how bad it could be)
    - EPSS score (probability: how likely exploitation is)
    - Reachability (relevance: is the vulnerable code actually used)

    Formula:
        CompositeScore = w1 × normalize(CVSS) + w2 × EPSS + w3 × Reachability
    """

    def __init__(
        self,
        config: Optional[ScoringConfig] = None,
        weight_profile: Optional[WeightProfile] = None,
    ):
        self.config = config or get_config().scoring
        self.weights = weight_profile or WeightProfile(
            w_cvss=self.config.weight_cvss,
            w_epss=self.config.weight_epss,
            w_reachability=self.config.weight_reachability,
            name="configured",
        )

    def _normalize_cvss(self, cvss_score: float) -> float:
        """Normalize CVSS from 0-10 to 0-1 range."""
        return min(max(cvss_score / 10.0, 0.0), 1.0)

    def _classify_severity(self, score: float) -> CompositeSeverity:
        """Classify composite score into severity bucket."""
        if score >= self.config.threshold_critical:
            return CompositeSeverity.CRITICAL
        elif score >= self.config.threshold_high:
            return CompositeSeverity.HIGH
        elif score >= self.config.threshold_medium:
            return CompositeSeverity.MEDIUM
        return CompositeSeverity.LOW

    def _generate_explanation(
        self,
        cvss_normalized: float,
        epss_score: float,
        reachability_score: float,
        composite_score: float,
    ) -> str:
        """Generate a human-readable explanation of the composite score."""
        parts: list[str] = []

        # Identify dominant factor
        contributions = {
            "CVSS severity": self.weights.w_cvss * cvss_normalized,
            "EPSS exploit probability": self.weights.w_epss * epss_score,
            "Reachability": self.weights.w_reachability * reachability_score,
        }
        dominant = max(contributions, key=contributions.get)  # type: ignore
        parts.append(f"Primary driver: {dominant}")

        # CVSS context
        cvss_orig = cvss_normalized * 10
        if cvss_orig >= 9.0:
            parts.append(f"CVSS {cvss_orig:.1f}/10 → extremely severe vulnerability")
        elif cvss_orig >= 7.0:
            parts.append(f"CVSS {cvss_orig:.1f}/10 → high severity")
        elif cvss_orig >= 4.0:
            parts.append(f"CVSS {cvss_orig:.1f}/10 → medium severity")
        else:
            parts.append(f"CVSS {cvss_orig:.1f}/10 → low severity")

        # EPSS context
        if epss_score >= 0.5:
            parts.append(f"EPSS {epss_score:.3f} → very high exploit probability (top tier)")
        elif epss_score >= 0.1:
            parts.append(f"EPSS {epss_score:.3f} → elevated exploit likelihood")
        elif epss_score >= 0.01:
            parts.append(f"EPSS {epss_score:.3f} → moderate exploit probability")
        else:
            parts.append(f"EPSS {epss_score:.4f} → low exploit probability")

        # Reachability context
        if reachability_score >= 0.8:
            parts.append("Vulnerable component is reachable in runtime")
        elif reachability_score <= 0.2:
            parts.append("Vulnerable component appears unreachable (risk mitigated)")
        else:
            parts.append(f"Reachability score: {reachability_score:.2f}")

        return " | ".join(parts)

    def score_vulnerability(
        self,
        vuln: Vulnerability,
        epss: Optional[EPSSScore] = None,
        reachability: Optional[ReachabilityResult] = None,
    ) -> EnrichedVulnerability:
        """
        Compute composite risk score for a single vulnerability.

        Args:
            vuln: Base vulnerability data from scanner.
            epss: EPSS score data (optional, defaults to 0).
            reachability: Reachability analysis result (optional, defaults to 1.0/assumed).

        Returns:
            EnrichedVulnerability with composite score computed.
        """
        cvss_normalized = self._normalize_cvss(vuln.cvss_v3_score)
        epss_score = epss.epss_score if epss else 0.0
        epss_percentile = epss.percentile if epss else 0.0
        reach_score = reachability.reachability_score if reachability else 1.0
        reach_method = reachability.analysis_method if reachability else "assumed"

        # Composite Score Calculation
        composite = (
            self.weights.w_cvss * cvss_normalized
            + self.weights.w_epss * epss_score
            + self.weights.w_reachability * reach_score
        )
        composite = min(max(composite, 0.0), 1.0)

        severity = self._classify_severity(composite)
        explanation = self._generate_explanation(
            cvss_normalized, epss_score, reach_score, composite
        )

        return EnrichedVulnerability(
            cve_id=vuln.cve_id,
            cvss_v3_score=vuln.cvss_v3_score,
            cvss_severity=vuln.severity,
            title=vuln.title,
            description=vuln.description,
            affected_package=vuln.affected_package,
            installed_version=vuln.installed_version,
            fixed_version=vuln.fixed_version,
            epss_score=epss_score,
            epss_percentile=epss_percentile,
            reachability_score=reach_score,
            reachability_method=reach_method,
            composite_score=round(composite, 6),
            composite_severity=severity,
            score_explanation=explanation,
            cwe_ids=vuln.cwe_ids,
            references=vuln.references,
            published_date=vuln.published_date,
        )

    def rank_vulnerabilities(
        self, enriched_vulns: list[EnrichedVulnerability]
    ) -> list[EnrichedVulnerability]:
        """
        Rank vulnerabilities by composite score (descending).

        Tie-breaking order:
        1. Composite score (primary, descending)
        2. EPSS score (secondary, descending)
        3. CVSS score (tertiary, descending)
        """
        return sorted(
            enriched_vulns,
            key=lambda v: (v.composite_score, v.epss_score, v.cvss_v3_score),
            reverse=True,
        )

    def compare_rankings(
        self, enriched_vulns: list[EnrichedVulnerability]
    ) -> dict:
        """
        Compare CVSS-only ranking vs. composite ranking.

        Returns statistics about how many CVEs changed rank positions.
        """
        # CVSS-only ranking
        cvss_ranked = sorted(
            enriched_vulns, key=lambda v: v.cvss_v3_score, reverse=True
        )
        cvss_order = {v.cve_id: i for i, v in enumerate(cvss_ranked)}

        # Composite ranking
        composite_ranked = self.rank_vulnerabilities(enriched_vulns)
        composite_order = {v.cve_id: i for i, v in enumerate(composite_ranked)}

        # Calculate rank changes
        rank_changes: list[dict] = []
        promoted = 0
        demoted = 0
        unchanged = 0

        for cve_id in cvss_order:
            cvss_rank = cvss_order[cve_id]
            composite_rank = composite_order[cve_id]
            change = cvss_rank - composite_rank  # positive = promoted

            if change > 0:
                promoted += 1
            elif change < 0:
                demoted += 1
            else:
                unchanged += 1

            rank_changes.append({
                "cve_id": cve_id,
                "cvss_rank": cvss_rank + 1,
                "composite_rank": composite_rank + 1,
                "rank_change": change,
            })

        # Sort by absolute rank change to find most significant movements
        rank_changes.sort(key=lambda x: abs(x["rank_change"]), reverse=True)

        return {
            "total_vulns": len(enriched_vulns),
            "promoted": promoted,
            "demoted": demoted,
            "unchanged": unchanged,
            "top_movements": rank_changes[:10],
            "weights_used": {
                "cvss": self.weights.w_cvss,
                "epss": self.weights.w_epss,
                "reachability": self.weights.w_reachability,
            },
        }
