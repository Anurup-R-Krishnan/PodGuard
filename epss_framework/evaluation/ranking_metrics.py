"""
NDCG@K and Ranking Evaluation Metrics (Phase 1 Foundation).

Implements information retrieval evaluation metrics for measuring
the quality of vulnerability ranking:
- NDCG@K (Normalized Discounted Cumulative Gain)
- Precision@K
- Recall@K
- MAP@K (Mean Average Precision)

Used for benchmarking composite scoring vs. CVSS-only ranking.
"""

from __future__ import annotations

import math
from typing import Optional

from epss_framework.utils.logging import get_logger
from epss_framework.utils.models import EnrichedVulnerability

logger = get_logger()


def dcg_at_k(relevance_scores: list[float], k: int) -> float:
    """
    Compute Discounted Cumulative Gain at position K.

    DCG@K = Σ (2^rel_i - 1) / log2(i + 2) for i in 0..k-1
    """
    dcg = 0.0
    for i in range(min(k, len(relevance_scores))):
        rel = relevance_scores[i]
        dcg += (2**rel - 1) / math.log2(i + 2)
    return dcg


def ndcg_at_k(relevance_scores: list[float], k: int) -> float:
    """
    Compute Normalized Discounted Cumulative Gain at position K.

    NDCG@K = DCG@K / IDCG@K

    Where IDCG@K is the ideal DCG (perfect ranking).

    Args:
        relevance_scores: Ordered list of relevance scores (in the ranking order).
        k: Number of top results to evaluate.

    Returns:
        NDCG@K score between 0.0 and 1.0 (1.0 = perfect ranking).
    """
    dcg = dcg_at_k(relevance_scores, k)

    # Ideal DCG: sort relevance scores in descending order
    ideal_scores = sorted(relevance_scores, reverse=True)
    idcg = dcg_at_k(ideal_scores, k)

    if idcg == 0:
        return 0.0
    return dcg / idcg


def precision_at_k(
    relevant_set: set[str], ranked_list: list[str], k: int
) -> float:
    """
    Compute Precision@K.

    Precision@K = |relevant items in top K| / K
    """
    top_k = ranked_list[:k]
    relevant_in_top_k = sum(1 for item in top_k if item in relevant_set)
    return relevant_in_top_k / k if k > 0 else 0.0


def recall_at_k(
    relevant_set: set[str], ranked_list: list[str], k: int
) -> float:
    """
    Compute Recall@K.

    Recall@K = |relevant items in top K| / |total relevant items|
    """
    if not relevant_set:
        return 0.0
    top_k = ranked_list[:k]
    relevant_in_top_k = sum(1 for item in top_k if item in relevant_set)
    return relevant_in_top_k / len(relevant_set)


def average_precision(
    relevant_set: set[str], ranked_list: list[str]
) -> float:
    """
    Compute Average Precision for a single query.

    AP = (1/|relevant|) × Σ Precision@k × rel(k) for k = 1..n
    """
    if not relevant_set:
        return 0.0

    num_relevant = 0
    sum_precision = 0.0

    for i, item in enumerate(ranked_list):
        if item in relevant_set:
            num_relevant += 1
            sum_precision += num_relevant / (i + 1)

    return sum_precision / len(relevant_set) if relevant_set else 0.0


def map_at_k(
    relevant_set: set[str], ranked_list: list[str], k: int
) -> float:
    """
    Compute Mean Average Precision at K.
    """
    truncated = ranked_list[:k]
    return average_precision(relevant_set, truncated)


class RankingEvaluator:
    """
    Evaluates ranking quality for vulnerability prioritization.

    Uses CISA KEV catalog as ground truth for "relevant" (known exploited) CVEs.

    Usage:
        evaluator = RankingEvaluator(kev_cve_ids={"CVE-2024-1234", "CVE-2024-5678"})
        metrics = evaluator.evaluate_ranking(enriched_vulns, k=10)
    """

    def __init__(self, kev_cve_ids: Optional[set[str]] = None):
        self.kev_cve_ids = kev_cve_ids or set()

    def _get_relevance_scores(
        self, ranked_vulns: list[EnrichedVulnerability]
    ) -> list[float]:
        """
        Convert ranked vulnerabilities to relevance scores.

        Relevance grading:
        - 3: In CISA KEV (confirmed exploited)
        - 2: EPSS ≥ 0.5 (high exploit probability)
        - 1: EPSS ≥ 0.1 (moderate exploit probability)
        - 0: Everything else
        """
        scores: list[float] = []
        for vuln in ranked_vulns:
            if vuln.cve_id in self.kev_cve_ids:
                scores.append(3.0)
            elif vuln.epss_score >= 0.5:
                scores.append(2.0)
            elif vuln.epss_score >= 0.1:
                scores.append(1.0)
            else:
                scores.append(0.0)
        return scores

    def evaluate_ranking(
        self,
        ranked_vulns: list[EnrichedVulnerability],
        k: int = 10,
    ) -> dict[str, float]:
        """
        Evaluate a vulnerability ranking using multiple metrics.

        Args:
            ranked_vulns: Vulnerabilities in ranked order (best first).
            k: Number of top results to evaluate.

        Returns:
            Dict of metric name → score.
        """
        # Relevance-based metrics (NDCG)
        relevance = self._get_relevance_scores(ranked_vulns)
        ndcg = ndcg_at_k(relevance, k)

        # Precision/Recall based on KEV membership
        cve_ids_ranked = [v.cve_id for v in ranked_vulns]
        prec = precision_at_k(self.kev_cve_ids, cve_ids_ranked, k)
        rec = recall_at_k(self.kev_cve_ids, cve_ids_ranked, k)
        map_score = map_at_k(self.kev_cve_ids, cve_ids_ranked, k)

        # F1@K
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0

        metrics = {
            f"NDCG@{k}": round(ndcg, 4),
            f"Precision@{k}": round(prec, 4),
            f"Recall@{k}": round(rec, 4),
            f"F1@{k}": round(f1, 4),
            f"MAP@{k}": round(map_score, 4),
            "total_vulns": len(ranked_vulns),
            "kev_vulns_in_dataset": len(
                [v for v in ranked_vulns if v.cve_id in self.kev_cve_ids]
            ),
        }

        logger.info(
            f"[green]📈 Ranking Evaluation (k={k}):[/green] "
            f"NDCG={ndcg:.4f} P={prec:.4f} R={rec:.4f} F1={f1:.4f}"
        )
        return metrics

    def compare_rankings(
        self,
        cvss_ranked: list[EnrichedVulnerability],
        composite_ranked: list[EnrichedVulnerability],
        k: int = 10,
    ) -> dict[str, dict[str, float]]:
        """
        Compare CVSS-only ranking vs. composite ranking.

        Returns:
            Dict with 'cvss_only' and 'composite' metric sets.
        """
        cvss_metrics = self.evaluate_ranking(cvss_ranked, k)
        composite_metrics = self.evaluate_ranking(composite_ranked, k)

        # Calculate improvement
        improvements: dict[str, float] = {}
        for key in [f"NDCG@{k}", f"Precision@{k}", f"Recall@{k}", f"F1@{k}", f"MAP@{k}"]:
            cvss_val = cvss_metrics.get(key, 0.0)
            comp_val = composite_metrics.get(key, 0.0)
            if isinstance(cvss_val, (int, float)) and isinstance(comp_val, (int, float)):
                diff = comp_val - cvss_val
                improvements[f"{key}_improvement"] = round(diff, 4)

        return {
            "cvss_only": cvss_metrics,
            "composite": composite_metrics,
            "improvements": improvements,
        }
