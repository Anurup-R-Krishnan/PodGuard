"""
Unit tests for Ranking Evaluation Metrics.
"""

from __future__ import annotations

import pytest

from epss_framework.evaluation.ranking_metrics import (
    RankingEvaluator,
    average_precision,
    dcg_at_k,
    map_at_k,
    ndcg_at_k,
    precision_at_k,
    recall_at_k,
)
from epss_framework.utils.models import EnrichedVulnerability


class TestDCG:
    """Tests for Discounted Cumulative Gain."""

    def test_perfect_ranking(self):
        """DCG with perfect ranking should be positive."""
        scores = [3.0, 2.0, 1.0, 0.0]
        dcg = dcg_at_k(scores, 4)
        assert dcg > 0

    def test_empty_list(self):
        """DCG of empty list should be 0."""
        assert dcg_at_k([], 5) == 0.0

    def test_k_larger_than_list(self):
        """DCG should handle k > len(scores)."""
        scores = [3.0, 2.0]
        dcg = dcg_at_k(scores, 10)
        assert dcg > 0

    def test_all_zeros(self):
        """DCG of all-zero relevance should be 0."""
        scores = [0.0, 0.0, 0.0]
        assert dcg_at_k(scores, 3) == 0.0


class TestNDCG:
    """Tests for Normalized Discounted Cumulative Gain."""

    def test_perfect_ranking_is_one(self):
        """Perfect ranking should give NDCG = 1.0."""
        scores = [3.0, 2.0, 1.0, 0.0]
        assert abs(ndcg_at_k(scores, 4) - 1.0) < 0.001

    def test_worst_ranking_is_less_than_one(self):
        """Reversed ranking should give NDCG < 1.0."""
        scores = [0.0, 1.0, 2.0, 3.0]
        ndcg = ndcg_at_k(scores, 4)
        assert ndcg < 1.0
        assert ndcg > 0.0

    def test_empty_gives_zero(self):
        assert ndcg_at_k([], 5) == 0.0

    def test_all_irrelevant_gives_zero(self):
        scores = [0.0, 0.0, 0.0]
        assert ndcg_at_k(scores, 3) == 0.0


class TestPrecisionRecall:
    """Tests for Precision@K and Recall@K."""

    def test_precision_at_k(self):
        relevant = {"A", "B", "C"}
        ranked = ["A", "D", "B", "E", "C"]
        assert precision_at_k(relevant, ranked, 2) == 0.5  # 1 of 2
        assert precision_at_k(relevant, ranked, 3) == 2 / 3  # 2 of 3

    def test_recall_at_k(self):
        relevant = {"A", "B", "C"}
        ranked = ["A", "D", "B", "E", "C"]
        assert recall_at_k(relevant, ranked, 2) == pytest.approx(1 / 3)
        assert recall_at_k(relevant, ranked, 5) == 1.0  # all found

    def test_empty_relevant_set(self):
        assert precision_at_k(set(), ["A", "B"], 2) == 0.0
        assert recall_at_k(set(), ["A", "B"], 2) == 0.0


class TestAveragePrecision:
    """Tests for Average Precision."""

    def test_perfect_ranking(self):
        relevant = {"A", "B", "C"}
        ranked = ["A", "B", "C", "D", "E"]
        ap = average_precision(relevant, ranked)
        assert abs(ap - 1.0) < 0.001

    def test_no_relevant_items(self):
        assert average_precision(set(), ["A", "B"]) == 0.0


class TestRankingEvaluator:
    """Tests for the full evaluation pipeline."""

    def test_evaluate_with_kev_vulns(self):
        kev_ids = {"CVE-1", "CVE-3"}
        evaluator = RankingEvaluator(kev_cve_ids=kev_ids)

        vulns = [
            EnrichedVulnerability(cve_id="CVE-1", composite_score=0.9, epss_score=0.8),
            EnrichedVulnerability(cve_id="CVE-2", composite_score=0.7, epss_score=0.3),
            EnrichedVulnerability(cve_id="CVE-3", composite_score=0.5, epss_score=0.1),
            EnrichedVulnerability(cve_id="CVE-4", composite_score=0.3, epss_score=0.01),
        ]

        metrics = evaluator.evaluate_ranking(vulns, k=4)
        assert "NDCG@4" in metrics
        assert "Precision@4" in metrics
        assert metrics["kev_vulns_in_dataset"] == 2

    def test_compare_rankings(self):
        kev_ids = {"CVE-1"}
        evaluator = RankingEvaluator(kev_cve_ids=kev_ids)

        cvss_ranked = [
            EnrichedVulnerability(cve_id="CVE-2", composite_score=0.5, cvss_v3_score=9.0, epss_score=0.01),
            EnrichedVulnerability(cve_id="CVE-1", composite_score=0.9, cvss_v3_score=5.0, epss_score=0.9),
        ]
        composite_ranked = [
            EnrichedVulnerability(cve_id="CVE-1", composite_score=0.9, cvss_v3_score=5.0, epss_score=0.9),
            EnrichedVulnerability(cve_id="CVE-2", composite_score=0.5, cvss_v3_score=9.0, epss_score=0.01),
        ]

        result = evaluator.compare_rankings(cvss_ranked, composite_ranked, k=2)
        assert "cvss_only" in result
        assert "composite" in result
        assert "improvements" in result
