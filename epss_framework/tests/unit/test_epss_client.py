"""
Unit tests for the EPSS Client.
"""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime

from epss_framework.enrichment.epss_client import EPSSClient, EPSSAPIError
from epss_framework.utils.models import EPSSScore


class TestEPSSClient:
    """Tests for the EPSS API client."""

    @pytest.fixture
    def client(self):
        """Create an EPSS client for testing."""
        return EPSSClient()

    def test_cache_miss(self, client):
        """Test that unknown CVEs are not cached."""
        assert not client._is_cached("CVE-2024-9999")

    def test_cache_hit_after_manual_insert(self, client):
        """Test cache lookup after manual insertion."""
        score = EPSSScore(
            cve_id="CVE-2024-TEST",
            epss_score=0.5,
            percentile=0.75,
        )
        client._cache["CVE-2024-TEST"] = score
        client._cache_timestamps["CVE-2024-TEST"] = datetime.now()
        assert client._is_cached("CVE-2024-TEST")

    def test_cache_size(self, client):
        """Test cache size property."""
        assert client.cache_size == 0
        client._cache["CVE-1"] = EPSSScore(cve_id="CVE-1", epss_score=0.1)
        assert client.cache_size == 1

    @pytest.mark.asyncio
    async def test_get_scores_with_fallback(self, client):
        """Test that missing CVEs get fallback scores."""
        # Mock the HTTP client to return empty data
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": [], "model_version": "test"}
        mock_response.raise_for_status = MagicMock()

        mock_http = AsyncMock()
        mock_http.get = AsyncMock(return_value=mock_response)
        mock_http.is_closed = False
        client._http_client = mock_http

        scores = await client.get_scores(["CVE-NOT-FOUND"])
        assert "CVE-NOT-FOUND" in scores
        assert scores["CVE-NOT-FOUND"].epss_score == 0.0  # fallback
        assert scores["CVE-NOT-FOUND"].model_version == "fallback"

    @pytest.mark.asyncio
    async def test_get_scores_caches_results(self, client):
        """Test that fetched scores are cached."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "data": [
                {"cve": "CVE-2024-1111", "epss": "0.75", "percentile": "0.95"}
            ],
            "model_version": "test",
        }
        mock_response.raise_for_status = MagicMock()

        mock_http = AsyncMock()
        mock_http.get = AsyncMock(return_value=mock_response)
        mock_http.is_closed = False
        client._http_client = mock_http

        await client.get_scores(["CVE-2024-1111"])
        assert client._is_cached("CVE-2024-1111")
        assert client._cache["CVE-2024-1111"].epss_score == 0.75
