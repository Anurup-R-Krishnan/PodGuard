"""
Unit tests for CISA KEV catalog integration.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from epss_framework.enrichment.kev_catalog import KEVCatalog


class TestKEVCatalog:
    """Tests for KEV download, caching, and lookups."""

    @pytest.mark.asyncio
    async def test_download_parses_catalog_and_writes_cache(self, tmp_path: Path) -> None:
        catalog = KEVCatalog(cache_dir=tmp_path)
        payload = {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2024-1234",
                    "vendorProject": "Acme",
                    "product": "Widget",
                    "vulnerabilityName": "Example vuln",
                    "dateAdded": "2024-01-01",
                    "shortDescription": "desc",
                    "requiredAction": "patch",
                    "dueDate": "2024-02-01",
                    "knownRansomwareCampaignUse": "Known",
                }
            ]
        }

        response = MagicMock()
        response.raise_for_status = MagicMock()
        response.json.return_value = payload

        client = AsyncMock()
        client.get = AsyncMock(return_value=response)

        async_cm = AsyncMock()
        async_cm.__aenter__.return_value = client
        async_cm.__aexit__.return_value = None

        with patch("epss_framework.enrichment.kev_catalog.httpx.AsyncClient", return_value=async_cm):
            count = await catalog.download(force=True)

        assert count == 1
        assert catalog.is_in_kev("CVE-2024-1234")
        assert catalog.get_kev_details("CVE-2024-1234") is not None
        assert catalog.cache_file.exists()

    @pytest.mark.asyncio
    async def test_download_uses_recent_cache(self, tmp_path: Path) -> None:
        cache = tmp_path / "kev_catalog.json"
        cache.write_text(json.dumps({"catalog": {"CVE-2024-1111": {"vendor": "x"}}}))

        catalog = KEVCatalog(cache_dir=tmp_path)
        count = await catalog.download(force=False)
        assert count == 1
        assert catalog.is_in_kev("CVE-2024-1111")

    @pytest.mark.asyncio
    async def test_download_falls_back_to_cache_on_error(self, tmp_path: Path) -> None:
        cache = tmp_path / "kev_catalog.json"
        cache.write_text(json.dumps({"catalog": {"CVE-2024-2222": {"vendor": "y"}}}))
        catalog = KEVCatalog(cache_dir=tmp_path)

        async_cm = AsyncMock()
        client = AsyncMock()
        client.get = AsyncMock(side_effect=RuntimeError("network down"))
        async_cm.__aenter__.return_value = client
        async_cm.__aexit__.return_value = None

        with patch("epss_framework.enrichment.kev_catalog.httpx.AsyncClient", return_value=async_cm):
            count = await catalog.download(force=True)

        assert count == 1
        assert catalog.is_in_kev("CVE-2024-2222")

    def test_get_stats_empty_and_loaded(self, tmp_path: Path) -> None:
        catalog = KEVCatalog(cache_dir=tmp_path)
        assert catalog.get_stats() == {"loaded": False, "count": 0}

        catalog._catalog = {
            "CVE-1": {"known_ransomware": "Known"},
            "CVE-2": {"known_ransomware": "Unknown"},
        }
        catalog._loaded = True
        stats = catalog.get_stats()
        assert stats["loaded"] is True
        assert stats["total_cves"] == 2
        assert stats["ransomware_associated"] == 1
