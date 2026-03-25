"""
EPSS (Exploit Prediction Scoring System) Integration Module.

Fetches EPSS scores from the FIRST.org API and provides local caching
for high-performance lookups.
"""

from __future__ import annotations

import asyncio
import gzip
import csv
import io
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

import httpx

from epss_framework.config.settings import get_config
from epss_framework.utils.logging import get_logger
from epss_framework.utils.models import EPSSScore

logger = get_logger()


class EPSSAPIError(Exception):
    """Raised when EPSS API requests fail."""
    pass


class EPSSClient:
    """
    Client for fetching EPSS scores from the FIRST.org API.

    Supports:
    - Single and batch CVE lookups via the REST API
    - Local in-memory + file-based caching
    - Rate limiting to respect API constraints
    - Bulk CSV download for offline/fast lookups

    Usage:
        client = EPSSClient()
        scores = await client.get_scores(["CVE-2024-1234", "CVE-2024-5678"])
    """

    def __init__(self, config: Optional[object] = None):
        self.config = config or get_config().epss
        self._cache: dict[str, EPSSScore] = {}
        self._cache_timestamps: dict[str, datetime] = {}
        self._last_request_time: float = 0.0
        self._http_client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create the HTTP client."""
        if self._http_client is None or self._http_client.is_closed:
            self._http_client = httpx.AsyncClient(
                timeout=30.0,
                headers={"Accept": "application/json"},
                follow_redirects=True,
            )
        return self._http_client

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._http_client and not self._http_client.is_closed:
            await self._http_client.aclose()

    async def _rate_limit(self) -> None:
        """Enforce rate limiting between API requests."""
        min_interval = 1.0 / self.config.rate_limit_requests_per_second
        elapsed = time.time() - self._last_request_time
        if elapsed < min_interval:
            await asyncio.sleep(min_interval - elapsed)
        self._last_request_time = time.time()

    def _is_cached(self, cve_id: str) -> bool:
        """Check if a CVE has a valid cached EPSS score."""
        if cve_id not in self._cache:
            return False
        cached_at = self._cache_timestamps.get(cve_id)
        if cached_at is None:
            return False
        ttl = timedelta(hours=self.config.cache_ttl_hours)
        return datetime.now() - cached_at < ttl

    async def _fetch_batch(self, cve_ids: list[str]) -> list[EPSSScore]:
        """Fetch EPSS scores for a batch of CVE IDs from the API."""
        await self._rate_limit()

        client = await self._get_client()
        cve_param = ",".join(cve_ids)

        try:
            response = await client.get(
                self.config.api_base_url,
                params={"cve": cve_param},
            )
            response.raise_for_status()
            data = response.json()
        except httpx.HTTPStatusError as e:
            raise EPSSAPIError(
                f"EPSS API returned status {e.response.status_code}: {e.response.text}"
            ) from e
        except httpx.RequestError as e:
            raise EPSSAPIError(f"EPSS API request failed: {e}") from e
        except Exception as e:
            raise EPSSAPIError(f"Unexpected error fetching EPSS scores: {e}") from e

        scores: list[EPSSScore] = []
        for item in data.get("data", []):
            score = EPSSScore(
                cve_id=item["cve"],
                epss_score=float(item["epss"]),
                percentile=float(item.get("percentile", 0.0)),
                model_version=data.get("model_version", "unknown"),
                score_date=datetime.now(),
            )
            scores.append(score)

            # Update cache
            self._cache[score.cve_id] = score
            self._cache_timestamps[score.cve_id] = datetime.now()

        return scores

    async def get_scores(self, cve_ids: list[str]) -> dict[str, EPSSScore]:
        """
        Get EPSS scores for a list of CVE IDs.

        Uses cache for known scores and batches API requests for unknown ones.

        Args:
            cve_ids: List of CVE identifiers to look up.

        Returns:
            Dict mapping CVE ID to EPSSScore. Missing CVEs will have fallback scores.
        """
        results: dict[str, EPSSScore] = {}
        uncached: list[str] = []

        # Check cache first
        for cve_id in cve_ids:
            if self._is_cached(cve_id):
                results[cve_id] = self._cache[cve_id]
            else:
                uncached.append(cve_id)

        if uncached:
            logger.info(
                f"[blue]📡 Fetching EPSS scores:[/blue] {len(uncached)} CVEs "
                f"({len(results)} cached)"
            )

            # Batch requests
            batch_size = self.config.batch_size
            for i in range(0, len(uncached), batch_size):
                batch = uncached[i : i + batch_size]
                try:
                    batch_scores = await self._fetch_batch(batch)
                    for score in batch_scores:
                        results[score.cve_id] = score
                except EPSSAPIError as e:
                    logger.warning(f"Failed to fetch batch {i//batch_size + 1}: {e}")

            # Apply fallback scores for CVEs not found in EPSS
            for cve_id in cve_ids:
                if cve_id not in results:
                    results[cve_id] = EPSSScore(
                        cve_id=cve_id,
                        epss_score=self.config.fallback_score,
                        percentile=0.0,
                        model_version="fallback",
                        score_date=datetime.now(),
                    )

        cache_hits = len(cve_ids) - len(uncached)
        api_found = len(results) - cache_hits
        logger.info(
            f"[green]✓ EPSS scores retrieved:[/green] "
            f"{len(results)} total ({cache_hits} cached, {api_found} from API)"
        )
        return results

    async def get_single_score(self, cve_id: str) -> EPSSScore:
        """Get EPSS score for a single CVE ID."""
        scores = await self.get_scores([cve_id])
        return scores[cve_id]

    async def load_bulk_csv(self, date: Optional[str] = None) -> int:
        """
        Download and load bulk EPSS CSV data into cache.

        Args:
            date: Date string in YYYY-MM-DD format. Defaults to today.

        Returns:
            Number of scores loaded.
        """
        if date is None:
            date = datetime.now().strftime("%Y-%m-%d")

        url = self.config.bulk_csv_url_template.format(date=date)
        logger.info(f"[blue]📥 Downloading bulk EPSS data:[/blue] {date}")

        client = await self._get_client()

        try:
            response = await client.get(url)
            response.raise_for_status()
        except httpx.HTTPError as e:
            raise EPSSAPIError(f"Failed to download bulk EPSS CSV: {e}") from e

        # Decompress and parse CSV
        try:
            decompressed = gzip.decompress(response.content)
            text = decompressed.decode("utf-8")
        except Exception as e:
            raise EPSSAPIError(f"Failed to decompress EPSS CSV: {e}") from e

        count = 0
        reader = csv.DictReader(io.StringIO(text))
        for row in reader:
            # Skip comment rows
            if not row.get("cve", "").startswith("CVE"):
                continue

            score = EPSSScore(
                cve_id=row["cve"],
                epss_score=float(row["epss"]),
                percentile=float(row.get("percentile", 0.0)),
                model_version="bulk",
                score_date=datetime.strptime(date, "%Y-%m-%d"),
            )
            self._cache[score.cve_id] = score
            self._cache_timestamps[score.cve_id] = datetime.now()
            count += 1

        logger.info(f"[green]✓ Loaded {count:,} EPSS scores from bulk CSV[/green]")
        return count

    @property
    def cache_size(self) -> int:
        """Number of scores currently in cache."""
        return len(self._cache)
