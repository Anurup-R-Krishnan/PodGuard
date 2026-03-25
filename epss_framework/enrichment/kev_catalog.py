"""
CISA KEV (Known Exploited Vulnerabilities) Catalog Integration.

Downloads and manages the CISA KEV catalog used as ground truth
for evaluating vulnerability prioritization accuracy.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Optional

import httpx

from epss_framework.utils.logging import get_logger

logger = get_logger()

KEV_CATALOG_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class KEVCatalog:
    """
    Interface to the CISA Known Exploited Vulnerabilities catalog.

    The KEV catalog contains CVEs that are confirmed to be actively
    exploited in the wild. It serves as ground truth for evaluating
    whether our composite scoring correctly prioritizes dangerous CVEs.

    Usage:
        kev = KEVCatalog()
        await kev.download()
        is_exploited = kev.is_in_kev("CVE-2024-1234")
    """

    def __init__(self, cache_dir: Optional[Path] = None):
        self.cache_dir = cache_dir or Path.home() / ".cache" / "epss-triage" / "kev"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._catalog: dict[str, dict] = {}
        self._loaded = False

    @property
    def cache_file(self) -> Path:
        return self.cache_dir / "kev_catalog.json"

    @property
    def cve_ids(self) -> set[str]:
        """Get all CVE IDs in the KEV catalog."""
        return set(self._catalog.keys())

    @property
    def count(self) -> int:
        """Number of CVEs in the catalog."""
        return len(self._catalog)

    async def download(self, force: bool = False) -> int:
        """
        Download the latest KEV catalog from CISA.

        Args:
            force: Force re-download even if cache exists.

        Returns:
            Number of CVEs in the catalog.
        """
        # Check cache
        if not force and self.cache_file.exists():
            age_hours = (
                datetime.now() - datetime.fromtimestamp(self.cache_file.stat().st_mtime)
            ).total_seconds() / 3600
            if age_hours < 24:
                return self._load_from_cache()

        logger.info("[blue]📥 Downloading CISA KEV catalog...[/blue]")

        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            try:
                response = await client.get(KEV_CATALOG_URL)
                response.raise_for_status()
                data = response.json()
            except Exception as e:
                logger.warning(f"Failed to download KEV catalog: {e}")
                # Try loading from cache as fallback
                if self.cache_file.exists():
                    return self._load_from_cache()
                raise

        # Parse catalog
        vulns = data.get("vulnerabilities", [])
        self._catalog = {}
        for vuln in vulns:
            cve_id = vuln.get("cveID", "")
            if cve_id:
                self._catalog[cve_id] = {
                    "vendor": vuln.get("vendorProject", ""),
                    "product": vuln.get("product", ""),
                    "vulnerability_name": vuln.get("vulnerabilityName", ""),
                    "date_added": vuln.get("dateAdded", ""),
                    "short_description": vuln.get("shortDescription", ""),
                    "required_action": vuln.get("requiredAction", ""),
                    "due_date": vuln.get("dueDate", ""),
                    "known_ransomware": vuln.get("knownRansomwareCampaignUse", ""),
                }

        # Save to cache
        with open(self.cache_file, "w") as f:
            json.dump({"downloaded_at": datetime.now().isoformat(), "catalog": self._catalog}, f)

        self._loaded = True
        logger.info(f"[green]✓ KEV catalog loaded:[/green] {self.count} known exploited CVEs")
        return self.count

    def _load_from_cache(self) -> int:
        """Load catalog from local cache file."""
        with open(self.cache_file) as f:
            data = json.load(f)
        self._catalog = data.get("catalog", {})
        self._loaded = True
        logger.info(f"[green]✓ KEV catalog loaded from cache:[/green] {self.count} CVEs")
        return self.count

    def is_in_kev(self, cve_id: str) -> bool:
        """Check if a CVE is in the KEV catalog (known exploited)."""
        return cve_id in self._catalog

    def get_kev_details(self, cve_id: str) -> Optional[dict]:
        """Get KEV details for a specific CVE."""
        return self._catalog.get(cve_id)

    def get_stats(self) -> dict:
        """Get KEV catalog statistics."""
        if not self._catalog:
            return {"loaded": False, "count": 0}

        ransomware_count = sum(
            1 for v in self._catalog.values()
            if v.get("known_ransomware", "").lower() == "known"
        )

        return {
            "loaded": self._loaded,
            "total_cves": self.count,
            "ransomware_associated": ransomware_count,
        }
