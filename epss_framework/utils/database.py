"""
Data storage layer with SQLite persistence for scan history.

Stores enriched scan results for:
- Historical trend analysis
- Before/after comparison
- Report generation over multiple scans
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional

from epss_framework.config.settings import get_config
from epss_framework.utils.logging import get_logger
from epss_framework.utils.models import EnrichedScanResult

logger = get_logger()

CREATE_TABLES_SQL = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    image_name TEXT NOT NULL,
    image_digest TEXT,
    scan_timestamp TEXT NOT NULL,
    enrichment_timestamp TEXT NOT NULL,
    scanner_version TEXT,
    framework_version TEXT,
    os_family TEXT,
    os_name TEXT,
    scoring_method TEXT,
    scoring_weights TEXT,
    total_vulns INTEGER,
    severity_summary TEXT,
    alert_fatigue_metrics TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    cve_id TEXT NOT NULL,
    composite_score REAL,
    composite_severity TEXT,
    cvss_v3_score REAL,
    cvss_severity TEXT,
    epss_score REAL,
    epss_percentile REAL,
    reachability_score REAL,
    reachability_method TEXT,
    affected_package TEXT,
    installed_version TEXT,
    fixed_version TEXT,
    title TEXT,
    score_explanation TEXT,
    cwe_ids TEXT,
    is_in_kev INTEGER DEFAULT 0,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

CREATE INDEX IF NOT EXISTS idx_vulns_scan_id ON vulnerabilities(scan_id);
CREATE INDEX IF NOT EXISTS idx_vulns_cve_id ON vulnerabilities(cve_id);
CREATE INDEX IF NOT EXISTS idx_vulns_composite_score ON vulnerabilities(composite_score);
CREATE INDEX IF NOT EXISTS idx_scans_image_name ON scans(image_name);
"""


class ScanDatabase:
    """
    SQLite-based storage for scan history and vulnerability data.

    Usage:
        db = ScanDatabase()
        scan_id = db.save_scan(enriched_result)
        history = db.get_scan_history("nginx:latest")
    """

    def __init__(self, db_path: Optional[str | Path] = None):
        self.db_path = Path(db_path) if db_path else get_config().pipeline.database_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        """Initialize database tables."""
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript(CREATE_TABLES_SQL)
        logger.debug(f"Database initialized at {self.db_path}")

    def save_scan(self, result: EnrichedScanResult) -> int:
        """
        Save an enriched scan result to the database.

        Returns:
            The scan_id of the saved record.
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                """
                INSERT INTO scans (
                    image_name, image_digest, scan_timestamp, enrichment_timestamp,
                    scanner_version, framework_version, os_family, os_name,
                    scoring_method, scoring_weights, total_vulns,
                    severity_summary, alert_fatigue_metrics
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result.image_name,
                    result.image_digest,
                    result.scan_timestamp.isoformat(),
                    result.enrichment_timestamp.isoformat(),
                    result.scanner_version,
                    result.framework_version,
                    result.os_family,
                    result.os_name,
                    result.scoring_method,
                    json.dumps(result.scoring_weights),
                    result.total_vulns,
                    json.dumps(result.severity_summary()),
                    json.dumps(result.alert_fatigue_reduction()),
                ),
            )
            scan_id = cursor.lastrowid

            # Save vulnerabilities
            for vuln in result.vulnerabilities:
                conn.execute(
                    """
                    INSERT INTO vulnerabilities (
                        scan_id, cve_id, composite_score, composite_severity,
                        cvss_v3_score, cvss_severity, epss_score, epss_percentile,
                        reachability_score, reachability_method,
                        affected_package, installed_version, fixed_version,
                        title, score_explanation, cwe_ids, is_in_kev
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scan_id,
                        vuln.cve_id,
                        vuln.composite_score,
                        vuln.composite_severity.value,
                        vuln.cvss_v3_score,
                        vuln.cvss_severity.value,
                        vuln.epss_score,
                        vuln.epss_percentile,
                        vuln.reachability_score,
                        vuln.reachability_method,
                        vuln.affected_package,
                        vuln.installed_version,
                        vuln.fixed_version,
                        vuln.title,
                        vuln.score_explanation,
                        json.dumps(vuln.cwe_ids),
                        int(vuln.is_in_kev),
                    ),
                )

            conn.commit()

        logger.info(
            f"[green]💾 Scan saved:[/green] ID={scan_id}, "
            f"{result.total_vulns} vulnerabilities for {result.image_name}"
        )
        return scan_id  # type: ignore

    def get_scan_history(
        self, image_name: str, limit: int = 10
    ) -> list[dict]:
        """Get scan history for an image."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                """
                SELECT id, image_name, scan_timestamp, total_vulns,
                       severity_summary, alert_fatigue_metrics, scoring_method
                FROM scans
                WHERE image_name = ?
                ORDER BY scan_timestamp DESC
                LIMIT ?
                """,
                (image_name, limit),
            )
            return [dict(row) for row in cursor.fetchall()]

    def get_scan_vulnerabilities(self, scan_id: int, limit: int = 100) -> list[dict]:
        """Get vulnerabilities for a specific scan."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                """
                SELECT * FROM vulnerabilities
                WHERE scan_id = ?
                ORDER BY composite_score DESC
                LIMIT ?
                """,
                (scan_id, limit),
            )
            return [dict(row) for row in cursor.fetchall()]

    def get_cve_history(self, cve_id: str) -> list[dict]:
        """Get the scoring history of a specific CVE across all scans."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                """
                SELECT v.*, s.image_name, s.scan_timestamp
                FROM vulnerabilities v
                JOIN scans s ON v.scan_id = s.id
                WHERE v.cve_id = ?
                ORDER BY s.scan_timestamp DESC
                """,
                (cve_id,),
            )
            return [dict(row) for row in cursor.fetchall()]

    def get_stats(self) -> dict:
        """Get overall database statistics."""
        with sqlite3.connect(self.db_path) as conn:
            total_scans = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
            total_vulns = conn.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]
            unique_cves = conn.execute(
                "SELECT COUNT(DISTINCT cve_id) FROM vulnerabilities"
            ).fetchone()[0]
            unique_images = conn.execute(
                "SELECT COUNT(DISTINCT image_name) FROM scans"
            ).fetchone()[0]

        return {
            "total_scans": total_scans,
            "total_vulnerability_records": total_vulns,
            "unique_cves": unique_cves,
            "unique_images": unique_images,
        }
