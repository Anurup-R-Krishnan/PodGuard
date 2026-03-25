"""
Reachability Analysis Engine (Phase 1 - Heuristic / Phase 2 - Static Analysis).

Determines whether a vulnerable component is actually reachable at runtime.
"""

from __future__ import annotations

import json
import subprocess
from typing import Optional

from epss_framework.utils.logging import get_logger
from epss_framework.utils.models import ReachabilityResult, Vulnerability

logger = get_logger()


class ReachabilityAnalyzer:
    """
    Analyzes whether vulnerable packages are reachable at runtime.

    Phase 1: Heuristic-based (OS packages, dev packages, missing versions)
    Phase 2: Full static analysis with call-graph inspection
    """

    def __init__(self, container_id: Optional[str] = None):
        self.container_id = container_id

    def analyze_vulnerability(
        self, vuln: Vulnerability, image: Optional[str] = None
    ) -> ReachabilityResult:
        """Perform reachability analysis for a single vulnerability."""
        is_reachable = True
        reachability_score = 1.0
        method = "assumed"
        evidence: list[str] = []

        # Heuristic: no installed version → phantom package
        if not vuln.installed_version:
            is_reachable = False
            reachability_score = 0.0
            method = "heuristic"
            evidence.append("No installed version detected; package may not be present")

        # Heuristic: OS-level shared libraries are typically reachable
        os_packages = {"libc", "openssl", "libssl", "libcrypto", "glibc", "zlib", "curl", "libcurl"}
        if any(pkg in vuln.affected_package.lower() for pkg in os_packages):
            is_reachable = True
            reachability_score = 1.0
            method = "heuristic"
            evidence.append(f"System-level package '{vuln.affected_package}' is highly likely reachable")

        # Heuristic: dev-only dependencies are less likely reachable in production
        dev_indicators = ["-dev", "-dbg", "-debug", "-doc", "-test"]
        if any(ind in vuln.affected_package.lower() for ind in dev_indicators):
            is_reachable = False
            reachability_score = 0.2
            method = "heuristic"
            evidence.append(f"Package '{vuln.affected_package}' appears to be a dev-only dependency")

        return ReachabilityResult(
            cve_id=vuln.cve_id,
            package_name=vuln.affected_package,
            is_reachable=is_reachable,
            reachability_score=reachability_score,
            analysis_method=method,
            evidence=evidence,
        )

    def analyze_batch(
        self, vulnerabilities: list[Vulnerability], image: Optional[str] = None
    ) -> dict[str, ReachabilityResult]:
        """Analyze reachability for a batch of vulnerabilities."""
        results: dict[str, ReachabilityResult] = {}
        reachable_count = 0

        for vuln in vulnerabilities:
            result = self.analyze_vulnerability(vuln, image)
            results[vuln.cve_id] = result
            if result.is_reachable:
                reachable_count += 1

        logger.info(
            f"[green]✓ Reachability analysis:[/green] "
            f"{reachable_count}/{len(vulnerabilities)} packages reachable"
        )
        return results
