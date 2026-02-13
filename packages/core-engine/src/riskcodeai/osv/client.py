"""OSV.dev API client for vulnerability queries.

Queries the OSV.dev REST API to find known vulnerabilities
for project dependencies. Supports batch querying for efficiency
and integrates with the SQLite cache for offline operation.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime
from typing import Any, Optional

import httpx

from riskcode_shared.constants.constants import (
    OSV_API_BASE_URL,
    OSV_BATCH_ENDPOINT,
    OSV_QUERY_ENDPOINT,
)
from riskcode_shared.types.enums import Ecosystem, Severity
from riskcode_shared.types.models import (
    AffectedRange,
    Dependency,
    VulnerabilityInfo,
    VulnerabilityReference,
)

from riskcodeai.osv.cache import VulnerabilityCache

logger = logging.getLogger(__name__)

# ─── Ecosystem name mapping (our enum → OSV.dev ecosystem name) ───────────────

_ECOSYSTEM_TO_OSV: dict[Ecosystem, str] = {
    Ecosystem.NPM: "npm",
    Ecosystem.PYPI: "PyPI",
    Ecosystem.MAVEN: "Maven",
    Ecosystem.GO: "Go",
    Ecosystem.RUST: "crates.io",
}


class OSVClient:
    """Client for querying the OSV.dev vulnerability database.

    Features:
    - Single and batch queries
    - SQLite cache integration (configurable TTL)
    - Rate limiting with exponential backoff
    - Graceful error handling (network failures don't crash the scan)
    """

    def __init__(
        self,
        cache: VulnerabilityCache | None = None,
        timeout: float = 30.0,
        max_retries: int = 3,
    ):
        """Initialize the OSV client.

        Args:
            cache: Optional vulnerability cache instance.
            timeout: HTTP request timeout in seconds.
            max_retries: Maximum retry attempts for failed requests.
        """
        self.cache = cache
        self.timeout = timeout
        self.max_retries = max_retries
        self._client = httpx.Client(timeout=timeout)

    def close(self) -> None:
        """Close the HTTP client."""
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    # ─── Public API ───────────────────────────────────────────────────────

    def query_package(
        self,
        name: str,
        version: str,
        ecosystem: Ecosystem,
    ) -> list[VulnerabilityInfo]:
        """Query OSV.dev for vulnerabilities affecting a single package.

        Args:
            name: Package name.
            version: Package version string (exact version, not constraint).
            ecosystem: Package ecosystem.

        Returns:
            List of VulnerabilityInfo objects.
        """
        osv_ecosystem = _ECOSYSTEM_TO_OSV.get(ecosystem)
        if not osv_ecosystem:
            logger.warning("Unsupported ecosystem for OSV: %s", ecosystem)
            return []

        # Check cache first
        if self.cache:
            cached = self.cache.get(osv_ecosystem, name, version)
            if cached is not None:
                logger.debug("Cache hit: %s@%s (%s)", name, version, osv_ecosystem)
                return self._parse_vulnerabilities(cached, name)

        # Query OSV.dev
        payload = {
            "version": version,
            "package": {
                "name": name,
                "ecosystem": osv_ecosystem,
            },
        }

        response_data = self._request_with_retry(OSV_QUERY_ENDPOINT, payload)
        if response_data is None:
            return []

        vuln_stubs = response_data.get("vulns", [])

        # Hydrate: fetch full details for each vulnerability
        vulns_full = self._hydrate_vulns(vuln_stubs)

        # Cache the hydrated result
        if self.cache:
            self.cache.set(osv_ecosystem, name, version, vulns_full)

        return self._parse_vulnerabilities(vulns_full, name)

    def query_batch(
        self,
        dependencies: list[Dependency],
    ) -> list[VulnerabilityInfo]:
        """Query OSV.dev for vulnerabilities affecting multiple packages.

        Uses the batch endpoint for efficiency. Falls back to individual
        queries if the batch endpoint fails.

        Args:
            dependencies: List of Dependency objects to check.

        Returns:
            Combined list of VulnerabilityInfo objects for all dependencies.
        """
        all_vulns: list[VulnerabilityInfo] = []
        uncached: list[tuple[int, Dependency]] = []

        # Step 1: Check cache for each dependency
        for i, dep in enumerate(dependencies):
            osv_ecosystem = _ECOSYSTEM_TO_OSV.get(dep.ecosystem)
            if not osv_ecosystem:
                continue

            version = self._extract_version(dep)
            if not version:
                continue

            if self.cache:
                cached = self.cache.get(osv_ecosystem, dep.name, version)
                if cached is not None:
                    logger.debug("Cache hit: %s@%s", dep.name, version)
                    all_vulns.extend(self._parse_vulnerabilities(cached, dep.name))
                    continue

            uncached.append((i, dep))

        if not uncached:
            return all_vulns

        # Step 2: Batch query uncached dependencies
        queries = []
        for _, dep in uncached:
            osv_eco = _ECOSYSTEM_TO_OSV.get(dep.ecosystem, "")
            version = self._extract_version(dep)
            if version and osv_eco:
                queries.append({
                    "version": version,
                    "package": {
                        "name": dep.name,
                        "ecosystem": osv_eco,
                    },
                })

        if not queries:
            return all_vulns

        payload = {"queries": queries}
        response_data = self._request_with_retry(OSV_BATCH_ENDPOINT, payload)

        if response_data is None:
            # Fallback: query individually
            logger.warning("Batch query failed, falling back to individual queries")
            for _, dep in uncached:
                version = self._extract_version(dep)
                if version:
                    vulns = self.query_package(dep.name, version, dep.ecosystem)
                    all_vulns.extend(vulns)
            return all_vulns

        # Step 3: Process batch results — hydrate each vuln with full details
        results = response_data.get("results", [])
        for idx, result in enumerate(results):
            if idx >= len(uncached):
                break

            _, dep = uncached[idx]
            vuln_stubs = result.get("vulns", [])
            osv_eco = _ECOSYSTEM_TO_OSV.get(dep.ecosystem, "")
            version = self._extract_version(dep)

            # Hydrate: fetch full details for each vulnerability
            vulns_full = self._hydrate_vulns(vuln_stubs)

            # Cache the hydrated data
            if self.cache and version and osv_eco:
                self.cache.set(osv_eco, dep.name, version, vulns_full)

            all_vulns.extend(self._parse_vulnerabilities(vulns_full, dep.name))

        return all_vulns

    # ─── Internal Methods ─────────────────────────────────────────────────

    def _hydrate_vulns(
        self,
        vuln_stubs: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Fetch full vulnerability details from OSV.dev.

        The batch endpoint only returns {id, modified} stubs.
        This method fetches full details from /v1/vulns/{id}.
        """
        if not vuln_stubs:
            return []

        hydrated: list[dict[str, Any]] = []
        for stub in vuln_stubs:
            vuln_id = stub.get("id", "")
            if not vuln_id:
                continue

            # If stub already has full data (summary field), skip hydration
            if stub.get("summary") or stub.get("affected"):
                hydrated.append(stub)
                continue

            # Fetch full details
            url = f"{OSV_API_BASE_URL}/vulns/{vuln_id}"
            try:
                response = self._client.get(url)
                response.raise_for_status()
                full_data = response.json()
                hydrated.append(full_data)
            except (httpx.HTTPStatusError, httpx.RequestError) as e:
                logger.warning("Failed to fetch details for %s: %s", vuln_id, e)
                hydrated.append(stub)  # Fall back to stub data

        return hydrated

    def _request_with_retry(
        self,
        url: str,
        payload: dict[str, Any],
    ) -> Optional[dict[str, Any]]:
        """Make an HTTP POST request with exponential backoff retry."""
        for attempt in range(self.max_retries):
            try:
                response = self._client.post(url, json=payload)
                response.raise_for_status()
                return response.json()
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 429:
                    # Rate limited — exponential backoff
                    wait = 2 ** attempt
                    logger.warning(
                        "OSV.dev rate limited, waiting %ds (attempt %d/%d)",
                        wait, attempt + 1, self.max_retries,
                    )
                    time.sleep(wait)
                elif e.response.status_code >= 500:
                    # Server error — retry
                    wait = 2 ** attempt
                    logger.warning(
                        "OSV.dev server error %d, retrying in %ds",
                        e.response.status_code, wait,
                    )
                    time.sleep(wait)
                else:
                    logger.error("OSV.dev request failed: %s", e)
                    return None
            except httpx.RequestError as e:
                logger.error("Network error querying OSV.dev: %s", e)
                if attempt < self.max_retries - 1:
                    time.sleep(2 ** attempt)
                else:
                    return None

        return None

    def _extract_version(self, dep: Dependency) -> Optional[str]:
        """Extract a concrete version string from a dependency.

        For version constraints like ^1.2.0 or >=1.0.0, extracts the
        base version number for querying. OSV.dev needs a concrete version.
        """
        vc = dep.version_constraint
        version = vc.version or vc.raw

        # Skip wildcard/unresolved versions
        if not version or version in ("*", "latest", ""):
            return None

        # Skip path/git/url dependencies
        if version.startswith(("path:", "git:", "http:", "https:", "file:")):
            return None

        # Clean version string — remove leading operators
        cleaned = version.lstrip("^~>=<! ")
        if not cleaned:
            return None

        # For ranges like "1.0.0,<2.0.0", take the first version
        if "," in cleaned:
            cleaned = cleaned.split(",")[0].strip().lstrip(">=<! ")

        return cleaned if cleaned else None

    def _parse_vulnerabilities(
        self,
        vulns_raw: list[dict[str, Any]],
        package_name: str,
    ) -> list[VulnerabilityInfo]:
        """Parse raw OSV.dev JSON response into VulnerabilityInfo objects."""
        results: list[VulnerabilityInfo] = []

        for vuln in vulns_raw:
            osv_id = vuln.get("id", "")

            # Extract aliases (CVE IDs, GHSA IDs, etc.)
            aliases = vuln.get("aliases", [])
            cve_id = next((a for a in aliases if a.startswith("CVE-")), None)

            # ── Extract CVSS score ────────────────────────────────────
            cvss_score = 0.0

            # 1) Try severity array (CVSS_V3 vector or numeric)
            severity_data = vuln.get("severity", [])
            for sev in severity_data:
                if sev.get("type") == "CVSS_V3":
                    score_str = sev.get("score", "")
                    try:
                        cvss_score = float(score_str)
                    except (ValueError, TypeError):
                        # It's a CVSS vector string — parse it
                        cvss_score = _cvss_vector_to_score(score_str)
                    if cvss_score > 0.0:
                        break

            # 2) Fallback: database_specific.cvss
            if cvss_score == 0.0:
                db_specific = vuln.get("database_specific", {})
                if isinstance(db_specific, dict):
                    if "cvss" in db_specific:
                        cvss_data = db_specific["cvss"]
                        if isinstance(cvss_data, dict):
                            try:
                                cvss_score = float(cvss_data.get("score", 0.0))
                            except (ValueError, TypeError):
                                pass

            # 3) Fallback: database_specific.severity text
            if cvss_score == 0.0:
                db_specific = vuln.get("database_specific", {})
                if isinstance(db_specific, dict) and "severity" in db_specific:
                    sev_str = str(db_specific["severity"]).upper()
                    cvss_score = {
                        "CRITICAL": 9.5,
                        "HIGH": 7.5,
                        "MODERATE": 5.0,
                        "MEDIUM": 5.0,
                        "LOW": 2.5,
                    }.get(sev_str, 0.0)

            severity = VulnerabilityInfo.severity_from_cvss(cvss_score)

            # ── Extract affected ranges & fixed version ───────────────
            affected_ranges: list[AffectedRange] = []
            fixed_version: Optional[str] = None
            for affected in vuln.get("affected", []):
                for r in affected.get("ranges", []):
                    for event in r.get("events", []):
                        if "introduced" in event:
                            ar = AffectedRange(
                                range_type=r.get("type", "ECOSYSTEM"),
                                introduced=event["introduced"],
                            )
                            affected_ranges.append(ar)
                        if "fixed" in event:
                            if affected_ranges:
                                affected_ranges[-1].fixed = event["fixed"]
                            if fixed_version is None:
                                fixed_version = event["fixed"]

            # ── Extract references ────────────────────────────────────
            references: list[VulnerabilityReference] = []
            for ref in vuln.get("references", []):
                references.append(VulnerabilityReference(
                    url=ref.get("url", ""),
                    ref_type=ref.get("type", "WEB"),
                ))

            # Parse dates
            published = _parse_datetime(vuln.get("published"))
            modified = _parse_datetime(vuln.get("modified"))

            results.append(VulnerabilityInfo(
                osv_id=osv_id,
                cve_id=cve_id,
                aliases=aliases,
                summary=vuln.get("summary", ""),
                details=vuln.get("details"),
                cvss_score=cvss_score,
                severity=severity,
                affected_dependency=package_name,
                affected_ranges=affected_ranges,
                fixed_version=fixed_version,
                references=references,
                published=published,
                modified=modified,
            ))

        return results


def _cvss_vector_to_score(vector: str) -> float:
    """Parse a CVSS v3.x vector string into a numeric base score.

    Implements a simplified CVSS 3.1 base score calculation.
    Example: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:L" -> ~5.0

    Args:
        vector: CVSS vector string (e.g., "CVSS:3.1/AV:N/AC:L/...")

    Returns:
        Numeric base score (0.0-10.0), or 0.0 if parsing fails.
    """
    if not vector or not vector.startswith("CVSS:"):
        return 0.0

    try:
        # Parse metrics from vector string
        parts = vector.split("/")
        metrics: dict[str, str] = {}
        for part in parts[1:]:  # Skip "CVSS:3.1"
            if ":" in part:
                key, val = part.split(":", 1)
                metrics[key] = val

        # CVSS v3.1 metric weights
        av_weights = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
        ac_weights = {"L": 0.77, "H": 0.44}
        pr_weights_unchanged = {"N": 0.85, "L": 0.62, "H": 0.27}
        pr_weights_changed = {"N": 0.85, "L": 0.68, "H": 0.50}
        ui_weights = {"N": 0.85, "R": 0.62}
        cia_weights = {"H": 0.56, "L": 0.22, "N": 0.0}

        scope_changed = metrics.get("S", "U") == "C"
        pr_weights = pr_weights_changed if scope_changed else pr_weights_unchanged

        av = av_weights.get(metrics.get("AV", "N"), 0.85)
        ac = ac_weights.get(metrics.get("AC", "L"), 0.77)
        pr = pr_weights.get(metrics.get("PR", "N"), 0.85)
        ui = ui_weights.get(metrics.get("UI", "N"), 0.85)

        c = cia_weights.get(metrics.get("C", "N"), 0.0)
        i = cia_weights.get(metrics.get("I", "N"), 0.0)
        a = cia_weights.get(metrics.get("A", "N"), 0.0)

        # ISS (Impact Sub-Score)
        iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))

        if iss <= 0:
            return 0.0

        # Exploitability
        exploitability = 8.22 * av * ac * pr * ui

        # Impact
        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
        else:
            impact = 6.42 * iss

        if impact <= 0:
            return 0.0

        # Base Score
        if scope_changed:
            base = min(1.08 * (impact + exploitability), 10.0)
        else:
            base = min(impact + exploitability, 10.0)

        # Round up to 1 decimal
        return round(base * 10) / 10

    except (KeyError, ValueError, TypeError):
        return 0.0


def _parse_datetime(value: Optional[str]) -> Optional[datetime]:
    """Parse an ISO 8601 datetime string from OSV.dev."""
    if not value:
        return None
    try:
        # OSV uses RFC 3339 / ISO 8601 format
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None

