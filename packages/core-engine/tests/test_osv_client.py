"""Tests for OSV.dev API client (using mocked HTTP responses)."""

from unittest.mock import MagicMock, patch

import pytest

from riskcode_shared.types.enums import Ecosystem, Severity
from riskcode_shared.types.models import Dependency, VersionConstraint

from riskcodeai.osv.cache import VulnerabilityCache
from riskcodeai.osv.client import OSVClient


# ─── Sample API Responses ────────────────────────────────────────────────────

SAMPLE_OSV_RESPONSE = {
    "vulns": [
        {
            "id": "GHSA-p6mc-m468-83gw",
            "summary": "lodash Prototype Pollution",
            "aliases": ["CVE-2020-8203"],
            "severity": [{"type": "CVSS_V3", "score": "7.4"}],
            "affected": [
                {
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [
                                {"introduced": "0"},
                                {"fixed": "4.17.20"},
                            ],
                        }
                    ]
                }
            ],
            "references": [
                {"type": "ADVISORY", "url": "https://github.com/advisories/GHSA-p6mc-m468-83gw"},
            ],
            "published": "2020-07-15T00:00:00Z",
            "modified": "2023-01-01T00:00:00Z",
        },
    ]
}

SAMPLE_BATCH_RESPONSE = {
    "results": [
        {"vulns": SAMPLE_OSV_RESPONSE["vulns"]},
        {"vulns": []},
    ]
}

EMPTY_RESPONSE = {"vulns": []}


def _make_dependency(name: str, version: str, eco: Ecosystem = Ecosystem.NPM) -> Dependency:
    """Helper to create a test dependency."""
    return Dependency(
        name=name,
        version_constraint=VersionConstraint(raw=version, operator="==", version=version),
        ecosystem=eco,
    )


class TestOSVClientQuery:
    """Test single package queries."""

    @patch("riskcodeai.osv.client.httpx.Client")
    def test_query_package_success(self, mock_client_cls):
        """Successful single query returns VulnerabilityInfo."""
        mock_response = MagicMock()
        mock_response.json.return_value = SAMPLE_OSV_RESPONSE
        mock_response.raise_for_status = MagicMock()

        mock_client = MagicMock()
        mock_client.post.return_value = mock_response
        mock_client_cls.return_value = mock_client

        client = OSVClient()
        client._client = mock_client

        vulns = client.query_package("lodash", "4.17.19", Ecosystem.NPM)
        assert len(vulns) == 1
        assert vulns[0].osv_id == "GHSA-p6mc-m468-83gw"
        assert vulns[0].cve_id == "CVE-2020-8203"
        assert vulns[0].fixed_version == "4.17.20"

    @patch("riskcodeai.osv.client.httpx.Client")
    def test_query_with_cache_hit(self, mock_client_cls, tmp_path):
        """Cache hit should not make HTTP request."""
        cache = VulnerabilityCache(db_path=tmp_path / "test.db")
        cache.set("npm", "lodash", "4.17.19", SAMPLE_OSV_RESPONSE["vulns"])

        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client

        client = OSVClient(cache=cache)
        client._client = mock_client

        vulns = client.query_package("lodash", "4.17.19", Ecosystem.NPM)
        assert len(vulns) == 1
        mock_client.post.assert_not_called()

    @patch("riskcodeai.osv.client.httpx.Client")
    def test_query_no_vulnerabilities(self, mock_client_cls):
        """No vulns returns empty list."""
        mock_response = MagicMock()
        mock_response.json.return_value = EMPTY_RESPONSE
        mock_response.raise_for_status = MagicMock()

        mock_client = MagicMock()
        mock_client.post.return_value = mock_response
        mock_client_cls.return_value = mock_client

        client = OSVClient()
        client._client = mock_client

        vulns = client.query_package("safe-package", "1.0.0", Ecosystem.NPM)
        assert len(vulns) == 0

    def test_query_unsupported_ecosystem(self):
        """Unsupported ecosystem returns empty list without API call."""
        from unittest.mock import MagicMock as _MagicMock
        fake_eco = _MagicMock()
        fake_eco.value = "unsupported"
        client = OSVClient()
        vulns = client.query_package("pkg", "1.0.0", fake_eco)
        assert vulns == []


class TestOSVClientBatch:
    """Test batch queries."""

    @patch("riskcodeai.osv.client.httpx.Client")
    def test_batch_query(self, mock_client_cls):
        """Batch query processes multiple dependencies."""
        mock_response = MagicMock()
        mock_response.json.return_value = SAMPLE_BATCH_RESPONSE
        mock_response.raise_for_status = MagicMock()

        mock_client = MagicMock()
        mock_client.post.return_value = mock_response
        mock_client_cls.return_value = mock_client

        client = OSVClient()
        client._client = mock_client

        deps = [
            _make_dependency("lodash", "4.17.19"),
            _make_dependency("express", "4.18.2"),
        ]

        vulns = client.query_batch(deps)
        assert len(vulns) == 1  # Only lodash has vulns
        assert vulns[0].affected_dependency == "lodash"

    @patch("riskcodeai.osv.client.httpx.Client")
    def test_batch_with_partial_cache(self, mock_client_cls, tmp_path):
        """Batch query uses cache for known packages, queries others."""
        cache = VulnerabilityCache(db_path=tmp_path / "test.db")
        cache.set("npm", "lodash", "4.17.19", SAMPLE_OSV_RESPONSE["vulns"])

        # Only express should be queried (lodash is cached)
        single_batch_response = {"results": [{"vulns": []}]}
        mock_response = MagicMock()
        mock_response.json.return_value = single_batch_response
        mock_response.raise_for_status = MagicMock()

        mock_client = MagicMock()
        mock_client.post.return_value = mock_response
        mock_client_cls.return_value = mock_client

        client = OSVClient(cache=cache)
        client._client = mock_client

        deps = [
            _make_dependency("lodash", "4.17.19"),
            _make_dependency("express", "4.18.2"),
        ]

        vulns = client.query_batch(deps)
        assert len(vulns) == 1  # Lodash vuln from cache
        # Only one batch call (for express), not two
        assert mock_client.post.call_count == 1


class TestOSVClientParsing:
    """Test vulnerability response parsing."""

    @patch("riskcodeai.osv.client.httpx.Client")
    def test_severity_from_cvss(self, mock_client_cls):
        """CVSS score correctly maps to severity."""
        mock_response = MagicMock()
        mock_response.json.return_value = SAMPLE_OSV_RESPONSE
        mock_response.raise_for_status = MagicMock()

        mock_client = MagicMock()
        mock_client.post.return_value = mock_response
        mock_client_cls.return_value = mock_client

        client = OSVClient()
        client._client = mock_client

        vulns = client.query_package("lodash", "4.17.19", Ecosystem.NPM)
        assert vulns[0].cvss_score == 7.4
        assert vulns[0].severity == Severity.HIGH

    @patch("riskcodeai.osv.client.httpx.Client")
    def test_affected_ranges_parsed(self, mock_client_cls):
        """Affected ranges are extracted from response."""
        mock_response = MagicMock()
        mock_response.json.return_value = SAMPLE_OSV_RESPONSE
        mock_response.raise_for_status = MagicMock()

        mock_client = MagicMock()
        mock_client.post.return_value = mock_response
        mock_client_cls.return_value = mock_client

        client = OSVClient()
        client._client = mock_client

        vulns = client.query_package("lodash", "4.17.19", Ecosystem.NPM)
        assert len(vulns[0].affected_ranges) == 1
        assert vulns[0].affected_ranges[0].introduced == "0"
        assert vulns[0].affected_ranges[0].fixed == "4.17.20"

    @patch("riskcodeai.osv.client.httpx.Client")
    def test_references_parsed(self, mock_client_cls):
        """References are extracted from response."""
        mock_response = MagicMock()
        mock_response.json.return_value = SAMPLE_OSV_RESPONSE
        mock_response.raise_for_status = MagicMock()

        mock_client = MagicMock()
        mock_client.post.return_value = mock_response
        mock_client_cls.return_value = mock_client

        client = OSVClient()
        client._client = mock_client

        vulns = client.query_package("lodash", "4.17.19", Ecosystem.NPM)
        assert len(vulns[0].references) == 1
        assert "github.com/advisories" in vulns[0].references[0].url


class TestVersionExtraction:
    """Test version extraction from various constraint formats."""

    def test_extract_exact_version(self):
        """Exact version is extracted correctly."""
        client = OSVClient()
        dep = _make_dependency("pkg", "1.2.3")
        assert client._extract_version(dep) == "1.2.3"

    def test_extract_caret_version(self):
        """Caret constraint extracts base version."""
        client = OSVClient()
        dep = Dependency(
            name="pkg",
            version_constraint=VersionConstraint(raw="^1.2.3", operator="^", version="1.2.3"),
            ecosystem=Ecosystem.NPM,
        )
        assert client._extract_version(dep) == "1.2.3"

    def test_skip_wildcard_version(self):
        """Wildcard versions return None."""
        client = OSVClient()
        dep = _make_dependency("pkg", "*")
        dep.version_constraint = VersionConstraint(raw="*", operator="*", version="*")
        assert client._extract_version(dep) is None

    def test_skip_path_dependency(self):
        """Path dependencies return None."""
        client = OSVClient()
        dep = Dependency(
            name="local-pkg",
            version_constraint=VersionConstraint(raw="path:../local", version="path:../local"),
            ecosystem=Ecosystem.PYPI,
        )
        assert client._extract_version(dep) is None
