"""Tests for SQLite vulnerability cache."""

import json
import time
from pathlib import Path

import pytest

from riskcodeai.osv.cache import VulnerabilityCache


@pytest.fixture
def cache(tmp_path):
    """Create a temporary cache for testing."""
    db_path = tmp_path / "test_cache.db"
    return VulnerabilityCache(db_path=db_path, ttl=3600)


@pytest.fixture
def sample_vulns():
    """Sample vulnerability data."""
    return [
        {
            "id": "GHSA-test-0001",
            "summary": "Test vulnerability",
            "severity": [{"type": "CVSS_V3", "score": "7.5"}],
        },
        {
            "id": "GHSA-test-0002",
            "summary": "Another vulnerability",
        },
    ]


class TestVulnerabilityCache:
    """Test suite for SQLite vulnerability cache."""

    def test_set_and_get(self, cache, sample_vulns):
        """Cache set/get round-trip."""
        cache.set("npm", "lodash", "4.17.21", sample_vulns)
        result = cache.get("npm", "lodash", "4.17.21")
        assert result is not None
        assert len(result) == 2
        assert result[0]["id"] == "GHSA-test-0001"

    def test_get_missing_entry(self, cache):
        """Missing entries return None."""
        result = cache.get("npm", "nonexistent", "1.0.0")
        assert result is None

    def test_case_insensitive_keys(self, cache, sample_vulns):
        """Keys should be case-insensitive for ecosystem and package."""
        cache.set("NPM", "Lodash", "4.17.21", sample_vulns)
        result = cache.get("npm", "lodash", "4.17.21")
        assert result is not None

    def test_ttl_expiry(self, tmp_path, sample_vulns):
        """Expired entries should return None."""
        cache = VulnerabilityCache(db_path=tmp_path / "ttl_test.db", ttl=1)
        cache.set("npm", "lodash", "4.17.21", sample_vulns)

        # Immediately should be valid
        assert cache.get("npm", "lodash", "4.17.21") is not None

        # After TTL, should be expired
        time.sleep(1.1)
        assert cache.get("npm", "lodash", "4.17.21") is None

    def test_overwrite_existing(self, cache, sample_vulns):
        """New data overwrites existing entries."""
        cache.set("npm", "lodash", "4.17.21", sample_vulns)
        new_vulns = [{"id": "GHSA-new-0001", "summary": "New vuln"}]
        cache.set("npm", "lodash", "4.17.21", new_vulns)

        result = cache.get("npm", "lodash", "4.17.21")
        assert len(result) == 1
        assert result[0]["id"] == "GHSA-new-0001"

    def test_different_versions(self, cache, sample_vulns):
        """Different versions are stored separately."""
        cache.set("npm", "lodash", "4.17.21", sample_vulns)
        cache.set("npm", "lodash", "4.17.20", [])

        assert len(cache.get("npm", "lodash", "4.17.21")) == 2
        assert len(cache.get("npm", "lodash", "4.17.20")) == 0

    def test_clear(self, cache, sample_vulns):
        """Clear removes all entries."""
        cache.set("npm", "lodash", "4.17.21", sample_vulns)
        cache.set("pypi", "requests", "2.31.0", [])

        count = cache.clear()
        assert count == 2
        assert cache.get("npm", "lodash", "4.17.21") is None

    def test_clear_expired(self, tmp_path, sample_vulns):
        """clear_expired only removes expired entries."""
        cache = VulnerabilityCache(db_path=tmp_path / "expire_test.db", ttl=1)
        cache.set("npm", "old-package", "1.0.0", sample_vulns)
        time.sleep(1.1)
        cache.set("npm", "new-package", "2.0.0", sample_vulns)

        removed = cache.clear_expired()
        assert removed == 1
        assert cache.get("npm", "new-package", "2.0.0") is not None
        assert cache.get("npm", "old-package", "1.0.0") is None

    def test_stats(self, cache, sample_vulns):
        """Stats should report correct counts."""
        cache.set("npm", "lodash", "4.17.21", sample_vulns)
        cache.set("npm", "express", "4.18.2", [])

        stats = cache.stats()
        assert stats["total_entries"] == 2
        assert stats["valid_entries"] == 2
        assert stats["expired_entries"] == 0
        assert "test_cache.db" in stats["db_path"]

    def test_empty_vulnerabilities(self, cache):
        """Empty list is a valid cache entry (no vulns found)."""
        cache.set("npm", "safe-package", "1.0.0", [])
        result = cache.get("npm", "safe-package", "1.0.0")
        assert result == []

    def test_db_auto_created(self, tmp_path):
        """Database file is auto-created."""
        db_path = tmp_path / "subdir" / "cache.db"
        cache = VulnerabilityCache(db_path=db_path)
        cache.set("npm", "test", "1.0.0", [])
        assert db_path.exists()
