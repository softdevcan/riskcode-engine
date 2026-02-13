"""SQLite-based vulnerability cache for OSV.dev responses.

Provides offline operation and reduces API calls by caching
vulnerability query results with configurable TTL.
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any, Optional


# Default cache location
_DEFAULT_CACHE_DIR = Path.home() / ".riskcodeai"
_DEFAULT_CACHE_DB = _DEFAULT_CACHE_DIR / "cache.db"

# Default TTL: 24 hours
_DEFAULT_TTL = 86400


class VulnerabilityCache:
    """SQLite-backed cache for OSV.dev vulnerability responses.

    Stores query results keyed by (ecosystem, package, version) with
    time-based expiration. Supports offline operation when the network
    is unavailable.
    """

    def __init__(
        self,
        db_path: str | Path | None = None,
        ttl: int = _DEFAULT_TTL,
    ):
        """Initialize the cache.

        Args:
            db_path: Path to the SQLite database file. Defaults to
                     ~/.riskcodeai/cache.db
            ttl: Time-to-live for cache entries in seconds (default: 86400 = 24h).
        """
        self.db_path = Path(db_path) if db_path else _DEFAULT_CACHE_DB
        self.ttl = ttl
        self._ensure_db()

    def _ensure_db(self) -> None:
        """Create the database and table if they don't exist."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS vulnerability_cache (
                    ecosystem   TEXT NOT NULL,
                    package     TEXT NOT NULL,
                    version     TEXT NOT NULL,
                    response    TEXT NOT NULL,
                    fetched_at  REAL NOT NULL,
                    PRIMARY KEY (ecosystem, package, version)
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_cache_fetched
                ON vulnerability_cache (fetched_at)
            """)

    def _connect(self) -> sqlite3.Connection:
        """Open a connection to the SQLite database."""
        return sqlite3.connect(str(self.db_path))

    # ─── Public API ───────────────────────────────────────────────────────

    def get(
        self,
        ecosystem: str,
        package: str,
        version: str,
    ) -> Optional[list[dict[str, Any]]]:
        """Retrieve cached vulnerability data for a package.

        Returns None if the entry is missing or expired.
        """
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT response, fetched_at FROM vulnerability_cache
                WHERE ecosystem = ? AND package = ? AND version = ?
                """,
                (ecosystem.lower(), package.lower(), version),
            ).fetchone()

        if row is None:
            return None

        response_json, fetched_at = row
        if self._is_expired(fetched_at):
            return None

        return json.loads(response_json)

    def set(
        self,
        ecosystem: str,
        package: str,
        version: str,
        vulnerabilities: list[dict[str, Any]],
    ) -> None:
        """Store vulnerability data in the cache."""
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO vulnerability_cache
                    (ecosystem, package, version, response, fetched_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    ecosystem.lower(),
                    package.lower(),
                    version,
                    json.dumps(vulnerabilities, ensure_ascii=False),
                    time.time(),
                ),
            )

    def _is_expired(self, fetched_at: float) -> bool:
        """Check if a cache entry has expired."""
        return (time.time() - fetched_at) > self.ttl

    def clear(self) -> int:
        """Remove all entries from the cache.

        Returns:
            Number of entries removed.
        """
        with self._connect() as conn:
            cursor = conn.execute("SELECT COUNT(*) FROM vulnerability_cache")
            count = cursor.fetchone()[0]
            conn.execute("DELETE FROM vulnerability_cache")
        return count

    def clear_expired(self) -> int:
        """Remove only expired entries.

        Returns:
            Number of entries removed.
        """
        cutoff = time.time() - self.ttl
        with self._connect() as conn:
            cursor = conn.execute(
                "SELECT COUNT(*) FROM vulnerability_cache WHERE fetched_at < ?",
                (cutoff,),
            )
            count = cursor.fetchone()[0]
            conn.execute(
                "DELETE FROM vulnerability_cache WHERE fetched_at < ?",
                (cutoff,),
            )
        return count

    def stats(self) -> dict[str, Any]:
        """Get cache statistics."""
        with self._connect() as conn:
            total = conn.execute(
                "SELECT COUNT(*) FROM vulnerability_cache"
            ).fetchone()[0]

            cutoff = time.time() - self.ttl
            valid = conn.execute(
                "SELECT COUNT(*) FROM vulnerability_cache WHERE fetched_at >= ?",
                (cutoff,),
            ).fetchone()[0]

        return {
            "total_entries": total,
            "valid_entries": valid,
            "expired_entries": total - valid,
            "db_path": str(self.db_path),
            "ttl_seconds": self.ttl,
        }
