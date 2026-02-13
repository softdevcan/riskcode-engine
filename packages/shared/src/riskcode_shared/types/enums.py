"""Shared enumerations for RiskCodeAI."""

from enum import Enum


class Ecosystem(str, Enum):
    """Supported package ecosystems."""

    NPM = "npm"
    PYPI = "pypi"
    GO = "go"
    MAVEN = "maven"
    RUST = "cargo"

    @classmethod
    def from_manifest(cls, filename: str) -> "Ecosystem":
        """Detect ecosystem from manifest filename."""
        from riskcode_shared.constants.constants import MANIFEST_ECOSYSTEM_MAP
        
        ecosystem = MANIFEST_ECOSYSTEM_MAP.get(filename)
        if ecosystem is None:
            raise ValueError(f"Unknown manifest file: {filename}")
        return ecosystem


class Severity(str, Enum):
    """Vulnerability severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @classmethod
    def from_score(cls, score: float) -> "Severity":
        """Determine severity from a risk score (0-10 scale)."""
        if score >= 8.0:
            return cls.CRITICAL
        elif score >= 6.0:
            return cls.HIGH
        elif score >= 4.0:
            return cls.MEDIUM
        else:
            return cls.LOW


class ReachabilityStatus(str, Enum):
    """Reachability analysis result statuses."""

    REACHABLE = "reachable"
    UNREACHABLE = "unreachable"
    POTENTIALLY_REACHABLE = "potentially_reachable"
    UNKNOWN = "unknown"
