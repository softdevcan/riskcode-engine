"""
RiskCode Shared — Common types, constants, and utilities for RiskCodeAI.
"""

from riskcode_shared.types.enums import Ecosystem, ReachabilityStatus, Severity
from riskcode_shared.types.models import (
    Dependency,
    DependencyGraph,
    ScanResult,
    VersionConstraint,
    VulnerabilityInfo,
)
from riskcode_shared.constants.constants import (
    CONFIG_FILE_NAME,
    DEFAULT_CONFIG,
    EXIT_SUCCESS,
    EXIT_GENERAL_ERROR,
    MANIFEST_ECOSYSTEM_MAP,
    MANIFEST_SEARCH_ORDER,
)

__version__ = "0.1.0"

__all__ = [
    # Enums
    "Ecosystem",
    "Severity",
    "ReachabilityStatus",
    # Models
    "VersionConstraint",
    "Dependency",
    "DependencyGraph",
    "ScanResult",
    "VulnerabilityInfo",
    # Constants
    "CONFIG_FILE_NAME",
    "DEFAULT_CONFIG",
    "EXIT_SUCCESS",
    "EXIT_GENERAL_ERROR",
    "MANIFEST_ECOSYSTEM_MAP",
    "MANIFEST_SEARCH_ORDER",
]
