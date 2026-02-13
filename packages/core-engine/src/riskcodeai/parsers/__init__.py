"""Parser registry and ecosystem detection for RiskCodeAI.

This module provides:
- ParserRegistry: automatic parser selection based on manifest filename
- detect_ecosystem(): directory scanning to determine project ecosystem
- parse_project(): one-call parsing for a project directory
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable

from riskcode_shared.types.enums import Ecosystem
from riskcode_shared.types.models import DependencyGraph
from riskcode_shared.constants.constants import (
    MANIFEST_ECOSYSTEM_MAP,
    MANIFEST_SEARCH_ORDER,
)

from riskcodeai.parsers import package_json, requirements_txt, go_mod, pom_xml

# Type alias for parser functions
ParserFunc = Callable[[str], DependencyGraph]

# ─── Parser Registry ──────────────────────────────────────────────────────────

_PARSER_MAP: dict[str, ParserFunc] = {
    "package.json": package_json.parse,
    "package-lock.json": package_json.parse,  # Falls back to package.json logic
    "requirements.txt": requirements_txt.parse,
    "go.mod": go_mod.parse,
    "pom.xml": pom_xml.parse,
}


def get_parser(manifest_filename: str) -> ParserFunc | None:
    """Get the appropriate parser function for a manifest filename.

    Args:
        manifest_filename: Name of the manifest file (e.g., 'package.json').

    Returns:
        Parser function, or None if no parser is available.
    """
    return _PARSER_MAP.get(manifest_filename)


def get_supported_manifests() -> list[str]:
    """Return list of supported manifest filenames."""
    return list(_PARSER_MAP.keys())


def detect_ecosystem(directory: str) -> tuple[Ecosystem, str] | None:
    """Detect the project ecosystem by scanning for known manifest files.

    Searches in priority order defined by MANIFEST_SEARCH_ORDER.

    Args:
        directory: Path to the project directory.

    Returns:
        Tuple of (Ecosystem, manifest_filename) or None if no manifest found.
    """
    dir_path = Path(directory)
    if not dir_path.is_dir():
        return None

    for manifest_name in MANIFEST_SEARCH_ORDER:
        manifest_path = dir_path / manifest_name
        if manifest_path.exists():
            ecosystem = MANIFEST_ECOSYSTEM_MAP.get(manifest_name)
            if ecosystem:
                return (ecosystem, manifest_name)

    return None


def detect_all_ecosystems(directory: str) -> list[tuple[Ecosystem, str]]:
    """Detect all ecosystems present in a directory.

    Args:
        directory: Path to the project directory.

    Returns:
        List of (Ecosystem, manifest_filename) tuples for all found manifests.
    """
    dir_path = Path(directory)
    if not dir_path.is_dir():
        return []

    results = []
    for manifest_name in MANIFEST_SEARCH_ORDER:
        manifest_path = dir_path / manifest_name
        if manifest_path.exists():
            ecosystem = MANIFEST_ECOSYSTEM_MAP.get(manifest_name)
            if ecosystem:
                results.append((ecosystem, manifest_name))

    return results


def parse_project(
    directory: str,
    manifest: str | None = None,
    ecosystem: str | None = None,
) -> DependencyGraph:
    """Parse a project directory, auto-detecting ecosystem if needed.

    Args:
        directory: Path to the project directory.
        manifest: Specific manifest filename to parse (optional).
        ecosystem: Force a specific ecosystem (optional).

    Returns:
        DependencyGraph from the parsed manifest.

    Raises:
        FileNotFoundError: If no supported manifest is found.
        ValueError: If the specified manifest has no parser.
    """
    dir_path = Path(directory)

    if manifest:
        # Use specified manifest
        manifest_path = dir_path / manifest
        if not manifest_path.exists():
            raise FileNotFoundError(
                f"Specified manifest not found: {manifest_path}"
            )
        parser = get_parser(manifest)
        if parser is None:
            raise ValueError(f"No parser available for: {manifest}")
        return parser(str(manifest_path))

    # Auto-detect
    detection = detect_ecosystem(directory)
    if detection is None:
        raise FileNotFoundError(
            f"No supported manifest file found in: {directory}\n"
            f"Supported files: {', '.join(MANIFEST_SEARCH_ORDER)}"
        )

    detected_ecosystem, manifest_name = detection
    manifest_path = dir_path / manifest_name
    parser = get_parser(manifest_name)
    if parser is None:
        raise ValueError(f"No parser available for: {manifest_name}")

    return parser(str(manifest_path))
