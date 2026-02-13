"""Parser for package.json (npm/Node.js ecosystem)."""

from __future__ import annotations

import json
from pathlib import Path

from riskcode_shared.types.enums import Ecosystem
from riskcode_shared.types.models import Dependency, DependencyGraph, VersionConstraint


def parse(file_path: str) -> DependencyGraph:
    """Parse a package.json file into a DependencyGraph.

    Args:
        file_path: Path to the package.json file.

    Returns:
        DependencyGraph with all dependencies found.

    Raises:
        FileNotFoundError: If the file does not exist.
        json.JSONDecodeError: If the file is not valid JSON.
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Manifest file not found: {file_path}")

    content = path.read_text(encoding="utf-8")
    data = json.loads(content)

    dependencies: list[Dependency] = []

    # Parse production dependencies
    for name, version_str in data.get("dependencies", {}).items():
        dependencies.append(
            Dependency(
                name=name,
                version_constraint=VersionConstraint.parse_version_string(version_str),
                is_direct=True,
                depth=0,
                ecosystem=Ecosystem.NPM,
                is_dev=False,
            )
        )

    # Parse devDependencies
    for name, version_str in data.get("devDependencies", {}).items():
        dependencies.append(
            Dependency(
                name=name,
                version_constraint=VersionConstraint.parse_version_string(version_str),
                is_direct=True,
                depth=0,
                ecosystem=Ecosystem.NPM,
                is_dev=True,
            )
        )

    # Parse peerDependencies (mark as non-dev, direct)
    for name, version_str in data.get("peerDependencies", {}).items():
        dependencies.append(
            Dependency(
                name=name,
                version_constraint=VersionConstraint.parse_version_string(version_str),
                is_direct=True,
                depth=0,
                ecosystem=Ecosystem.NPM,
                is_dev=False,
                scope="peer",
            )
        )

    # Try to enrich with lockfile data for transitive deps
    lock_path = path.parent / "package-lock.json"
    if lock_path.exists():
        dependencies = _enrich_from_lockfile(lock_path, dependencies)

    return DependencyGraph(
        dependencies=dependencies,
        ecosystem=Ecosystem.NPM,
        manifest_path=str(path.resolve()),
    )


def _enrich_from_lockfile(
    lock_path: Path, direct_deps: list[Dependency]
) -> list[Dependency]:
    """Enrich dependency list with transitive dependencies from package-lock.json.

    Uses lockfile v2/v3 format (packages field).
    """
    try:
        content = lock_path.read_text(encoding="utf-8")
        lock_data = json.loads(content)
    except (json.JSONDecodeError, OSError):
        return direct_deps

    direct_names = {d.name for d in direct_deps}
    all_deps = list(direct_deps)

    # lockfileVersion 2/3 uses "packages" key
    packages = lock_data.get("packages", {})
    for pkg_path, pkg_info in packages.items():
        if not pkg_path or pkg_path == "":
            continue  # Skip root package

        # Extract package name from path: "node_modules/lodash" -> "lodash"
        # Also handles scoped: "node_modules/@scope/pkg" -> "@scope/pkg"
        parts = pkg_path.split("node_modules/")
        if len(parts) < 2:
            continue
        name = parts[-1]

        if name in direct_names:
            continue  # Already in direct deps

        version = pkg_info.get("version", "")
        if not version:
            continue

        is_dev = pkg_info.get("dev", False)
        # Calculate depth based on nesting
        depth = pkg_path.count("node_modules/")

        all_deps.append(
            Dependency(
                name=name,
                version_constraint=VersionConstraint(raw=version, operator="==", version=version),
                is_direct=False,
                depth=depth,
                ecosystem=Ecosystem.NPM,
                is_dev=is_dev,
            )
        )

    return all_deps
