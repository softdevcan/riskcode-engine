"""Parser for pyproject.toml (Python/pip ecosystem — Poetry & PEP 621)."""

from __future__ import annotations

import re
from pathlib import Path

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore[no-redef]

from riskcode_shared.types.enums import Ecosystem
from riskcode_shared.types.models import Dependency, DependencyGraph, VersionConstraint

# PEP 508 version specifier regex (simplified)
_VERSION_RE = re.compile(
    r"(?P<op>~=|==|!=|<=|>=|<|>|===)\s*(?P<version>[^\s,;]+)"
)


def parse(file_path: str) -> DependencyGraph:
    """Parse a pyproject.toml file into a DependencyGraph.

    Supports:
    - PEP 621 [project.dependencies] and [project.optional-dependencies]
    - Poetry [tool.poetry.dependencies] and [tool.poetry.group.*.dependencies]

    Args:
        file_path: Path to the pyproject.toml file.

    Returns:
        DependencyGraph with all dependencies found.

    Raises:
        FileNotFoundError: If the file does not exist.
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Manifest file not found: {file_path}")

    content = path.read_bytes()
    data = tomllib.loads(content.decode("utf-8"))

    dependencies: list[Dependency] = []

    # Try Poetry format first
    poetry_deps = _parse_poetry(data)
    if poetry_deps:
        dependencies.extend(poetry_deps)
    else:
        # Fall back to PEP 621 format
        pep621_deps = _parse_pep621(data)
        dependencies.extend(pep621_deps)

    return DependencyGraph(
        dependencies=dependencies,
        ecosystem=Ecosystem.PYPI,
        manifest_path=str(path.resolve()),
    )


def _parse_poetry(data: dict) -> list[Dependency]:
    """Parse Poetry-format dependencies from [tool.poetry.dependencies]."""
    poetry = data.get("tool", {}).get("poetry", {})
    if not poetry:
        return []

    dependencies: list[Dependency] = []

    # Main dependencies
    main_deps = poetry.get("dependencies", {})
    for name, spec in main_deps.items():
        if name.lower() == "python":
            continue  # Skip python version constraint

        version_str = _extract_poetry_version(spec)
        dependencies.append(
            Dependency(
                name=name,
                version_constraint=VersionConstraint.parse_version_string(version_str),
                is_direct=True,
                depth=0,
                ecosystem=Ecosystem.PYPI,
                is_dev=False,
            )
        )

    # Dev dependencies (Poetry v1 style)
    dev_deps = poetry.get("dev-dependencies", {})
    for name, spec in dev_deps.items():
        version_str = _extract_poetry_version(spec)
        dependencies.append(
            Dependency(
                name=name,
                version_constraint=VersionConstraint.parse_version_string(version_str),
                is_direct=True,
                depth=0,
                ecosystem=Ecosystem.PYPI,
                is_dev=True,
            )
        )

    # Group dependencies (Poetry v2 style: [tool.poetry.group.dev.dependencies])
    groups = poetry.get("group", {})
    for group_name, group_data in groups.items():
        is_dev = group_name in ("dev", "test", "lint", "docs")
        group_deps = group_data.get("dependencies", {})
        for name, spec in group_deps.items():
            version_str = _extract_poetry_version(spec)
            dependencies.append(
                Dependency(
                    name=name,
                    version_constraint=VersionConstraint.parse_version_string(version_str),
                    is_direct=True,
                    depth=0,
                    ecosystem=Ecosystem.PYPI,
                    is_dev=is_dev,
                    scope=group_name,
                )
            )

    return dependencies


def _extract_poetry_version(spec) -> str:
    """Extract version string from Poetry dependency specification.

    Handles both simple ("^1.0") and table ({version = "^1.0", extras = [...]}) formats.
    Also handles path dependencies ({path = "../shared"}).
    """
    if isinstance(spec, str):
        return spec
    elif isinstance(spec, dict):
        if "version" in spec:
            return spec["version"]
        elif "path" in spec:
            return f"path:{spec['path']}"
        elif "git" in spec:
            return f"git:{spec['git']}"
        else:
            return "*"
    else:
        return str(spec)


def _parse_pep621(data: dict) -> list[Dependency]:
    """Parse PEP 621 format dependencies from [project.dependencies]."""
    project = data.get("project", {})
    if not project:
        return []

    dependencies: list[Dependency] = []

    # [project.dependencies]
    for dep_str in project.get("dependencies", []):
        dep = _parse_pep508(dep_str, is_dev=False)
        if dep:
            dependencies.append(dep)

    # [project.optional-dependencies]
    optional = project.get("optional-dependencies", {})
    for group_name, group_deps in optional.items():
        is_dev = group_name in ("dev", "test", "lint", "docs")
        for dep_str in group_deps:
            dep = _parse_pep508(dep_str, is_dev=is_dev)
            if dep:
                dep.scope = group_name
                dependencies.append(dep)

    return dependencies


def _parse_pep508(dep_str: str, is_dev: bool = False) -> Dependency | None:
    """Parse a PEP 508 dependency string.

    Examples: "requests>=2.28", "flask[async]>=2.0,<3.0", "numpy"
    """
    dep_str = dep_str.strip()
    if not dep_str:
        return None

    # Strip environment markers (everything after ;)
    if ";" in dep_str:
        dep_str = dep_str[:dep_str.index(";")].strip()

    # Extract name (before any version specifiers or extras)
    match = re.match(r"^([A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)", dep_str)
    if not match:
        return None

    name = match.group(1)
    rest = dep_str[match.end():].strip()

    # Strip extras: [async,security]
    if rest.startswith("["):
        bracket_end = rest.index("]") + 1 if "]" in rest else len(rest)
        rest = rest[bracket_end:].strip()

    # Parse version constraints
    if not rest:
        version_constraint = VersionConstraint(raw="*", operator="*", version="*")
    else:
        constraint_matches = _VERSION_RE.findall(rest)
        if constraint_matches:
            first_op, first_ver = constraint_matches[0]
            version_constraint = VersionConstraint(
                raw=rest.strip(),
                operator=first_op,
                version=first_ver,
            )
        else:
            version_constraint = VersionConstraint.parse_version_string(rest.strip())

    return Dependency(
        name=name,
        version_constraint=version_constraint,
        is_direct=True,
        depth=0,
        ecosystem=Ecosystem.PYPI,
        is_dev=is_dev,
    )
