"""Parser for requirements.txt (Python/pip ecosystem)."""

from __future__ import annotations

import re
from pathlib import Path

from riskcode_shared.types.enums import Ecosystem
from riskcode_shared.types.models import Dependency, DependencyGraph, VersionConstraint

# Regex for parsing requirement lines
# Matches: package_name[extras] operator version [; markers] [# comment]
_REQUIREMENT_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)"
    r"(?:\[(?P<extras>[^\]]*)\])?"
    r"\s*(?P<constraints>[^;#]*?)?"
    r"\s*(?:;.*)?$"
)

# Version constraint operators
_CONSTRAINT_RE = re.compile(
    r"(?P<op>~=|==|!=|<=|>=|<|>|===)\s*(?P<version>[^\s,]+)"
)


def parse(file_path: str) -> DependencyGraph:
    """Parse a requirements.txt file into a DependencyGraph.

    Supports:
    - Pinned versions: package==1.2.3
    - Range constraints: package>=1.0,<2.0
    - Comments and blank lines
    - -r (recursive includes)
    - Environment markers (ignored)

    Args:
        file_path: Path to the requirements.txt file.

    Returns:
        DependencyGraph with all dependencies found.

    Raises:
        FileNotFoundError: If the file does not exist.
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Manifest file not found: {file_path}")

    dependencies = _parse_file(path, set())

    return DependencyGraph(
        dependencies=dependencies,
        ecosystem=Ecosystem.PYPI,
        manifest_path=str(path.resolve()),
    )


def _parse_file(path: Path, visited: set[str]) -> list[Dependency]:
    """Parse a single requirements file, handling -r includes recursively."""
    resolved = str(path.resolve())
    if resolved in visited:
        return []  # Prevent circular includes
    visited.add(resolved)

    content = path.read_text(encoding="utf-8")
    dependencies: list[Dependency] = []

    for line in content.splitlines():
        line = line.strip()

        # Skip empty lines and comments
        if not line or line.startswith("#"):
            continue

        # Handle -r / --requirement includes
        if line.startswith(("-r ", "--requirement ")):
            include_path = line.split(maxsplit=1)[1].strip()
            include_full = path.parent / include_path
            if include_full.exists():
                dependencies.extend(_parse_file(include_full, visited))
            continue

        # Skip option lines (-e, -f, --index-url, etc.)
        if line.startswith("-"):
            continue

        # Parse requirement line
        dep = _parse_requirement_line(line)
        if dep is not None:
            dependencies.append(dep)

    return dependencies


def _parse_requirement_line(line: str) -> Dependency | None:
    """Parse a single requirement line into a Dependency.
    
    Examples:
        "requests==2.31.0"
        "flask>=2.0,<3.0"
        "numpy"
        "django[argon2]>=4.0  # latest LTS"
    """
    # Strip inline comments
    if " #" in line:
        line = line[: line.index(" #")].strip()

    match = _REQUIREMENT_RE.match(line)
    if not match:
        return None

    name = match.group("name")
    constraints_str = (match.group("constraints") or "").strip()

    if not constraints_str:
        # No version specified
        version_constraint = VersionConstraint(raw="*", operator="*", version="*")
    else:
        # Parse all version constraints
        constraint_matches = _CONSTRAINT_RE.findall(constraints_str)
        if constraint_matches:
            # Use the full raw string, but extract first operator/version
            first_op, first_ver = constraint_matches[0]
            version_constraint = VersionConstraint(
                raw=constraints_str.strip(),
                operator=first_op,
                version=first_ver,
            )
        else:
            version_constraint = VersionConstraint.parse_version_string(constraints_str.strip())

    return Dependency(
        name=name,
        version_constraint=version_constraint,
        is_direct=True,
        depth=0,
        ecosystem=Ecosystem.PYPI,
        is_dev=False,
    )
