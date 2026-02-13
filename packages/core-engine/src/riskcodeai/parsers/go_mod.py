"""Parser for go.mod (Go ecosystem)."""

from __future__ import annotations

import re
from pathlib import Path

from riskcode_shared.types.enums import Ecosystem
from riskcode_shared.types.models import Dependency, DependencyGraph, VersionConstraint

# Regex for single-line require: require github.com/pkg/errors v0.9.1
_SINGLE_REQUIRE_RE = re.compile(
    r"^\s*require\s+(?P<module>\S+)\s+(?P<version>\S+)"
)

# Regex for require block entries: \tgithub.com/pkg/errors v0.9.1 // indirect
_BLOCK_ENTRY_RE = re.compile(
    r"^\s*(?P<module>\S+)\s+(?P<version>\S+)(?:\s+//\s*(?P<comment>.*))?$"
)

# Regex for replace directive
_REPLACE_RE = re.compile(
    r"^\s*replace\s+(?P<old>\S+)\s+=>\s+(?P<new>\S+)\s+(?P<version>\S+)"
)


def parse(file_path: str) -> DependencyGraph:
    """Parse a go.mod file into a DependencyGraph.

    Supports:
    - Single-line require statements
    - Multi-line require blocks
    - // indirect comment detection
    - replace directives (tracked but not resolved)

    Args:
        file_path: Path to the go.mod file.

    Returns:
        DependencyGraph with all dependencies found.

    Raises:
        FileNotFoundError: If the file does not exist.
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Manifest file not found: {file_path}")

    content = path.read_text(encoding="utf-8")
    dependencies: list[Dependency] = []
    replacements: dict[str, tuple[str, str]] = {}

    lines = content.splitlines()
    in_require_block = False
    in_replace_block = False

    for line in lines:
        stripped = line.strip()

        # Handle block openings and closings
        if stripped.startswith("require ("):
            in_require_block = True
            continue
        if stripped.startswith("replace ("):
            in_replace_block = True
            continue
        if stripped == ")":
            in_require_block = False
            in_replace_block = False
            continue

        # Parse require block entries
        if in_require_block:
            match = _BLOCK_ENTRY_RE.match(stripped)
            if match:
                module = match.group("module")
                version = match.group("version")
                comment = match.group("comment") or ""
                is_indirect = "indirect" in comment.lower()

                dependencies.append(
                    Dependency(
                        name=module,
                        version_constraint=VersionConstraint(
                            raw=version, operator="==", version=version,
                        ),
                        is_direct=not is_indirect,
                        depth=0 if not is_indirect else 1,
                        ecosystem=Ecosystem.GO,
                        is_dev=False,
                    )
                )
            continue

        # Parse replace block entries
        if in_replace_block:
            match = _REPLACE_RE.match(line)
            if match:
                replacements[match.group("old")] = (
                    match.group("new"),
                    match.group("version"),
                )
            continue

        # Parse single-line require
        match = _SINGLE_REQUIRE_RE.match(stripped)
        if match:
            dependencies.append(
                Dependency(
                    name=match.group("module"),
                    version_constraint=VersionConstraint(
                        raw=match.group("version"),
                        operator="==",
                        version=match.group("version"),
                    ),
                    is_direct=True,
                    depth=0,
                    ecosystem=Ecosystem.GO,
                    is_dev=False,
                )
            )
            continue

        # Parse single-line replace
        match = _REPLACE_RE.match(stripped)
        if match:
            replacements[match.group("old")] = (
                match.group("new"),
                match.group("version"),
            )

    # Apply replacements
    for dep in dependencies:
        if dep.name in replacements:
            new_module, new_version = replacements[dep.name]
            dep.name = new_module
            dep.version_constraint = VersionConstraint(
                raw=new_version, operator="==", version=new_version,
            )

    return DependencyGraph(
        dependencies=dependencies,
        ecosystem=Ecosystem.GO,
        manifest_path=str(path.resolve()),
    )
