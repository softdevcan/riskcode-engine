"""Parser for pom.xml (Maven/Java ecosystem)."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path

from riskcode_shared.types.enums import Ecosystem
from riskcode_shared.types.models import Dependency, DependencyGraph, VersionConstraint

# Maven POM namespace
_MAVEN_NS = "{http://maven.apache.org/POM/4.0.0}"

# Property placeholder pattern: ${property.name}
_PROPERTY_RE = re.compile(r"\$\{([^}]+)\}")


def parse(file_path: str) -> DependencyGraph:
    """Parse a pom.xml file into a DependencyGraph.

    Supports:
    - <dependencies> section
    - <dependencyManagement> section
    - <properties> variable substitution (${version.name})
    - groupId:artifactId naming format
    - <scope> tracking (compile, test, provided, runtime, system)

    Args:
        file_path: Path to the pom.xml file.

    Returns:
        DependencyGraph with all dependencies found.

    Raises:
        FileNotFoundError: If the file does not exist.
        ET.ParseError: If the file is not valid XML.
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Manifest file not found: {file_path}")

    content = path.read_text(encoding="utf-8")
    tree = ET.ElementTree(ET.fromstring(content))
    root = tree.getroot()

    # Detect namespace
    ns = ""
    if root.tag.startswith("{"):
        ns = root.tag[: root.tag.index("}") + 1]

    # Extract properties for variable substitution
    properties = _extract_properties(root, ns)

    # Parse dependencies from <dependencies> section
    dependencies: list[Dependency] = []
    managed_versions: dict[str, str] = {}

    # First, parse <dependencyManagement> for version defaults
    dep_mgmt = root.find(f"{ns}dependencyManagement")
    if dep_mgmt is not None:
        deps_elem = dep_mgmt.find(f"{ns}dependencies")
        if deps_elem is not None:
            for dep_elem in deps_elem.findall(f"{ns}dependency"):
                dep_info = _parse_dependency_element(dep_elem, ns, properties)
                if dep_info:
                    key = f"{dep_info['group_id']}:{dep_info['artifact_id']}"
                    managed_versions[key] = dep_info["version"]

    # Then parse <dependencies> section
    deps_section = root.find(f"{ns}dependencies")
    if deps_section is not None:
        for dep_elem in deps_section.findall(f"{ns}dependency"):
            dep_info = _parse_dependency_element(dep_elem, ns, properties)
            if dep_info is None:
                continue

            name = f"{dep_info['group_id']}:{dep_info['artifact_id']}"
            version = dep_info["version"]
            scope = dep_info["scope"]

            # Fall back to managed version if not specified
            if not version and name in managed_versions:
                version = managed_versions[name]

            if not version:
                version = "UNKNOWN"

            is_dev = scope in ("test", "provided")

            dependencies.append(
                Dependency(
                    name=name,
                    version_constraint=VersionConstraint.parse_version_string(version),
                    is_direct=True,
                    depth=0,
                    ecosystem=Ecosystem.MAVEN,
                    is_dev=is_dev,
                    scope=scope,
                )
            )

    return DependencyGraph(
        dependencies=dependencies,
        ecosystem=Ecosystem.MAVEN,
        manifest_path=str(path.resolve()),
    )


def _extract_properties(root: ET.Element, ns: str) -> dict[str, str]:
    """Extract Maven properties for variable substitution."""
    properties: dict[str, str] = {}
    props_elem = root.find(f"{ns}properties")
    if props_elem is not None:
        for prop in props_elem:
            # Remove namespace from tag
            tag = prop.tag.replace(ns, "")
            if prop.text:
                properties[tag] = prop.text.strip()

    # Also extract project-level properties
    for field in ("groupId", "artifactId", "version", "name"):
        elem = root.find(f"{ns}{field}")
        if elem is not None and elem.text:
            properties[f"project.{field}"] = elem.text.strip()

    return properties


def _resolve_properties(value: str, properties: dict[str, str]) -> str:
    """Resolve ${property.name} placeholders using extracted properties."""
    if not value or "${" not in value:
        return value

    def replacer(match: re.Match) -> str:
        prop_name = match.group(1)
        return properties.get(prop_name, match.group(0))

    # Resolve up to 5 levels of nesting
    for _ in range(5):
        resolved = _PROPERTY_RE.sub(replacer, value)
        if resolved == value:
            break
        value = resolved

    return value


def _parse_dependency_element(
    dep_elem: ET.Element, ns: str, properties: dict[str, str]
) -> dict[str, str] | None:
    """Parse a single <dependency> XML element."""
    group_id_elem = dep_elem.find(f"{ns}groupId")
    artifact_id_elem = dep_elem.find(f"{ns}artifactId")

    if group_id_elem is None or artifact_id_elem is None:
        return None

    group_id = _resolve_properties(group_id_elem.text or "", properties)
    artifact_id = _resolve_properties(artifact_id_elem.text or "", properties)

    version_elem = dep_elem.find(f"{ns}version")
    version = ""
    if version_elem is not None and version_elem.text:
        version = _resolve_properties(version_elem.text.strip(), properties)

    scope_elem = dep_elem.find(f"{ns}scope")
    scope = "compile"
    if scope_elem is not None and scope_elem.text:
        scope = scope_elem.text.strip().lower()

    return {
        "group_id": group_id,
        "artifact_id": artifact_id,
        "version": version,
        "scope": scope,
    }
