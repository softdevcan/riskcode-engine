"""Tests for pom.xml parser."""

from pathlib import Path

import pytest

from riskcodeai.parsers.pom_xml import parse
from riskcode_shared.types.enums import Ecosystem


class TestPomXmlParser:
    """Test suite for Maven pom.xml parsing."""

    def test_parse_dependencies(self, pom_xml_path: str):
        """Test that dependencies are correctly parsed."""
        graph = parse(pom_xml_path)
        
        assert graph.ecosystem == Ecosystem.MAVEN
        assert len(graph.dependencies) > 0

    def test_group_artifact_naming(self, pom_xml_path: str):
        """Test that dependency names use groupId:artifactId format."""
        graph = parse(pom_xml_path)

        spring = graph.get_dependency("org.springframework:spring-core")
        assert spring is not None
        assert spring.version_constraint.version == "6.1.3"

    def test_property_substitution(self, pom_xml_path: str):
        """Test ${property} variable substitution."""
        graph = parse(pom_xml_path)

        # spring-core version should be resolved from ${spring.version}
        spring = graph.get_dependency("org.springframework:spring-core")
        assert spring is not None
        assert spring.version_constraint.version == "6.1.3"
        assert "${" not in spring.version_constraint.raw

    def test_dependency_management_fallback(self, pom_xml_path: str):
        """Test that version falls back to dependencyManagement."""
        graph = parse(pom_xml_path)

        jackson = graph.get_dependency("com.fasterxml.jackson.core:jackson-databind")
        assert jackson is not None
        assert jackson.version_constraint.version == "2.16.1"

    def test_scope_detection(self, pom_xml_path: str):
        """Test that scope is correctly detected."""
        graph = parse(pom_xml_path)

        # Test scope
        junit = graph.get_dependency("junit:junit")
        assert junit is not None
        assert junit.scope == "test"
        assert junit.is_dev is True

        # Compile scope (default)
        spring = graph.get_dependency("org.springframework:spring-core")
        assert spring is not None
        assert spring.scope == "compile"
        assert spring.is_dev is False

    def test_test_dependencies_count(self, pom_xml_path: str):
        """Test dev/test dependency counting."""
        graph = parse(pom_xml_path)
        
        dev_deps = [d for d in graph.dependencies if d.is_dev]
        prod_deps = [d for d in graph.dependencies if not d.is_dev]

        assert len(dev_deps) == 2  # junit, mockito
        assert len(prod_deps) == 3  # spring-core, jackson, slf4j

    def test_total_dependency_count(self, pom_xml_path: str):
        """Test total number of parsed dependencies."""
        graph = parse(pom_xml_path)
        assert len(graph.dependencies) == 5

    def test_file_not_found(self):
        """Test FileNotFoundError for missing files."""
        with pytest.raises(FileNotFoundError):
            parse("/nonexistent/pom.xml")

    def test_empty_pom(self, tmp_path: Path):
        """Test parsing a pom.xml with no dependencies."""
        pom = tmp_path / "pom.xml"
        pom.write_text("""<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>empty</artifactId>
    <version>1.0.0</version>
</project>""")

        graph = parse(str(pom))
        assert len(graph.dependencies) == 0
        assert graph.ecosystem == Ecosystem.MAVEN

    def test_all_direct(self, pom_xml_path: str):
        """All deps in pom.xml should be direct."""
        graph = parse(pom_xml_path)
        for dep in graph.dependencies:
            assert dep.is_direct is True
