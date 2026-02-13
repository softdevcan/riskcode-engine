"""Tests for requirements.txt parser."""

from pathlib import Path

import pytest

from riskcodeai.parsers.requirements_txt import parse
from riskcode_shared.types.enums import Ecosystem


class TestRequirementsTxtParser:
    """Test suite for pip requirements.txt parsing."""

    def test_parse_pinned_version(self, requirements_txt_path: str):
        """Test parsing pinned versions (==)."""
        graph = parse(requirements_txt_path)

        requests = graph.get_dependency("requests")
        assert requests is not None
        assert requests.version_constraint.operator == "=="
        assert requests.version_constraint.version == "2.31.0"

    def test_parse_range_constraints(self, requirements_txt_path: str):
        """Test parsing range constraints (>=, <)."""
        graph = parse(requirements_txt_path)

        flask = graph.get_dependency("flask")
        assert flask is not None
        assert ">=" in flask.version_constraint.raw
        assert "<" in flask.version_constraint.raw

    def test_parse_tilde_constraint(self, requirements_txt_path: str):
        """Test parsing PEP 440 compatible release (~=)."""
        graph = parse(requirements_txt_path)

        sqlalchemy = graph.get_dependency("sqlalchemy")
        assert sqlalchemy is not None
        assert sqlalchemy.version_constraint.operator == "~="
        assert sqlalchemy.version_constraint.version == "2.0.0"

    def test_parse_no_version(self, requirements_txt_path: str):
        """Test parsing requirement with no version specified."""
        graph = parse(requirements_txt_path)

        numpy = graph.get_dependency("numpy")
        assert numpy is not None
        assert numpy.version_constraint.raw == "*"

    def test_comments_skipped(self, requirements_txt_path: str):
        """Test that comment lines are properly skipped."""
        graph = parse(requirements_txt_path)

        # Should not have any dependency with a '#' in the name
        for dep in graph.dependencies:
            assert not dep.name.startswith("#")

    def test_inline_comments(self, requirements_txt_path: str):
        """Test that inline comments don't affect parsing."""
        graph = parse(requirements_txt_path)

        django = graph.get_dependency("django")
        assert django is not None
        assert "LTS" not in django.version_constraint.raw

    def test_extras_handling(self, requirements_txt_path: str):
        """Test that packages with extras are parsed correctly."""
        graph = parse(requirements_txt_path)

        django = graph.get_dependency("django")
        assert django is not None
        # The extras [argon2] should not affect the package name
        assert django.name == "django"

    def test_not_equal_constraint(self, requirements_txt_path: str):
        """Test !=  version constraint."""
        graph = parse(requirements_txt_path)

        psycopg2 = graph.get_dependency("psycopg2-binary")
        assert psycopg2 is not None
        assert ">=" in psycopg2.version_constraint.raw

    def test_dependency_count(self, requirements_txt_path: str):
        """Test total number of parsed dependencies."""
        graph = parse(requirements_txt_path)

        # requests, flask, numpy, django, sqlalchemy, psycopg2-binary, 
        # pydantic, python-dateutil, click, rich = 10
        assert len(graph.dependencies) == 10

    def test_ecosystem_is_pypi(self, requirements_txt_path: str):
        """Test that ecosystem is correctly set to PYPI."""
        graph = parse(requirements_txt_path)
        assert graph.ecosystem == Ecosystem.PYPI

    def test_file_not_found(self):
        """Test FileNotFoundError for missing files."""
        with pytest.raises(FileNotFoundError):
            parse("/nonexistent/requirements.txt")

    def test_recursive_include(self, tmp_path: Path):
        """Test -r directive for including other requirements files."""
        # Create base requirements
        base = tmp_path / "requirements-base.txt"
        base.write_text("requests==2.31.0\n")

        # Create main requirements referencing base
        main = tmp_path / "requirements.txt"
        main.write_text(f"-r requirements-base.txt\nflask>=2.0\n")

        graph = parse(str(main))
        assert graph.get_dependency("requests") is not None
        assert graph.get_dependency("flask") is not None

    def test_all_direct(self, requirements_txt_path: str):
        """All deps in requirements.txt should be direct."""
        graph = parse(requirements_txt_path)
        for dep in graph.dependencies:
            assert dep.is_direct is True
            assert dep.depth == 0

    def test_empty_file(self, tmp_path: Path):
        """Test parsing an empty requirements.txt."""
        empty = tmp_path / "requirements.txt"
        empty.write_text("")
        
        graph = parse(str(empty))
        assert len(graph.dependencies) == 0
