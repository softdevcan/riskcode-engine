"""Tests for package.json parser."""

import json
from pathlib import Path

import pytest

from riskcodeai.parsers.package_json import parse
from riskcode_shared.types.enums import Ecosystem


class TestPackageJsonParser:
    """Test suite for npm package.json parsing."""

    def test_parse_dependencies(self, package_json_path: str):
        """Test that production dependencies are correctly parsed."""
        graph = parse(package_json_path)

        assert graph.ecosystem == Ecosystem.NPM
        assert len(graph.direct_dependencies) > 0

        # Check specific dependencies
        express = graph.get_dependency("express")
        assert express is not None
        assert express.version_constraint.raw == "^4.18.2"
        assert express.version_constraint.operator == "^"
        assert express.is_direct is True
        assert express.is_dev is False

    def test_parse_dev_dependencies(self, package_json_path: str):
        """Test that devDependencies are parsed with is_dev=True."""
        graph = parse(package_json_path)

        jest = graph.get_dependency("jest")
        assert jest is not None
        assert jest.is_dev is True
        assert jest.version_constraint.raw == "^29.7.0"

        eslint = graph.get_dependency("eslint")
        assert eslint is not None
        assert eslint.is_dev is True

    def test_parse_peer_dependencies(self, package_json_path: str):
        """Test that peerDependencies are parsed with scope='peer'."""
        graph = parse(package_json_path)

        react = graph.get_dependency("react")
        assert react is not None
        assert react.scope == "peer"
        assert react.is_dev is False

    def test_version_constraints(self, package_json_path: str):
        """Test various version constraint formats."""
        graph = parse(package_json_path)

        # Caret
        express = graph.get_dependency("express")
        assert express.version_constraint.operator == "^"
        assert express.version_constraint.version == "4.18.2"

        # Tilde
        lodash = graph.get_dependency("lodash")
        assert lodash.version_constraint.operator == "~"
        assert lodash.version_constraint.version == "4.17.21"

        # Greater-than-or-equal
        axios = graph.get_dependency("axios")
        assert axios.version_constraint.operator == ">="
        assert axios.version_constraint.version == "1.0.0"

        # Exact version
        uuid = graph.get_dependency("uuid")
        assert uuid.version_constraint.operator == "=="
        assert uuid.version_constraint.version == "9.0.0"

        # Wildcard
        dotenv = graph.get_dependency("dotenv")
        assert dotenv.version_constraint.operator == "*"

    def test_dependency_counts(self, package_json_path: str):
        """Test total dependency counts."""
        graph = parse(package_json_path)
        summary = graph.to_summary()

        # 5 deps + 3 devDeps + 1 peerDep = 9
        assert summary["total_dependencies"] == 9
        assert summary["direct"] == 9  # All are direct in package.json
        assert summary["dev"] == 3
        assert summary["production"] == 6

    def test_file_not_found(self):
        """Test that FileNotFoundError is raised for missing files."""
        with pytest.raises(FileNotFoundError):
            parse("/nonexistent/package.json")

    def test_invalid_json(self, tmp_path: Path):
        """Test that JSONDecodeError is raised for invalid JSON."""
        bad_file = tmp_path / "package.json"
        bad_file.write_text("not valid json {{{")

        with pytest.raises(json.JSONDecodeError):
            parse(str(bad_file))

    def test_empty_package_json(self, tmp_path: Path):
        """Test parsing a minimal package.json with no dependencies."""
        minimal = tmp_path / "package.json"
        minimal.write_text('{"name": "empty", "version": "1.0.0"}')

        graph = parse(str(minimal))
        assert len(graph.dependencies) == 0
        assert graph.ecosystem == Ecosystem.NPM

    def test_manifest_path_is_absolute(self, package_json_path: str):
        """Test that manifest_path in the result is absolute."""
        graph = parse(package_json_path)
        assert Path(graph.manifest_path).is_absolute()
