"""Tests for go.mod parser."""

from pathlib import Path

import pytest

from riskcodeai.parsers.go_mod import parse
from riskcode_shared.types.enums import Ecosystem


class TestGoModParser:
    """Test suite for Go go.mod parsing."""

    def test_parse_require_block(self, go_mod_path: str):
        """Test parsing multi-line require blocks."""
        graph = parse(go_mod_path)
        
        assert graph.ecosystem == Ecosystem.GO
        assert len(graph.dependencies) > 0

        gin = graph.get_dependency("github.com/gin-gonic/gin")
        assert gin is not None
        assert gin.version_constraint.version == "v1.9.1"
        assert gin.is_direct is True

    def test_indirect_detection(self, go_mod_path: str):
        """Test that // indirect comments are detected."""
        graph = parse(go_mod_path)

        testify = graph.get_dependency("github.com/stretchr/testify")
        assert testify is not None
        assert testify.is_direct is False
        assert testify.depth == 1

        validator = graph.get_dependency("github.com/go-playground/validator/v10")
        assert validator is not None
        assert validator.is_direct is False

    def test_direct_dependencies(self, go_mod_path: str):
        """Test that non-indirect deps are marked as direct."""
        graph = parse(go_mod_path)

        crypto = graph.get_dependency("golang.org/x/crypto")
        assert crypto is not None
        assert crypto.is_direct is True
        assert crypto.depth == 0

    def test_replace_directive(self, go_mod_path: str):
        """Test that replace directives are applied."""
        graph = parse(go_mod_path)

        # lib/pq should be replaced by jackc/pgx
        lib_pq = graph.get_dependency("github.com/lib/pq")
        assert lib_pq is None  # Should be replaced

        pgx = graph.get_dependency("github.com/jackc/pgx/v5")
        assert pgx is not None
        assert pgx.version_constraint.version == "v5.5.0"

    def test_dependency_count(self, go_mod_path: str):
        """Test total dependency count."""
        graph = parse(go_mod_path)
        # gin, pq->pgx, testify, crypto, validator, go-toml = 6
        assert len(graph.dependencies) == 6

    def test_file_not_found(self):
        """Test FileNotFoundError for missing files."""
        with pytest.raises(FileNotFoundError):
            parse("/nonexistent/go.mod")

    def test_empty_go_mod(self, tmp_path: Path):
        """Test parsing a go.mod with only module declaration."""
        go_mod = tmp_path / "go.mod"
        go_mod.write_text("module github.com/example/test\n\ngo 1.21\n")
        
        graph = parse(str(go_mod))
        assert len(graph.dependencies) == 0
        assert graph.ecosystem == Ecosystem.GO

    def test_all_versions_pinned(self, go_mod_path: str):
        """Go dependencies should all have exact versions."""
        graph = parse(go_mod_path)
        for dep in graph.dependencies:
            assert dep.version_constraint.operator == "=="
            assert dep.version_constraint.version.startswith("v")
