"""Tests for CLI commands."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from riskcodeai.cli.entry import app

runner = CliRunner()


class TestScanCommand:
    """Test suite for the 'scan' CLI command."""

    def test_scan_with_fixture(self, tmp_project: Path):
        """Test scan command with a temporary project."""
        result = runner.invoke(app, ["scan", str(tmp_project), "--format", "json"])
        assert result.exit_code == 0
        assert "express" in result.stdout

    def test_scan_nonexistent_directory(self):
        """Test scan with nonexistent directory."""
        result = runner.invoke(app, ["scan", "/nonexistent/path"])
        assert result.exit_code != 0

    def test_scan_no_manifest(self, tmp_path: Path):
        """Test scan in directory with no manifest file."""
        result = runner.invoke(app, ["scan", str(tmp_path)])
        assert result.exit_code != 0

    def test_scan_with_output_file(self, tmp_project: Path, tmp_path: Path):
        """Test scan with --output flag."""
        output_file = tmp_path / "report.json"
        result = runner.invoke(
            app,
            ["scan", str(tmp_project), "--output", str(output_file)],
        )
        assert result.exit_code == 0
        assert output_file.exists()

        # Verify the output is valid JSON
        report = json.loads(output_file.read_text())
        assert "dependencies" in report
        assert "summary" in report

    def test_scan_specific_manifest(self, tmp_project: Path):
        """Test scan with --manifest option."""
        result = runner.invoke(
            app,
            ["scan", str(tmp_project), "--manifest", "package.json"],
        )
        assert result.exit_code == 0


class TestConfigCommand:
    """Test suite for the 'config' CLI command."""

    def test_config_init(self, tmp_path: Path):
        """Test config init creates .riskcodeai.yaml."""
        result = runner.invoke(app, ["config", "init", str(tmp_path)])
        assert result.exit_code == 0

        config_file = tmp_path / ".riskcodeai.yaml"
        assert config_file.exists()

    def test_config_show(self, tmp_path: Path):
        """Test config show displays configuration."""
        # First create a config
        runner.invoke(app, ["config", "init", str(tmp_path)])

        result = runner.invoke(app, ["config", "show", str(tmp_path)])
        assert result.exit_code == 0
        assert "llm" in result.stdout
        assert "ollama" in result.stdout

    def test_config_set(self, tmp_path: Path):
        """Test config set updates a value."""
        # First create a config
        runner.invoke(app, ["config", "init", str(tmp_path)])

        result = runner.invoke(
            app,
            ["config", "set", "llm.model", "llama3.2", "--dir", str(tmp_path)],
        )
        assert result.exit_code == 0
        assert "llama3.2" in result.stdout


class TestHelpOutput:
    """Test that help output works correctly."""

    def test_main_help(self):
        """Test main --help."""
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "RiskCodeAI" in result.stdout

    def test_scan_help(self):
        """Test scan --help."""
        result = runner.invoke(app, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--manifest" in result.stdout
        assert "--format" in result.stdout
