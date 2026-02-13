"""Tests for analysis orchestrator (Sprint 2 integration)."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from riskcode_shared.types.enums import Ecosystem, Severity
from riskcode_shared.types.models import (
    Dependency,
    DependencyGraph,
    VersionConstraint,
    VulnerabilityInfo,
)

from riskcodeai.analysis.orchestrator import AnalysisOrchestrator
from riskcodeai.config import RiskCodeConfig


@pytest.fixture
def config():
    """Test configuration."""
    return RiskCodeConfig({
        "llm": {
            "provider": "ollama",
            "model": "deepseek-coder-v2:16b-q4",
            "base_url": "http://localhost:11434",
        },
        "osv": {
            "cache_ttl": 3600,
        },
    })


@pytest.fixture
def sample_graph(tmp_path):
    """Create a sample dependency graph."""
    return DependencyGraph(
        dependencies=[
            Dependency(
                name="lodash",
                version_constraint=VersionConstraint(raw="4.17.19", operator="==", version="4.17.19"),
                ecosystem=Ecosystem.NPM,
            ),
            Dependency(
                name="express",
                version_constraint=VersionConstraint(raw="4.18.2", operator="==", version="4.18.2"),
                ecosystem=Ecosystem.NPM,
            ),
        ],
        ecosystem=Ecosystem.NPM,
        manifest_path=str(tmp_path / "package.json"),
    )


@pytest.fixture
def sample_vulns():
    """Sample vulnerabilities."""
    return [
        VulnerabilityInfo(
            osv_id="GHSA-p6mc-m468-83gw",
            cve_id="CVE-2020-8203",
            summary="Prototype Pollution in lodash",
            cvss_score=7.4,
            severity=Severity.HIGH,
            affected_dependency="lodash",
            fixed_version="4.17.20",
        ),
    ]


class TestOrchestratorAnalyze:
    """Test the analyze workflow."""

    @patch("riskcodeai.analysis.orchestrator.parse_project")
    def test_analyze_parse_only(self, mock_parse, config, sample_graph, tmp_path):
        """Analyze with OSV and AI disabled only parses."""
        mock_parse.return_value = sample_graph

        orchestrator = AnalysisOrchestrator(config=config)
        result = orchestrator.analyze(
            directory=str(tmp_path),
            enable_osv=False,
            enable_ai=False,
        )

        assert result.dependency_graph is not None
        assert len(result.vulnerabilities) == 0
        assert result.status == "completed"

    @patch("riskcodeai.analysis.orchestrator.OllamaBridge")
    @patch("riskcodeai.analysis.orchestrator.OSVClient")
    @patch("riskcodeai.analysis.orchestrator.parse_project")
    def test_analyze_with_osv(
        self, mock_parse, mock_osv_cls, mock_ollama_cls, config, sample_graph, sample_vulns, tmp_path
    ):
        """Analyze with OSV enabled queries vulnerabilities."""
        mock_parse.return_value = sample_graph

        # Mock OSV client
        mock_osv = MagicMock()
        mock_osv.query_batch.return_value = sample_vulns
        mock_osv.__enter__ = MagicMock(return_value=mock_osv)
        mock_osv.__exit__ = MagicMock(return_value=False)
        mock_osv_cls.return_value = mock_osv

        # Mock Ollama — unavailable
        mock_ollama = MagicMock()
        mock_ollama.is_available.return_value = False
        mock_ollama.__enter__ = MagicMock(return_value=mock_ollama)
        mock_ollama.__exit__ = MagicMock(return_value=False)
        mock_ollama_cls.return_value = mock_ollama

        orchestrator = AnalysisOrchestrator(config=config)
        result = orchestrator.analyze(
            directory=str(tmp_path),
            enable_osv=True,
            enable_ai=True,
        )

        assert len(result.vulnerabilities) == 1
        assert result.vulnerabilities[0].osv_id == "GHSA-p6mc-m468-83gw"

    @patch("riskcodeai.analysis.orchestrator.parse_project")
    def test_analyze_no_manifest(self, mock_parse, config, tmp_path):
        """Analyze handles missing manifest gracefully."""
        mock_parse.side_effect = FileNotFoundError("No manifest found")

        orchestrator = AnalysisOrchestrator(config=config)
        with pytest.raises(FileNotFoundError):
            orchestrator.analyze(directory=str(tmp_path))


class TestOrchestratorReport:
    """Test report generation."""

    @patch("riskcodeai.analysis.orchestrator.parse_project")
    def test_json_report_structure(self, mock_parse, config, sample_graph, tmp_path):
        """JSON report contains expected fields."""
        mock_parse.return_value = sample_graph

        orchestrator = AnalysisOrchestrator(config=config)
        result = orchestrator.analyze(
            directory=str(tmp_path),
            enable_osv=False,
            enable_ai=False,
        )

        report_str = orchestrator.generate_report(result=result)
        report = json.loads(report_str)

        assert "scan_id" in report
        assert "dependencies" in report
        assert "vulnerabilities" in report
        assert "vulnerability_summary" in report
        assert report["vulnerability_summary"]["total"] == 0

    @patch("riskcodeai.analysis.orchestrator.parse_project")
    def test_json_report_with_vulns(self, mock_parse, config, sample_graph, tmp_path):
        """JSON report includes vulnerability data."""
        mock_parse.return_value = sample_graph

        orchestrator = AnalysisOrchestrator(config=config)
        result = orchestrator.analyze(
            directory=str(tmp_path),
            enable_osv=False,
            enable_ai=False,
        )

        # Manually add a vulnerability
        result.vulnerabilities.append(VulnerabilityInfo(
            osv_id="GHSA-test",
            cve_id="CVE-2024-1234",
            summary="Test vuln",
            cvss_score=7.5,
            severity=Severity.HIGH,
            affected_dependency="lodash",
            fixed_version="5.0.0",
        ))

        report_str = orchestrator.generate_report(result=result)
        report = json.loads(report_str)

        assert report["vulnerability_summary"]["total"] == 1
        assert report["vulnerability_summary"]["high"] == 1
        assert len(report["vulnerabilities"]) == 1
        assert report["vulnerabilities"][0]["osv_id"] == "GHSA-test"
        assert report["vulnerabilities"][0]["fixed_version"] == "5.0.0"

    @patch("riskcodeai.analysis.orchestrator.parse_project")
    def test_report_saved_to_file(self, mock_parse, config, sample_graph, tmp_path):
        """Report is saved to file when output_path provided."""
        mock_parse.return_value = sample_graph

        orchestrator = AnalysisOrchestrator(config=config)
        result = orchestrator.analyze(
            directory=str(tmp_path),
            enable_osv=False,
            enable_ai=False,
        )

        output_file = tmp_path / "report.json"
        orchestrator.generate_report(
            result=result,
            output_path=str(output_file),
        )

        assert output_file.exists()
        saved = json.loads(output_file.read_text())
        assert "scan_id" in saved
