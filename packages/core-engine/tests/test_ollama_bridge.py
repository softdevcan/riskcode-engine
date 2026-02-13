"""Tests for Ollama LLM bridge (using mocked HTTP responses)."""

from unittest.mock import MagicMock, patch

import pytest

from riskcode_shared.types.enums import Severity
from riskcode_shared.types.models import VulnerabilityInfo

from riskcodeai.llm.ollama_bridge import OllamaBridge


def _make_vuln(osv_id: str, severity: Severity = Severity.HIGH, cvss: float = 7.5) -> VulnerabilityInfo:
    """Helper to create test vulnerability."""
    return VulnerabilityInfo(
        osv_id=osv_id,
        cve_id=f"CVE-2024-{osv_id[-4:]}",
        summary=f"Test vulnerability {osv_id}",
        cvss_score=cvss,
        severity=severity,
        affected_dependency="test-package",
        fixed_version="2.0.0",
    )


class TestOllamaBridgeAvailability:
    """Test Ollama health check logic."""

    @patch("riskcodeai.llm.ollama_bridge.httpx.Client")
    def test_available_with_model(self, mock_client_cls):
        """Available when Ollama is running and model exists."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "models": [
                {"name": "deepseek-coder-v2:16b-q4"},
                {"name": "llama3.2:latest"},
            ]
        }
        mock_response.raise_for_status = MagicMock()

        mock_client = MagicMock()
        mock_client.get.return_value = mock_response
        mock_client_cls.return_value = mock_client

        bridge = OllamaBridge(model="deepseek-coder-v2:16b-q4")
        bridge._client = mock_client
        assert bridge.is_available() is True

    @patch("riskcodeai.llm.ollama_bridge.httpx.Client")
    def test_unavailable_no_model(self, mock_client_cls):
        """Unavailable when model is not found."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "models": [{"name": "llama3.2:latest"}]
        }
        mock_response.raise_for_status = MagicMock()

        mock_client = MagicMock()
        mock_client.get.return_value = mock_response
        mock_client_cls.return_value = mock_client

        bridge = OllamaBridge(model="nonexistent-model")
        bridge._client = mock_client
        assert bridge.is_available() is False

    @patch("riskcodeai.llm.ollama_bridge.httpx.Client")
    def test_unavailable_connection_error(self, mock_client_cls):
        """Unavailable when Ollama server is not running."""
        import httpx
        mock_client = MagicMock()
        mock_client.get.side_effect = httpx.ConnectError("Connection refused")
        mock_client_cls.return_value = mock_client

        bridge = OllamaBridge()
        bridge._client = mock_client
        assert bridge.is_available() is False

    @patch("riskcodeai.llm.ollama_bridge.httpx.Client")
    def test_availability_cached(self, mock_client_cls):
        """Availability check result is cached."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"models": [{"name": "deepseek-coder-v2:16b-q4"}]}
        mock_response.raise_for_status = MagicMock()

        mock_client = MagicMock()
        mock_client.get.return_value = mock_response
        mock_client_cls.return_value = mock_client

        bridge = OllamaBridge()
        bridge._client = mock_client

        bridge.is_available()
        bridge.is_available()
        # Only one API call due to caching
        assert mock_client.get.call_count == 1


class TestOllamaBridgeGeneration:
    """Test text generation."""

    @patch("riskcodeai.llm.ollama_bridge.httpx.Client")
    def test_generate_success(self, mock_client_cls):
        """Successful generation returns text."""
        mock_client = MagicMock()

        # Health check response
        tags_response = MagicMock()
        tags_response.json.return_value = {"models": [{"name": "deepseek-coder-v2:16b-q4"}]}
        tags_response.raise_for_status = MagicMock()

        # Generate response
        gen_response = MagicMock()
        gen_response.json.return_value = {"response": "This is a test summary."}
        gen_response.raise_for_status = MagicMock()

        mock_client.get.return_value = tags_response
        mock_client.post.return_value = gen_response
        mock_client_cls.return_value = mock_client

        bridge = OllamaBridge()
        bridge._client = mock_client

        result = bridge.generate("Test prompt")
        assert result == "This is a test summary."

    def test_generate_when_unavailable(self):
        """Returns None when Ollama is not available."""
        bridge = OllamaBridge()
        bridge._available = False
        assert bridge.generate("Test") is None


class TestOllamaBridgeSummaries:
    """Test vulnerability summary generation."""

    @patch("riskcodeai.llm.ollama_bridge.httpx.Client")
    def test_vulnerability_summary(self, mock_client_cls):
        """Generates individual vulnerability summary."""
        mock_client = MagicMock()

        tags_response = MagicMock()
        tags_response.json.return_value = {"models": [{"name": "deepseek-coder-v2:16b-q4"}]}
        tags_response.raise_for_status = MagicMock()

        gen_response = MagicMock()
        gen_response.json.return_value = {
            "response": "This vulnerability allows remote code execution. Update to 2.0.0 immediately."
        }
        gen_response.raise_for_status = MagicMock()

        mock_client.get.return_value = tags_response
        mock_client.post.return_value = gen_response
        mock_client_cls.return_value = mock_client

        bridge = OllamaBridge()
        bridge._client = mock_client

        vuln = _make_vuln("GHSA-test-0001")
        summary = bridge.generate_vulnerability_summary(vuln)
        assert summary is not None
        assert "code execution" in summary.lower()

    def test_batch_summarize_unavailable(self):
        """Batch summarize returns empty dict when unavailable."""
        bridge = OllamaBridge()
        bridge._available = False

        vulns = [_make_vuln("GHSA-1"), _make_vuln("GHSA-2")]
        result = bridge.batch_summarize(vulns)
        assert result == {}

    @patch("riskcodeai.llm.ollama_bridge.httpx.Client")
    def test_batch_summarize_prioritizes_severity(self, mock_client_cls):
        """Batch summarize processes critical vulns first."""
        mock_client = MagicMock()

        tags_response = MagicMock()
        tags_response.json.return_value = {"models": [{"name": "deepseek-coder-v2:16b-q4"}]}
        tags_response.raise_for_status = MagicMock()

        gen_response = MagicMock()
        gen_response.json.return_value = {"response": "AI summary text"}
        gen_response.raise_for_status = MagicMock()

        mock_client.get.return_value = tags_response
        mock_client.post.return_value = gen_response
        mock_client_cls.return_value = mock_client

        bridge = OllamaBridge()
        bridge._client = mock_client

        vulns = [
            _make_vuln("GHSA-low", Severity.LOW, 2.0),
            _make_vuln("GHSA-crit", Severity.CRITICAL, 9.5),
            _make_vuln("GHSA-high", Severity.HIGH, 7.5),
        ]

        summaries = bridge.batch_summarize(vulns, max_individual=2)
        # Should only process 2 (the most severe)
        assert len(summaries) == 2
        assert "GHSA-crit" in summaries
        assert "GHSA-high" in summaries
        assert "GHSA-low" not in summaries

    def test_project_assessment_unavailable(self):
        """Project assessment returns None when unavailable."""
        bridge = OllamaBridge()
        bridge._available = False

        result = bridge.generate_project_assessment(
            [_make_vuln("GHSA-1")], total_deps=10
        )
        assert result is None

    def test_project_assessment_no_vulns(self):
        """Project assessment returns None with no vulns."""
        bridge = OllamaBridge()
        bridge._available = True

        result = bridge.generate_project_assessment([], total_deps=10)
        assert result is None
