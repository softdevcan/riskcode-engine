"""Ollama LLM bridge for RiskCodeAI.

Provides AI-powered vulnerability summaries using locally-hosted
LLMs via the Ollama REST API. Gracefully handles Ollama being
unavailable — scans continue without AI summaries.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

import httpx

from riskcode_shared.types.models import VulnerabilityInfo
from riskcodeai.llm.prompts import (
    BATCH_VULNERABILITY_PROMPT,
    VULNERABILITY_SUMMARY_PROMPT,
)

logger = logging.getLogger(__name__)


class OllamaBridge:
    """Bridge to Ollama local LLM for AI-powered analysis.

    Connects to a locally-running Ollama instance to generate
    plain-language vulnerability summaries. If Ollama is not
    available, all methods return None gracefully.
    """

    def __init__(
        self,
        base_url: str = "http://localhost:11434",
        model: str = "deepseek-coder-v2:16b-q4",
        timeout: float = 60.0,
    ):
        """Initialize the Ollama bridge.

        Args:
            base_url: Ollama server URL.
            model: Model name to use for generation.
            timeout: Request timeout in seconds.
        """
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout
        self._client = httpx.Client(timeout=timeout)
        self._available: Optional[bool] = None

    def close(self) -> None:
        """Close the HTTP client."""
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    # ─── Health Check ─────────────────────────────────────────────────────

    def is_available(self) -> bool:
        """Check if Ollama server is running and the model is available.

        Caches the result after the first check.
        """
        if self._available is not None:
            return self._available

        try:
            response = self._client.get(
                f"{self.base_url}/api/tags",
                timeout=5.0,
            )
            response.raise_for_status()
            models = response.json().get("models", [])
            model_names = [m.get("name", "") for m in models]

            # Check if our model is available (exact match or base name match)
            base_model = self.model.split(":")[0]
            self._available = any(
                self.model in name or base_model in name
                for name in model_names
            )

            if not self._available:
                logger.warning(
                    "Ollama is running but model '%s' not found. "
                    "Available models: %s",
                    self.model,
                    ", ".join(model_names) or "(none)",
                )
            else:
                logger.info("Ollama available with model: %s", self.model)

            return self._available

        except (httpx.RequestError, httpx.HTTPStatusError) as e:
            logger.info("Ollama not available: %s", e)
            self._available = False
            return False

    # ─── Generation ───────────────────────────────────────────────────────

    def generate(self, prompt: str) -> Optional[str]:
        """Generate text using Ollama.

        Args:
            prompt: The prompt to send to the LLM.

        Returns:
            Generated text, or None if Ollama is unavailable.
        """
        if not self.is_available():
            return None

        try:
            response = self._client.post(
                f"{self.base_url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": 0.3,
                        "num_predict": 256,
                        "top_p": 0.9,
                    },
                },
            )
            response.raise_for_status()
            result = response.json()
            return result.get("response", "").strip()

        except httpx.HTTPStatusError as e:
            logger.error("Ollama generation failed: %s", e)
            return None
        except httpx.RequestError as e:
            logger.error("Ollama connection error: %s", e)
            self._available = False
            return None

    # ─── Vulnerability Summaries ──────────────────────────────────────────

    def generate_vulnerability_summary(
        self,
        vuln: VulnerabilityInfo,
    ) -> Optional[str]:
        """Generate an AI summary for a single vulnerability.

        Args:
            vuln: The vulnerability to summarize.

        Returns:
            AI-generated summary string, or None if unavailable.
        """
        prompt = VULNERABILITY_SUMMARY_PROMPT.format(
            osv_id=vuln.osv_id,
            cve_id=vuln.cve_id or "N/A",
            package_name=vuln.affected_dependency or "Unknown",
            cvss_score=vuln.cvss_score,
            summary=vuln.summary or "No summary available",
            fixed_version=vuln.fixed_version or "No fix available",
        )
        return self.generate(prompt)

    def batch_summarize(
        self,
        vulnerabilities: list[VulnerabilityInfo],
        max_individual: int = 10,
    ) -> dict[str, Optional[str]]:
        """Generate AI summaries for multiple vulnerabilities.

        Generates individual summaries for up to `max_individual`
        vulnerabilities (prioritizing by severity).

        Args:
            vulnerabilities: List of vulnerabilities to summarize.
            max_individual: Max number of individual summaries to generate.

        Returns:
            Dict mapping osv_id -> AI summary.
        """
        if not self.is_available() or not vulnerabilities:
            return {}

        # Sort by severity (critical first)
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
        sorted_vulns = sorted(
            vulnerabilities,
            key=lambda v: severity_order.get(v.severity.value.upper(), 5),
        )

        summaries: dict[str, Optional[str]] = {}
        for vuln in sorted_vulns[:max_individual]:
            summary = self.generate_vulnerability_summary(vuln)
            summaries[vuln.osv_id] = summary

        return summaries

    def generate_project_assessment(
        self,
        vulnerabilities: list[VulnerabilityInfo],
        total_deps: int,
    ) -> Optional[str]:
        """Generate an overall security assessment for the project.

        Args:
            vulnerabilities: All found vulnerabilities.
            total_deps: Total number of dependencies.

        Returns:
            AI-generated assessment string, or None if unavailable.
        """
        if not self.is_available() or not vulnerabilities:
            return None

        vuln_list_lines = []
        for v in vulnerabilities[:20]:  # Limit to keep prompt within context window
            vuln_list_lines.append(
                f"- [{v.severity.value}] {v.osv_id} in {v.affected_dependency} "
                f"(CVSS: {v.cvss_score}, fix: {v.fixed_version or 'none'})"
            )

        prompt = BATCH_VULNERABILITY_PROMPT.format(
            total_deps=total_deps,
            total_vulns=len(vulnerabilities),
            vulnerability_list="\n".join(vuln_list_lines),
        )
        return self.generate(prompt)
