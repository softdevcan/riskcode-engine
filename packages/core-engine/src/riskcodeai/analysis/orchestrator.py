"""Analysis orchestrator for RiskCodeAI.

Coordinates the complete analysis workflow:
1. Ecosystem detection
2. Manifest parsing
3. Vulnerability scanning (OSV.dev)
4. AI-powered summaries (Ollama)
5. (Future) Reachability analysis
6. (Future) Risk scoring
7. Report generation
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path

from riskcode_shared.types.models import DependencyGraph, ScanResult, VulnerabilityInfo

from riskcodeai.config import RiskCodeConfig, load_config
from riskcodeai.llm.ollama_bridge import OllamaBridge
from riskcodeai.osv.cache import VulnerabilityCache
from riskcodeai.osv.client import OSVClient
from riskcodeai.parsers import detect_ecosystem, parse_project

logger = logging.getLogger(__name__)


class AnalysisOrchestrator:
    """Orchestrates the full dependency analysis workflow.

    Sprint 1: Manifest parsing and basic reporting.
    Sprint 2: Vulnerability scanning (OSV.dev) and AI summaries (Ollama).
    """

    def __init__(self, config: RiskCodeConfig | None = None):
        self.config = config or load_config()

    def analyze(
        self,
        directory: str,
        manifest: str | None = None,
        ecosystem: str | None = None,
        enable_osv: bool = True,
        enable_ai: bool = True,
    ) -> ScanResult:
        """Run full analysis on a project directory.

        Args:
            directory: Path to the project directory.
            manifest: Specific manifest file to parse (optional).
            ecosystem: Force ecosystem detection (optional).
            enable_osv: Whether to query OSV.dev for vulnerabilities.
            enable_ai: Whether to generate AI summaries via Ollama.

        Returns:
            ScanResult with dependency graph, vulnerabilities, and AI summaries.
        """
        # Step 1: Parse dependencies
        graph = parse_project(
            directory=directory,
            manifest=manifest,
            ecosystem=ecosystem,
        )

        # Step 2: Scan for vulnerabilities (OSV.dev)
        vulnerabilities: list[VulnerabilityInfo] = []
        if enable_osv and graph:
            vulnerabilities = self._scan_vulnerabilities(graph)

        # Step 3: Generate AI summaries (Ollama)
        if enable_ai and vulnerabilities:
            self._enrich_with_ai(vulnerabilities)

        # Step 4: Create scan result
        result = ScanResult(
            project_name=Path(directory).name,
            dependency_graph=graph,
            vulnerabilities=vulnerabilities,
            scanned_at=datetime.now(),
            status="completed",
        )

        return result

    def _scan_vulnerabilities(
        self,
        graph: DependencyGraph,
    ) -> list[VulnerabilityInfo]:
        """Query OSV.dev for vulnerabilities in the dependency graph."""
        cache_ttl = self.config.get("osv.cache_ttl", 86400)
        cache = VulnerabilityCache(ttl=cache_ttl)

        try:
            with OSVClient(cache=cache) as client:
                vulns = client.query_batch(graph.dependencies)
                logger.info(
                    "OSV scan complete: %d vulnerabilities found in %d dependencies",
                    len(vulns),
                    len(graph.dependencies),
                )
                return vulns
        except Exception as e:
            logger.error("OSV.dev scan failed: %s", e)
            return []

    def _enrich_with_ai(
        self,
        vulnerabilities: list[VulnerabilityInfo],
    ) -> None:
        """Add AI-generated summaries to vulnerabilities using Ollama."""
        base_url = self.config.get("llm.base_url", "http://localhost:11434")
        model = self.config.get("llm.model", "deepseek-coder-v2:16b-q4")

        try:
            with OllamaBridge(base_url=base_url, model=model) as llm:
                if not llm.is_available():
                    logger.info(
                        "Ollama not available — skipping AI summaries. "
                        "Start Ollama with: ollama serve"
                    )
                    return

                summaries = llm.batch_summarize(vulnerabilities)
                for vuln in vulnerabilities:
                    if vuln.osv_id in summaries and summaries[vuln.osv_id]:
                        vuln.ai_summary = summaries[vuln.osv_id]

                logger.info(
                    "AI summaries generated for %d/%d vulnerabilities",
                    sum(1 for s in summaries.values() if s),
                    len(vulnerabilities),
                )
        except Exception as e:
            logger.error("AI enrichment failed: %s", e)

    def generate_report(
        self,
        result: ScanResult,
        format: str = "json",
        output_path: str | None = None,
    ) -> str:
        """Generate a report from scan results.

        Args:
            result: The scan result to report on.
            format: Output format ('json' for now).
            output_path: File path to write the report (optional).

        Returns:
            The report content as string.
        """
        if format == "json":
            report = self._generate_json_report(result)
        else:
            report = self._generate_json_report(result)

        if output_path:
            Path(output_path).write_text(report, encoding="utf-8")

        return report

    def _generate_json_report(self, result: ScanResult) -> str:
        """Generate JSON report with dependencies and vulnerabilities."""
        graph = result.dependency_graph
        report_data = {
            "scan_id": str(result.id),
            "project_name": result.project_name,
            "scanned_at": result.scanned_at.isoformat(),
            "status": result.status,
            "summary": graph.to_summary() if graph else {},
            "vulnerability_summary": result.vulnerability_summary(),
            "dependencies": [],
            "vulnerabilities": [],
        }

        if graph:
            for dep in graph.dependencies:
                report_data["dependencies"].append({
                    "name": dep.name,
                    "version": dep.version_constraint.raw,
                    "is_direct": dep.is_direct,
                    "is_dev": dep.is_dev,
                    "depth": dep.depth,
                    "ecosystem": dep.ecosystem.value,
                    "scope": dep.scope,
                })

        for vuln in result.vulnerabilities:
            vuln_data = {
                "osv_id": vuln.osv_id,
                "cve_id": vuln.cve_id,
                "severity": vuln.severity.value,
                "cvss_score": vuln.cvss_score,
                "affected_dependency": vuln.affected_dependency,
                "summary": vuln.summary,
                "fixed_version": vuln.fixed_version,
                "ai_summary": vuln.ai_summary,
            }
            report_data["vulnerabilities"].append(vuln_data)

        return json.dumps(report_data, indent=2, ensure_ascii=False)
