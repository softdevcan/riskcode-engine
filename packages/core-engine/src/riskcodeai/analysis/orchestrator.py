"""Analysis orchestrator for RiskCodeAI.

Coordinates the complete analysis workflow:
1. Ecosystem detection
2. Manifest parsing
3. (Future) Vulnerability scanning
4. (Future) Reachability analysis
5. (Future) AI changelog generation
6. (Future) Risk scoring
7. Report generation
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from riskcode_shared.types.models import DependencyGraph, ScanResult

from riskcodeai.config import RiskCodeConfig, load_config
from riskcodeai.parsers import detect_ecosystem, parse_project


class AnalysisOrchestrator:
    """Orchestrates the full dependency analysis workflow.
    
    Sprint 1: Only manifest parsing and basic reporting.
    Future sprints will add vulnerability scanning, reachability, AI, and scoring.
    """

    def __init__(self, config: RiskCodeConfig | None = None):
        self.config = config or load_config()

    def analyze(
        self,
        directory: str,
        manifest: str | None = None,
        ecosystem: str | None = None,
    ) -> ScanResult:
        """Run full analysis on a project directory.

        Args:
            directory: Path to the project directory.
            manifest: Specific manifest file to parse (optional).
            ecosystem: Force ecosystem detection (optional).

        Returns:
            ScanResult with dependency graph and (future) vulnerabilities.
        """
        # Step 1: Parse dependencies
        graph = parse_project(
            directory=directory,
            manifest=manifest,
            ecosystem=ecosystem,
        )

        # Step 2: Create scan result
        # Future: vulnerability scan, reachability, AI changelog, risk scoring
        result = ScanResult(
            project_name=Path(directory).name,
            dependency_graph=graph,
            vulnerabilities=[],  # Sprint 2+
            scanned_at=datetime.now(),
            status="completed",
        )

        return result

    def generate_report(
        self,
        result: ScanResult,
        format: str = "json",
        output_path: str | None = None,
    ) -> str:
        """Generate a report from scan results.

        Args:
            result: The scan result to report on.
            format: Output format ('json' for Sprint 1).
            output_path: File path to write the report (optional).

        Returns:
            The report content as string.
        """
        if format == "json":
            report = self._generate_json_report(result)
        else:
            # Sprint 1: only JSON supported
            report = self._generate_json_report(result)

        if output_path:
            Path(output_path).write_text(report, encoding="utf-8")

        return report

    def _generate_json_report(self, result: ScanResult) -> str:
        """Generate JSON report."""
        graph = result.dependency_graph
        report_data = {
            "scan_id": str(result.id),
            "project_name": result.project_name,
            "scanned_at": result.scanned_at.isoformat(),
            "status": result.status,
            "summary": graph.to_summary() if graph else {},
            "dependencies": [],
            "vulnerabilities": [],  # Sprint 2+
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

        return json.dumps(report_data, indent=2, ensure_ascii=False)
