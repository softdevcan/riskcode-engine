"""AI-powered changelog and upgrade analysis for RiskCodeAI.

Uses Ollama to generate:
- Changelog summaries for version upgrades
- Breaking change analysis
- Update recommendations
"""

from __future__ import annotations

import logging
import re
from typing import Optional

from riskcode_shared.types.models import Dependency, DependencyGraph, VulnerabilityInfo

from riskcodeai.llm.ollama_bridge import OllamaBridge
from riskcodeai.llm.prompts import (
    BREAKING_CHANGE_PROMPT,
    CHANGELOG_SUMMARY_PROMPT,
    RISK_ASSESSMENT_PROMPT,
    UPDATE_RECOMMENDATION_PROMPT,
)
from riskcodeai.llm.validation import (
    BreakingChangeResult,
    LLMOutputValidator,
    ValidationResult,
)

logger = logging.getLogger(__name__)

# Maximum input tokens (~4 chars per token, leave room for response)
_MAX_CONTEXT_CHARS = 6000  # ~1500 tokens, safe for 8k context window


class ChangelogGenerator:
    """AI-powered changelog and upgrade analysis.

    Wraps OllamaBridge with changelog-specific prompts,
    validation, and context window management.
    """

    def __init__(
        self,
        bridge: OllamaBridge,
        max_context: int = _MAX_CONTEXT_CHARS,
    ):
        """Initialize the changelog generator.

        Args:
            bridge: Configured Ollama bridge instance.
            max_context: Max characters for prompt context.
        """
        self.bridge = bridge
        self.max_context = max_context
        self.validator = LLMOutputValidator(max_length=500)

    @property
    def is_available(self) -> bool:
        """Check if the underlying LLM is available."""
        return self.bridge.is_available()

    # ─── Changelog Summary ────────────────────────────────────────────

    def generate_changelog_summary(
        self,
        package_name: str,
        from_version: str,
        to_version: str,
        changelog_content: str = "",
    ) -> Optional[str]:
        """Generate a summary of changes between two versions.

        Args:
            package_name: Name of the package.
            from_version: Current version.
            to_version: Target version (usually the fix version).
            changelog_content: Raw changelog text (will be truncated
                             if too long for context window).

        Returns:
            Validated changelog summary, or None if unavailable.
        """
        if not self.is_available:
            return None

        # Sliding window: truncate changelog to fit context
        max_changelog = self.max_context - 500  # Reserve for prompt template
        if len(changelog_content) > max_changelog:
            changelog_content = self._sliding_window(
                changelog_content, max_changelog
            )

        prompt = CHANGELOG_SUMMARY_PROMPT.format(
            package_name=package_name,
            from_version=from_version,
            to_version=to_version,
            changelog_content=changelog_content or "No changelog available",
        )

        result = self.bridge.generate(prompt)
        if result:
            validated = self.validator.validate(result)
            return validated.text if validated.is_valid else result.strip()

        return None

    # ─── Breaking Change Analysis ─────────────────────────────────────

    def analyze_breaking_changes(
        self,
        vuln: VulnerabilityInfo,
        current_version: str,
        ecosystem: str = "npm",
    ) -> BreakingChangeResult:
        """Analyze if upgrading to the fix version introduces breaking changes.

        Also uses semver heuristics before calling LLM.

        Args:
            vuln: Vulnerability with fix version.
            current_version: Current dependency version.
            ecosystem: Package ecosystem name.

        Returns:
            BreakingChangeResult with analysis.
        """
        if not vuln.fixed_version:
            return BreakingChangeResult(
                is_breaking=False,
                confidence="HIGH",
                details="No fix version available, no upgrade to analyze.",
                raw_output="",
            )

        # Quick semver check first (no LLM needed)
        semver_breaking = self._is_major_bump(current_version, vuln.fixed_version)

        if not self.is_available:
            # Fallback to semver-only analysis
            return BreakingChangeResult(
                is_breaking=semver_breaking,
                confidence="MEDIUM" if semver_breaking else "LOW",
                details=(
                    f"Major version change detected ({current_version} → "
                    f"{vuln.fixed_version}). Manual review recommended."
                    if semver_breaking
                    else f"Minor/patch update ({current_version} → "
                    f"{vuln.fixed_version}). Likely safe to upgrade."
                ),
                raw_output="",
            )

        # Use LLM for deeper analysis
        prompt = BREAKING_CHANGE_PROMPT.format(
            package_name=vuln.affected_dependency or "unknown",
            current_version=current_version,
            target_version=vuln.fixed_version,
            vulnerability_summary=vuln.summary or vuln.osv_id,
            ecosystem=ecosystem,
        )

        result = self.bridge.generate(prompt)
        return self.validator.parse_breaking_change(result)

    # ─── Update Recommendation ────────────────────────────────────────

    def generate_update_recommendation(
        self,
        vuln: VulnerabilityInfo,
        current_version: str,
        risk_score: float = 0.0,
    ) -> Optional[str]:
        """Generate an upgrade recommendation for a vulnerable dependency.

        Args:
            vuln: The vulnerability to address.
            current_version: Current dependency version.
            risk_score: Composite risk score (0-10).

        Returns:
            Validated recommendation text, or None if unavailable.
        """
        if not self.is_available:
            return None

        prompt = UPDATE_RECOMMENDATION_PROMPT.format(
            package_name=vuln.affected_dependency or "unknown",
            current_version=current_version,
            fixed_version=vuln.fixed_version or "No fix available",
            vulnerability_summary=vuln.summary or vuln.osv_id,
            severity=vuln.severity.value,
            cvss_score=vuln.cvss_score,
            risk_score=round(risk_score, 1),
        )

        result = self.bridge.generate(prompt)
        if result:
            validated = self.validator.validate(result)
            return validated.text if validated.is_valid else result.strip()

        return None

    # ─── Risk Assessment ──────────────────────────────────────────────

    def generate_risk_assessment(
        self,
        vuln: VulnerabilityInfo,
        dep: Dependency | None = None,
    ) -> Optional[str]:
        """Generate a contextual risk assessment for a vulnerability.

        Args:
            vuln: The vulnerability to assess.
            dep: The affected dependency (for context).

        Returns:
            Validated risk assessment text, or None if unavailable.
        """
        if not self.is_available:
            return None

        prompt = RISK_ASSESSMENT_PROMPT.format(
            osv_id=vuln.osv_id,
            cve_id=vuln.cve_id or "N/A",
            package_name=vuln.affected_dependency or "unknown",
            current_version=(
                dep.version_constraint.raw if dep else "unknown"
            ),
            cvss_score=vuln.cvss_score,
            severity=vuln.severity.value,
            summary=vuln.summary or "No summary",
            dep_type="direct" if (dep and dep.is_direct) else "transitive",
            dep_env="development" if (dep and dep.is_dev) else "production",
            depth=dep.depth if dep else 0,
        )

        result = self.bridge.generate(prompt)
        if result:
            validated = self.validator.validate(result)
            return validated.text if validated.is_valid else result.strip()

        return None

    # ─── Batch Operations ─────────────────────────────────────────────

    def batch_generate(
        self,
        vulnerabilities: list[VulnerabilityInfo],
        graph: DependencyGraph | None = None,
        max_items: int = 10,
    ) -> dict[str, dict[str, Optional[str]]]:
        """Generate changelog analysis for multiple vulnerabilities.

        Prioritizes by severity. For each vulnerability generates:
        - update_recommendation
        - breaking_change analysis (if fix version available)

        Args:
            vulnerabilities: Vulnerabilities to analyze.
            graph: Dependency graph for context.
            max_items: Maximum items to process.

        Returns:
            Dict mapping osv_id → {recommendation, breaking_change, ...}
        """
        if not self.is_available or not vulnerabilities:
            return {}

        # Sort by severity (critical first)
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sorted_vulns = sorted(
            vulnerabilities,
            key=lambda v: severity_order.get(v.severity.value, 5),
        )

        results: dict[str, dict[str, Optional[str]]] = {}

        for vuln in sorted_vulns[:max_items]:
            dep = None
            current_version = "unknown"

            if graph and vuln.affected_dependency:
                dep = graph.get_dependency(vuln.affected_dependency)
                if dep:
                    current_version = dep.version_constraint.raw

            entry: dict[str, Optional[str]] = {}

            # Generate update recommendation
            recommendation = self.generate_update_recommendation(
                vuln, current_version
            )
            entry["update_recommendation"] = recommendation

            # Analyze breaking changes (only if fix version exists)
            if vuln.fixed_version:
                bc = self.analyze_breaking_changes(
                    vuln, current_version,
                    ecosystem=dep.ecosystem.value if dep else "npm",
                )
                entry["breaking_change"] = (
                    f"[{bc.confidence}] {'BREAKING' if bc.is_breaking else 'SAFE'}: "
                    f"{bc.details}"
                )
            else:
                entry["breaking_change"] = None

            results[vuln.osv_id] = entry

        return results

    # ─── Internal Helpers ─────────────────────────────────────────────

    def _sliding_window(self, text: str, max_chars: int) -> str:
        """Extract the most relevant portion of a changelog.

        Strategy: keep the beginning (latest changes) and end
        (security notes), truncate the middle.
        """
        if len(text) <= max_chars:
            return text

        # Keep first 60% and last 40%
        head_size = int(max_chars * 0.6)
        tail_size = max_chars - head_size - 30  # 30 chars for separator

        head = text[:head_size].rstrip()
        tail = text[-tail_size:].lstrip()

        return f"{head}\n\n[... truncated ...]\n\n{tail}"

    @staticmethod
    def _is_major_bump(from_ver: str, to_ver: str) -> bool:
        """Check if the version change is a major bump (semver).

        Examples:
            "1.2.3" → "2.0.0" → True (major bump)
            "1.2.3" → "1.3.0" → False (minor bump)
            "^4.18.2" → "4.20.0" → False (same major)
        """
        def extract_major(ver: str) -> Optional[int]:
            cleaned = ver.lstrip("^~>=<! ")
            match = re.match(r"(\d+)", cleaned)
            return int(match.group(1)) if match else None

        from_major = extract_major(from_ver)
        to_major = extract_major(to_ver)

        if from_major is not None and to_major is not None:
            return to_major > from_major

        return False
