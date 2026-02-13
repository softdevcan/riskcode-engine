"""Composite risk scorer for RiskCodeAI.

Calculates a composite risk score (0-10) for each vulnerability
by combining multiple factors:
  - CVSS base score (vulnerability severity)
  - Usage impact (direct/transitive, dev/prod, depth)
  - Fixability (is a fix available?)
  - Age penalty (older unfixed vulns are riskier)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime

from riskcode_shared.types.enums import Severity
from riskcode_shared.types.models import (
    DependencyGraph,
    VulnerabilityInfo,
)

from riskcodeai.scoring.impact_analyzer import ImpactAnalyzer, ImpactFactors

logger = logging.getLogger(__name__)


@dataclass
class ScoringWeights:
    """Configurable weights for composite risk scoring.

    All weights should sum to 1.0 for normalized output.
    """

    cvss: float = 0.40          # Base vulnerability severity
    usage_impact: float = 0.25  # How important is the dependency
    fixability: float = 0.20    # Is there a known fix
    age: float = 0.15           # How long has it been unfixed

    def __post_init__(self):
        total = self.cvss + self.usage_impact + self.fixability + self.age
        if abs(total - 1.0) > 0.01:
            logger.warning(
                "Scoring weights sum to %.2f (expected 1.0). "
                "Results may not be on 0-10 scale.",
                total,
            )


@dataclass
class RiskBreakdown:
    """Detailed breakdown of a vulnerability's risk score."""

    osv_id: str
    cvss_component: float
    usage_component: float
    fixability_component: float
    age_component: float
    total_score: float
    severity: Severity
    impact_factors: ImpactFactors | None = None

    @property
    def risk_level(self) -> str:
        """Human-readable risk level."""
        if self.total_score >= 8.0:
            return "CRITICAL"
        elif self.total_score >= 6.0:
            return "HIGH"
        elif self.total_score >= 4.0:
            return "MEDIUM"
        return "LOW"


class RiskScorer:
    """Composite risk scorer combining CVSS, usage, fixability, and age.

    Produces a 0-10 risk score for each vulnerability that reflects
    both the technical severity and the project-specific context.
    """

    def __init__(
        self,
        weights: ScoringWeights | None = None,
    ):
        self.weights = weights or ScoringWeights()
        self._impact_analyzer = ImpactAnalyzer()

    def score_vulnerability(
        self,
        vuln: VulnerabilityInfo,
        graph: DependencyGraph | None = None,
    ) -> RiskBreakdown:
        """Calculate composite risk score for a single vulnerability.

        Args:
            vuln: The vulnerability to score.
            graph: Dependency graph for usage analysis (optional).

        Returns:
            RiskBreakdown with score components and total.
        """
        # ── Component 1: CVSS Score (0-10, already normalized) ──────────
        cvss_component = vuln.cvss_score

        # ── Component 2: Usage Impact (0-10) ────────────────────────────
        impact_factors: ImpactFactors | None = None
        if graph and vuln.affected_dependency:
            dep = graph.get_dependency(vuln.affected_dependency)
            if dep:
                impact_factors = self._impact_analyzer.analyze(dep, graph)
                usage_component = impact_factors.total * 10.0
            else:
                usage_component = 5.0  # Unknown dependency, assume medium
        else:
            usage_component = 5.0  # No graph available

        # ── Component 3: Fixability (0-10) ──────────────────────────────
        # Having a fix available INCREASES risk urgency (should be fixed NOW)
        if vuln.fixed_version:
            fixability_component = 8.0  # Fix available → high urgency
        else:
            fixability_component = 4.0  # No fix → less actionable

        # ── Component 4: Age Penalty (0-10) ─────────────────────────────
        age_component = self._calculate_age_score(vuln)

        # ── Weighted Composite ──────────────────────────────────────────
        total = (
            self.weights.cvss * cvss_component
            + self.weights.usage_impact * usage_component
            + self.weights.fixability * fixability_component
            + self.weights.age * age_component
        )

        # Clamp to 0-10 range
        total = min(max(round(total * 10) / 10, 0.0), 10.0)

        return RiskBreakdown(
            osv_id=vuln.osv_id,
            cvss_component=round(cvss_component, 1),
            usage_component=round(usage_component, 1),
            fixability_component=round(fixability_component, 1),
            age_component=round(age_component, 1),
            total_score=total,
            severity=VulnerabilityInfo.severity_from_cvss(total),
            impact_factors=impact_factors,
        )

    def score_all(
        self,
        vulnerabilities: list[VulnerabilityInfo],
        graph: DependencyGraph | None = None,
    ) -> list[RiskBreakdown]:
        """Score all vulnerabilities and return sorted by risk (highest first).

        Args:
            vulnerabilities: List of vulnerabilities to score.
            graph: Dependency graph for impact analysis.

        Returns:
            List of RiskBreakdown sorted by total_score descending.
        """
        breakdowns = [
            self.score_vulnerability(vuln, graph)
            for vuln in vulnerabilities
        ]

        # Sort by total score descending
        breakdowns.sort(key=lambda b: b.total_score, reverse=True)

        return breakdowns

    def _calculate_age_score(self, vuln: VulnerabilityInfo) -> float:
        """Calculate age-based risk factor.

        Older vulnerabilities with available fixes are riskier because
        they've been known and exploitable for longer.

        Returns:
            Score 0-10 where higher = older/riskier.
        """
        if not vuln.published:
            return 5.0  # Unknown age, assume moderate

        age_days = (datetime.now(tz=vuln.published.tzinfo) - vuln.published).days

        if age_days < 30:
            return 3.0   # Very recent
        elif age_days < 90:
            return 5.0   # A few months
        elif age_days < 365:
            return 7.0   # Several months to a year
        elif age_days < 730:
            return 8.5   # 1-2 years
        else:
            return 10.0  # Very old, high risk
