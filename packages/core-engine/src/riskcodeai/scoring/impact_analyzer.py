"""Dependency impact analyzer for RiskCodeAI.

Calculates how much impact a vulnerability has based on the
dependency's role in the project (direct vs transitive, dev vs
prod, depth, etc.).
"""

from __future__ import annotations

from dataclasses import dataclass

from riskcode_shared.types.models import Dependency, DependencyGraph


@dataclass(frozen=True)
class ImpactFactors:
    """Breakdown of factors contributing to a dependency's impact score."""

    is_direct: float       # 1.0 if direct, 0.4 if transitive
    is_production: float   # 1.0 if production, 0.3 if dev-only
    depth_penalty: float   # 1.0 at depth 0, decays with depth
    dependents_factor: float  # Higher if many packages depend on it

    @property
    def total(self) -> float:
        """Compute weighted impact score (0.0-1.0)."""
        raw = (
            0.35 * self.is_direct
            + 0.30 * self.is_production
            + 0.20 * self.depth_penalty
            + 0.15 * self.dependents_factor
        )
        return min(max(raw, 0.0), 1.0)


class ImpactAnalyzer:
    """Analyzes the impact of a dependency within the project.

    Impact represents how important a dependency is to the project.
    A direct production dependency has higher impact than a deeply-nested
    dev dependency.
    """

    def analyze(
        self,
        dep: Dependency,
        graph: DependencyGraph,
    ) -> ImpactFactors:
        """Calculate impact factors for a single dependency.

        Args:
            dep: The dependency to analyze.
            graph: The full dependency graph for context.

        Returns:
            ImpactFactors with individual scores and total.
        """
        # Factor 1: Direct vs transitive
        direct_score = 1.0 if dep.is_direct else 0.4

        # Factor 2: Production vs dev
        prod_score = 0.3 if dep.is_dev else 1.0

        # Factor 3: Depth penalty (deeper = less impact)
        # depth 0 → 1.0, depth 1 → 0.8, depth 2 → 0.6, ...
        depth_score = max(1.0 - (dep.depth * 0.2), 0.1)

        # Factor 4: How many other deps might depend on this?
        # Heuristic: well-known packages (lodash, express) are high-impact
        dependents = self._estimate_dependents(dep, graph)
        dependents_score = min(dependents / 5.0, 1.0)  # Cap at 5 dependents

        return ImpactFactors(
            is_direct=direct_score,
            is_production=prod_score,
            depth_penalty=depth_score,
            dependents_factor=dependents_score,
        )

    def analyze_all(
        self,
        graph: DependencyGraph,
    ) -> dict[str, ImpactFactors]:
        """Calculate impact for all dependencies in the graph.

        Returns:
            Dict mapping dependency name → ImpactFactors.
        """
        return {
            dep.name: self.analyze(dep, graph)
            for dep in graph.dependencies
        }

    def _estimate_dependents(
        self,
        dep: Dependency,
        graph: DependencyGraph,
    ) -> int:
        """Estimate how many other dependencies depend on this package.

        Simple heuristic: count how many deps could transitively
        depend on this one based on depth ordering.
        Currently returns 1 for direct deps (conservative estimate).

        Future: build reverse dependency graph for accurate count.
        """
        if dep.is_direct:
            # Direct deps are used by the project itself
            return 1

        # Transitive deps may be pulled in by multiple direct deps
        # Heuristic: assume packages at lower depth have more dependents
        depth = dep.depth or 1
        return max(1, 3 - depth)
