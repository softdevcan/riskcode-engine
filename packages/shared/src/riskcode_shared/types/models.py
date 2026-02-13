"""Shared Pydantic models for RiskCodeAI."""

from __future__ import annotations

from datetime import datetime
from typing import Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from riskcode_shared.types.enums import Ecosystem, ReachabilityStatus, Severity


class VersionConstraint(BaseModel):
    """Parsed version constraint from a manifest file.
    
    Examples:
        - "^1.2.0" -> operator="^", version="1.2.0"
        - ">=1.0.0,<2.0.0" -> raw=">=1.0.0,<2.0.0"
        - "==3.4.5" -> operator="==", version="3.4.5"
    """

    raw: str = Field(description="Original version string from manifest")
    operator: Optional[str] = Field(default=None, description="Version operator (^, ~, >=, ==, etc.)")
    version: Optional[str] = Field(default=None, description="Extracted version number")

    @classmethod
    def parse_version_string(cls, raw: str) -> "VersionConstraint":
        """Parse a version constraint string into components."""
        raw = raw.strip()
        if not raw or raw in ("*", "latest"):
            return cls(raw=raw, operator="*", version=raw)

        # Handle common operators
        for op in (">=", "<=", "!=", "==", "~=", "^", "~", ">", "<"):
            if raw.startswith(op):
                version = raw[len(op):].strip()
                return cls(raw=raw, operator=op, version=version)

        # No operator — treat as exact version
        return cls(raw=raw, operator="==", version=raw)


class Dependency(BaseModel):
    """A single dependency entry from a manifest file."""

    name: str = Field(description="Package name")
    version_constraint: VersionConstraint = Field(description="Version constraint")
    is_direct: bool = Field(default=True, description="Direct or transitive dependency")
    depth: int = Field(default=0, description="Depth in dependency tree (0 = direct)")
    ecosystem: Ecosystem = Field(description="Package ecosystem")
    is_dev: bool = Field(default=False, description="Whether this is a dev/test dependency")
    scope: Optional[str] = Field(default=None, description="Dependency scope (Maven: compile/test/provided)")

    @property
    def display_name(self) -> str:
        """Human-readable name with version."""
        return f"{self.name}@{self.version_constraint.raw}"


class DependencyGraph(BaseModel):
    """Complete dependency graph parsed from a manifest file."""

    dependencies: list[Dependency] = Field(default_factory=list)
    ecosystem: Ecosystem = Field(description="Detected package ecosystem")
    manifest_path: str = Field(description="Path to the manifest file")
    parsed_at: datetime = Field(default_factory=datetime.now)

    @property
    def direct_dependencies(self) -> list[Dependency]:
        """Get only direct (non-transitive) dependencies."""
        return [d for d in self.dependencies if d.is_direct]

    @property
    def transitive_dependencies(self) -> list[Dependency]:
        """Get only transitive (indirect) dependencies."""
        return [d for d in self.dependencies if not d.is_direct]

    @property
    def dev_dependencies(self) -> list[Dependency]:
        """Get only dev/test dependencies."""
        return [d for d in self.dependencies if d.is_dev]

    @property
    def production_dependencies(self) -> list[Dependency]:
        """Get only production dependencies."""
        return [d for d in self.dependencies if not d.is_dev]

    def get_dependency(self, name: str) -> Optional[Dependency]:
        """Find a dependency by name."""
        for dep in self.dependencies:
            if dep.name == name:
                return dep
        return None

    def to_summary(self) -> dict:
        """Generate a summary dict for reporting."""
        return {
            "ecosystem": self.ecosystem.value,
            "manifest_path": self.manifest_path,
            "total_dependencies": len(self.dependencies),
            "direct": len(self.direct_dependencies),
            "transitive": len(self.transitive_dependencies),
            "dev": len(self.dev_dependencies),
            "production": len(self.production_dependencies),
            "parsed_at": self.parsed_at.isoformat(),
        }


class AffectedRange(BaseModel):
    """Version range affected by a vulnerability."""

    range_type: str = Field(default="ECOSYSTEM", description="Range type (ECOSYSTEM, SEMVER, GIT)")
    introduced: Optional[str] = Field(default=None, description="Version where vulnerability was introduced")
    fixed: Optional[str] = Field(default=None, description="Version where vulnerability was fixed")
    last_affected: Optional[str] = Field(default=None, description="Last known affected version")


class VulnerabilityReference(BaseModel):
    """Reference link for a vulnerability."""

    url: str = Field(description="Reference URL")
    ref_type: str = Field(default="WEB", description="Reference type (ADVISORY, WEB, FIX, REPORT, etc.)")


class VulnerabilityInfo(BaseModel):
    """Vulnerability information from OSV.dev API."""

    id: UUID = Field(default_factory=uuid4)
    osv_id: str = Field(description="OSV identifier (e.g., GHSA-xxxx, PYSEC-xxxx)")
    cve_id: Optional[str] = Field(default=None, description="CVE identifier (e.g., CVE-2024-xxxx)")
    aliases: list[str] = Field(default_factory=list, description="All known aliases (CVE, GHSA, etc.)")
    summary: str = Field(default="", description="Short vulnerability summary from OSV")
    details: Optional[str] = Field(default=None, description="Full vulnerability description")
    cvss_score: float = Field(default=0.0, description="CVSS base score (0-10)")
    severity: Severity = Field(default=Severity.LOW)
    reachability: ReachabilityStatus = Field(default=ReachabilityStatus.UNKNOWN)
    risk_score: float = Field(default=0.0, description="Composite risk score (0-10)")
    affected_dependency: Optional[str] = Field(default=None, description="Name of the affected package")
    affected_ranges: list[AffectedRange] = Field(default_factory=list, description="Affected version ranges")
    fixed_version: Optional[str] = Field(default=None, description="Earliest version that fixes the issue")
    references: list[VulnerabilityReference] = Field(default_factory=list, description="Advisory/reference links")
    published: Optional[datetime] = Field(default=None, description="Date vulnerability was published")
    modified: Optional[datetime] = Field(default=None, description="Date vulnerability was last modified")
    ai_summary: Optional[str] = Field(default=None, description="AI-generated plain-language summary")

    @classmethod
    def severity_from_cvss(cls, score: float) -> Severity:
        """Derive severity from CVSS score."""
        if score >= 9.0:
            return Severity.CRITICAL
        elif score >= 7.0:
            return Severity.HIGH
        elif score >= 4.0:
            return Severity.MEDIUM
        elif score > 0.0:
            return Severity.LOW
        return Severity.LOW


class ScanResult(BaseModel):
    """Complete scan result with dependency graph and vulnerability data."""

    id: UUID = Field(default_factory=uuid4)
    project_name: str = Field(default="")
    dependency_graph: Optional[DependencyGraph] = None
    vulnerabilities: list[VulnerabilityInfo] = Field(default_factory=list)
    scanned_at: datetime = Field(default_factory=datetime.now)
    status: str = Field(default="completed")

    @property
    def critical_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.LOW)

    def vulnerability_summary(self) -> dict:
        """Generate a summary dict of vulnerability counts by severity."""
        return {
            "total": len(self.vulnerabilities),
            "critical": self.critical_count,
            "high": self.high_count,
            "medium": self.medium_count,
            "low": self.low_count,
            "with_fix": sum(1 for v in self.vulnerabilities if v.fixed_version),
            "with_ai_summary": sum(1 for v in self.vulnerabilities if v.ai_summary),
        }

