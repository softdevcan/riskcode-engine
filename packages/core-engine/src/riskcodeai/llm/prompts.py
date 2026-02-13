"""Prompt templates for RiskCodeAI LLM interactions.

These prompts are designed for local LLMs (Ollama) with limited context
windows. They are concise and structured to produce consistent output.
"""

# ─── Vulnerability Summary Prompt ─────────────────────────────────────────────

VULNERABILITY_SUMMARY_PROMPT = """You are a security analyst. Summarize this vulnerability in 2-3 sentences for a developer.
Focus on: what the vulnerability does, how it can be exploited, and what the developer should do.

Vulnerability ID: {osv_id}
CVE: {cve_id}
Package: {package_name}
CVSS Score: {cvss_score}
Summary: {summary}
Fixed Version: {fixed_version}

Provide a clear, actionable summary in plain language. Do NOT include markdown formatting."""


# ─── Changelog Summary Prompt ────────────────────────────────────────────────

CHANGELOG_SUMMARY_PROMPT = """You are a technical writer. Summarize the changes between package versions for a developer.

Package: {package_name}
From Version: {from_version}
To Version: {to_version}
Changelog Content:
{changelog_content}

Provide a concise summary focusing on:
1. Breaking changes (if any)
2. New features
3. Bug fixes
4. Security patches

Format as a brief paragraph. Do NOT include markdown formatting."""


# ─── Breaking Change Detection Prompt ────────────────────────────────────────

BREAKING_CHANGE_PROMPT = """You are a software compatibility expert. Analyze if upgrading this package will introduce breaking changes.

Package: {package_name}
Current Version: {current_version}
Target Version: {target_version}
Vulnerability: {vulnerability_summary}
Package Ecosystem: {ecosystem}

Based on semantic versioning rules and the version jump:
1. Is this a MAJOR version change? (likely breaking)
2. Are there known breaking changes in this upgrade path?
3. What should the developer check before upgrading?

Respond with:
BREAKING: YES or NO
CONFIDENCE: HIGH, MEDIUM, or LOW
DETAILS: Brief explanation (2-3 sentences max)

Do NOT include markdown formatting."""


# ─── Update Recommendation Prompt ────────────────────────────────────────────

UPDATE_RECOMMENDATION_PROMPT = """You are a dependency management expert. Recommend an upgrade strategy for this vulnerable dependency.

Package: {package_name}
Current Version: {current_version}
Fixed Version: {fixed_version}
Vulnerability: {vulnerability_summary}
Severity: {severity}
CVSS Score: {cvss_score}
Risk Score: {risk_score}

Provide a brief recommendation (3-4 sentences) covering:
1. Urgency level (immediate, soon, when convenient)
2. Recommended target version
3. Any migration steps or precautions
4. Alternative mitigations if upgrade is not possible

Do NOT include markdown formatting."""


# ─── Risk Assessment Prompt ──────────────────────────────────────────────────

RISK_ASSESSMENT_PROMPT = """You are a security risk analyst. Assess the real-world risk of this vulnerability in context.

Vulnerability: {osv_id} ({cve_id})
Package: {package_name} (version {current_version})
CVSS Score: {cvss_score}
Severity: {severity}
Summary: {summary}

Dependency Context:
- Type: {dep_type} (direct/transitive)
- Environment: {dep_env} (production/development)
- Depth in dependency tree: {depth}

In 2-3 sentences, assess:
1. How likely is exploitation in a typical project?
2. What is the realistic impact?
3. Is this a priority fix?

Do NOT include markdown formatting."""


# ─── Batch Summary Prompt ────────────────────────────────────────────────────

BATCH_VULNERABILITY_PROMPT = """You are a security analyst. Provide a brief security assessment for this project.

Project has {total_deps} dependencies with {total_vulns} known vulnerabilities:

{vulnerability_list}

Provide a 3-5 sentence security assessment with prioritized recommendations.
Focus on the most critical issues and immediate actions. Do NOT include markdown formatting."""
