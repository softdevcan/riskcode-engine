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


# ─── Changelog Summary Prompt (Sprint 3 preparation) ─────────────────────────

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


# ─── Batch Summary Prompt ────────────────────────────────────────────────────

BATCH_VULNERABILITY_PROMPT = """You are a security analyst. Provide a brief security assessment for this project.

Project has {total_deps} dependencies with {total_vulns} known vulnerabilities:

{vulnerability_list}

Provide a 3-5 sentence security assessment with prioritized recommendations.
Focus on the most critical issues and immediate actions. Do NOT include markdown formatting."""
