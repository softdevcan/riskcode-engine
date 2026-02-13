"""LLM output validation and sanitization for RiskCodeAI.

Validates LLM responses to detect common issues:
- Hallucinated version numbers
- Markdown formatting in plain-text responses
- Overly long or repetitive output
- Confidence scoring for structured responses
"""

from __future__ import annotations

import re
import logging
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

# ─── Regex patterns ──────────────────────────────────────────────────────────

_SEMVER_PATTERN = re.compile(
    r"\b(\d+\.\d+\.\d+(?:-[\w.]+)?(?:\+[\w.]+)?)\b"
)

_MARKDOWN_PATTERNS = [
    re.compile(r"^#{1,6}\s+", re.MULTILINE),       # Headers
    re.compile(r"\*\*(.+?)\*\*"),                    # Bold
    re.compile(r"\*(.+?)\*"),                        # Italic
    re.compile(r"`(.+?)`"),                          # Inline code
    re.compile(r"```[\s\S]*?```", re.MULTILINE),     # Code blocks
    re.compile(r"^\s*[-*]\s+", re.MULTILINE),        # List items
    re.compile(r"^\s*\d+\.\s+", re.MULTILINE),       # Numbered lists
]

_BREAKING_PATTERN = re.compile(
    r"BREAKING:\s*(YES|NO)", re.IGNORECASE
)

_CONFIDENCE_PATTERN = re.compile(
    r"CONFIDENCE:\s*(HIGH|MEDIUM|LOW)", re.IGNORECASE
)

_DETAILS_PATTERN = re.compile(
    r"DETAILS:\s*(.+?)(?:\n|$)", re.IGNORECASE | re.DOTALL
)


@dataclass
class ValidationResult:
    """Result of validating an LLM output."""

    text: str             # Cleaned/sanitized text
    is_valid: bool        # Whether the output passed all checks
    confidence: float     # 0.0-1.0 confidence in the output quality
    warnings: list[str]   # Any warnings found during validation
    versions_found: list[str]  # Version numbers found in the output


@dataclass
class BreakingChangeResult:
    """Parsed result from a breaking change analysis prompt."""

    is_breaking: bool
    confidence: str       # "HIGH", "MEDIUM", "LOW"
    details: str
    raw_output: str


class LLMOutputValidator:
    """Validates and sanitizes LLM output.

    Detects common issues like hallucinated versions, unwanted
    markdown formatting, and overly verbose responses.
    """

    def __init__(
        self,
        max_length: int = 500,
        known_versions: list[str] | None = None,
    ):
        """Initialize the validator.

        Args:
            max_length: Maximum allowed output length in characters.
            known_versions: List of known-valid version numbers for
                           hallucination detection.
        """
        self.max_length = max_length
        self.known_versions = set(known_versions or [])

    def validate(self, text: str | None) -> ValidationResult:
        """Validate and sanitize LLM output.

        Args:
            text: Raw LLM output to validate.

        Returns:
            ValidationResult with cleaned text and quality metrics.
        """
        if not text or not text.strip():
            return ValidationResult(
                text="",
                is_valid=False,
                confidence=0.0,
                warnings=["Empty output"],
                versions_found=[],
            )

        warnings: list[str] = []
        cleaned = text.strip()

        # ── Check 1: Strip markdown formatting ────────────────────────
        markdown_count = 0
        for pattern in _MARKDOWN_PATTERNS:
            matches = pattern.findall(cleaned)
            if matches:
                markdown_count += len(matches)

        if markdown_count > 0:
            cleaned = self._strip_markdown(cleaned)
            warnings.append(f"Stripped {markdown_count} markdown elements")

        # ── Check 2: Truncate if too long ─────────────────────────────
        if len(cleaned) > self.max_length:
            # Try to truncate at sentence boundary
            cleaned = self._smart_truncate(cleaned, self.max_length)
            warnings.append(f"Truncated from {len(text)} to {len(cleaned)} chars")

        # ── Check 3: Detect version numbers ───────────────────────────
        versions_found = _SEMVER_PATTERN.findall(cleaned)

        # ── Check 4: Check for hallucinated versions ──────────────────
        if self.known_versions and versions_found:
            hallucinated = [
                v for v in versions_found
                if v not in self.known_versions
            ]
            if hallucinated:
                warnings.append(
                    f"Potentially hallucinated versions: {', '.join(hallucinated)}"
                )

        # ── Check 5: Detect repetitive text ───────────────────────────
        if self._is_repetitive(cleaned):
            warnings.append("Repetitive output detected")
            # Take first occurrence
            cleaned = self._dedup_text(cleaned)

        # ── Confidence scoring ────────────────────────────────────────
        confidence = self._calculate_confidence(cleaned, warnings)

        return ValidationResult(
            text=cleaned,
            is_valid=len(warnings) <= 2 and confidence >= 0.3,
            confidence=confidence,
            warnings=warnings,
            versions_found=versions_found,
        )

    def parse_breaking_change(self, text: str | None) -> BreakingChangeResult:
        """Parse a structured breaking change analysis response.

        Expects format:
            BREAKING: YES/NO
            CONFIDENCE: HIGH/MEDIUM/LOW
            DETAILS: ...
        """
        if not text:
            return BreakingChangeResult(
                is_breaking=False,
                confidence="LOW",
                details="No analysis available",
                raw_output="",
            )

        # Parse structured fields
        breaking_match = _BREAKING_PATTERN.search(text)
        confidence_match = _CONFIDENCE_PATTERN.search(text)
        details_match = _DETAILS_PATTERN.search(text)

        is_breaking = (
            breaking_match.group(1).upper() == "YES"
            if breaking_match
            else False
        )

        confidence = (
            confidence_match.group(1).upper()
            if confidence_match
            else "LOW"
        )

        details = (
            details_match.group(1).strip()
            if details_match
            else text.strip()
        )

        # Validate details
        validated = self.validate(details)

        return BreakingChangeResult(
            is_breaking=is_breaking,
            confidence=confidence,
            details=validated.text,
            raw_output=text,
        )

    def _strip_markdown(self, text: str) -> str:
        """Remove markdown formatting from text."""
        result = text

        # Remove code blocks first
        result = re.sub(r"```[\s\S]*?```", "", result)

        # Remove headers
        result = re.sub(r"^#{1,6}\s+", "", result, flags=re.MULTILINE)

        # Remove bold/italic
        result = re.sub(r"\*\*(.+?)\*\*", r"\1", result)
        result = re.sub(r"\*(.+?)\*", r"\1", result)

        # Remove inline code
        result = re.sub(r"`(.+?)`", r"\1", result)

        # Clean up extra whitespace
        result = re.sub(r"\n{3,}", "\n\n", result)

        return result.strip()

    def _smart_truncate(self, text: str, max_len: int) -> str:
        """Truncate text at a sentence boundary."""
        if len(text) <= max_len:
            return text

        # Find last sentence end within limit
        truncated = text[:max_len]
        last_period = truncated.rfind(".")
        last_excl = truncated.rfind("!")
        last_q = truncated.rfind("?")

        best_end = max(last_period, last_excl, last_q)

        if best_end > max_len * 0.5:  # Only if we keep >50% of content
            return truncated[:best_end + 1]

        return truncated.rstrip() + "..."

    def _is_repetitive(self, text: str) -> bool:
        """Check if text contains significant repetition."""
        sentences = [s.strip() for s in text.split(".") if s.strip()]
        if len(sentences) < 3:
            return False

        seen: set[str] = set()
        dupes = 0
        for s in sentences:
            normalized = s.lower().strip()
            if normalized in seen:
                dupes += 1
            seen.add(normalized)

        return dupes > len(sentences) * 0.3

    def _dedup_text(self, text: str) -> str:
        """Remove duplicate sentences from text."""
        sentences = text.split(".")
        seen: set[str] = set()
        unique: list[str] = []

        for s in sentences:
            normalized = s.lower().strip()
            if normalized and normalized not in seen:
                seen.add(normalized)
                unique.append(s)

        return ".".join(unique).strip()

    def _calculate_confidence(
        self,
        text: str,
        warnings: list[str],
    ) -> float:
        """Calculate a confidence score for the LLM output.

        Returns:
            Float 0.0-1.0 where 1.0 is highest confidence.
        """
        score = 1.0

        # Penalty for warnings
        score -= len(warnings) * 0.15

        # Penalty for very short output
        if len(text) < 20:
            score -= 0.3

        # Penalty for very long output
        if len(text) > self.max_length:
            score -= 0.1

        # Bonus for having version numbers (more factual)
        if _SEMVER_PATTERN.search(text):
            score += 0.05

        return min(max(score, 0.0), 1.0)
