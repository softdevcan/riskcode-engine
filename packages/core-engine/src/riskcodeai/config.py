"""RiskCodeAI configuration management.

Handles loading, saving, and managing .riskcodeai.yaml config files.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

from riskcode_shared.constants.constants import (
    CONFIG_ENV_VAR,
    CONFIG_FILE_NAME,
    DEFAULT_CONFIG,
)


class RiskCodeConfig:
    """Application configuration loaded from .riskcodeai.yaml."""

    def __init__(self, config_data: dict[str, Any] | None = None):
        self._data = _deep_merge(DEFAULT_CONFIG.copy(), config_data or {})

    # ─── LLM Settings ──────────────────────────────────────────────────────────
    @property
    def llm_provider(self) -> str:
        return self._data["llm"]["provider"]

    @property
    def llm_model(self) -> str:
        return self._data["llm"]["model"]

    @property
    def llm_base_url(self) -> str:
        return os.environ.get("OLLAMA_URL", self._data["llm"]["base_url"])

    # ─── OSV Settings ──────────────────────────────────────────────────────────
    @property
    def osv_cache_ttl(self) -> int:
        return self._data["osv"]["cache_ttl"]

    @property
    def osv_offline_mode(self) -> bool:
        return self._data["osv"]["offline_mode"]

    # ─── Reachability Settings ─────────────────────────────────────────────────
    @property
    def reachability_enabled(self) -> bool:
        return self._data["reachability"]["enabled"]

    @property
    def reachability_languages(self) -> list[str]:
        return self._data["reachability"]["languages"]

    @property
    def reachability_max_depth(self) -> int:
        return self._data["reachability"]["max_depth"]

    # ─── Scoring Weights ───────────────────────────────────────────────────────
    @property
    def scoring_cvss_weight(self) -> float:
        return self._data["scoring"]["cvss_weight"]

    @property
    def scoring_reachability_weight(self) -> float:
        return self._data["scoring"]["reachability_weight"]

    @property
    def scoring_usage_weight(self) -> float:
        return self._data["scoring"]["usage_weight"]

    # ─── Report Settings ───────────────────────────────────────────────────────
    @property
    def default_report_format(self) -> str:
        return self._data["reports"]["default_format"]

    # ─── Utility Methods ───────────────────────────────────────────────────────
    def get(self, key: str, default: Any = None) -> Any:
        """Get a nested config value using dot notation."""
        keys = key.split(".")
        value = self._data
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        return value

    def set(self, key: str, value: Any) -> None:
        """Set a nested config value using dot notation."""
        keys = key.split(".")
        data = self._data
        for k in keys[:-1]:
            if k not in data or not isinstance(data[k], dict):
                data[k] = {}
            data = data[k]
        data[keys[-1]] = value

    def to_dict(self) -> dict[str, Any]:
        """Return the full config as a dict."""
        return self._data.copy()


def load_config(directory: str | None = None) -> RiskCodeConfig:
    """Load configuration from .riskcodeai.yaml.

    Search order:
    1. RISKCODEAI_CONFIG environment variable
    2. .riskcodeai.yaml in the specified directory
    3. .riskcodeai.yaml in current working directory
    4. Default config (if no file found)

    Args:
        directory: Directory to search for config file.

    Returns:
        RiskCodeConfig instance.
    """
    # Check env var first
    env_path = os.environ.get(CONFIG_ENV_VAR)
    if env_path:
        config_path = Path(env_path)
        if config_path.exists():
            return _load_from_file(config_path)

    # Check specified directory
    if directory:
        config_path = Path(directory) / CONFIG_FILE_NAME
        if config_path.exists():
            return _load_from_file(config_path)

    # Check CWD
    config_path = Path.cwd() / CONFIG_FILE_NAME
    if config_path.exists():
        return _load_from_file(config_path)

    # Return defaults
    return RiskCodeConfig()


def save_config(directory: str, config: RiskCodeConfig | None = None) -> Path:
    """Save configuration to .riskcodeai.yaml.

    Args:
        directory: Directory where the config will be saved.
        config: Config to save. Uses defaults if None.

    Returns:
        Path to the saved config file.
    """
    config = config or RiskCodeConfig()
    config_path = Path(directory) / CONFIG_FILE_NAME

    with open(config_path, "w", encoding="utf-8") as f:
        yaml.dump(
            config.to_dict(),
            f,
            default_flow_style=False,
            allow_unicode=True,
            sort_keys=False,
        )

    return config_path


def _load_from_file(path: Path) -> RiskCodeConfig:
    """Load config from a YAML file."""
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return RiskCodeConfig(data)


def _deep_merge(base: dict, override: dict) -> dict:
    """Deep merge two dicts, with override taking precedence."""
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result
