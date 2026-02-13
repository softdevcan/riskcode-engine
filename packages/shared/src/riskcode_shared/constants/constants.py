"""Shared constants for RiskCodeAI."""

from riskcode_shared.types.enums import Ecosystem

# ─── Exit Codes ────────────────────────────────────────────────────────────────
EXIT_SUCCESS = 0
EXIT_GENERAL_ERROR = 1
EXIT_CONFIG_ERROR = 2
EXIT_NETWORK_ERROR = 3
EXIT_LLM_ERROR = 4
EXIT_VULNERABILITIES_FOUND = 10

# ─── Manifest File → Ecosystem Mapping ─────────────────────────────────────────
MANIFEST_ECOSYSTEM_MAP: dict[str, Ecosystem] = {
    # JavaScript / Node.js
    "package.json": Ecosystem.NPM,
    "package-lock.json": Ecosystem.NPM,
    "yarn.lock": Ecosystem.NPM,
    "pnpm-lock.yaml": Ecosystem.NPM,
    # Python
    "requirements.txt": Ecosystem.PYPI,
    "Pipfile.lock": Ecosystem.PYPI,
    "pyproject.toml": Ecosystem.PYPI,
    "poetry.lock": Ecosystem.PYPI,
    # Java / Maven
    "pom.xml": Ecosystem.MAVEN,
    "build.gradle": Ecosystem.MAVEN,
    # Go
    "go.mod": Ecosystem.GO,
    "go.sum": Ecosystem.GO,
    # Rust
    "Cargo.toml": Ecosystem.RUST,
    "Cargo.lock": Ecosystem.RUST,
}

# ─── Manifest files to search (in priority order per ecosystem) ────────────────
MANIFEST_SEARCH_ORDER: list[str] = [
    "package.json",
    "requirements.txt",
    "pyproject.toml",
    "go.mod",
    "pom.xml",
    "Cargo.toml",
]

# ─── Default Configuration Values ──────────────────────────────────────────────
DEFAULT_CONFIG = {
    "llm": {
        "provider": "ollama",
        "model": "deepseek-coder-v2:16b-q4",
        "base_url": "http://localhost:11434",
    },
    "osv": {
        "cache_ttl": 86400,  # 24 hours
        "offline_mode": False,
    },
    "reachability": {
        "enabled": True,
        "languages": ["javascript", "typescript", "python"],
        "max_depth": 10,
    },
    "scoring": {
        "cvss_weight": 0.4,
        "reachability_weight": 0.4,
        "usage_weight": 0.2,
    },
    "reports": {
        "default_format": "html",
        "include_changelogs": True,
        "include_call_paths": True,
    },
}

# ─── External API URLs ────────────────────────────────────────────────────────
OSV_API_BASE_URL = "https://api.osv.dev/v1"
OSV_QUERY_ENDPOINT = f"{OSV_API_BASE_URL}/query"
OSV_BATCH_ENDPOINT = f"{OSV_API_BASE_URL}/querybatch"

# ─── Config File Names ────────────────────────────────────────────────────────
CONFIG_FILE_NAME = ".riskcodeai.yaml"
CONFIG_ENV_VAR = "RISKCODEAI_CONFIG"

# ─── Supported Output Formats ─────────────────────────────────────────────────
SUPPORTED_FORMATS = ["json", "html", "pdf", "sarif"]
