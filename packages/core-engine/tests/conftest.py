"""Shared pytest fixtures for RiskCodeAI tests."""

from pathlib import Path

import pytest

# ─── Fixture Paths ─────────────────────────────────────────────────────────────

FIXTURES_DIR = Path(__file__).parent / "fixtures"
MANIFESTS_DIR = FIXTURES_DIR / "manifests"


@pytest.fixture
def fixtures_dir() -> Path:
    """Path to the fixtures directory."""
    return FIXTURES_DIR


@pytest.fixture
def manifests_dir() -> Path:
    """Path to the manifests fixture directory."""
    return MANIFESTS_DIR


@pytest.fixture
def package_json_path(manifests_dir: Path) -> str:
    """Path to the test package.json fixture."""
    return str(manifests_dir / "package.json")


@pytest.fixture
def requirements_txt_path(manifests_dir: Path) -> str:
    """Path to the test requirements.txt fixture."""
    return str(manifests_dir / "requirements.txt")


@pytest.fixture
def go_mod_path(manifests_dir: Path) -> str:
    """Path to the test go.mod fixture."""
    return str(manifests_dir / "go.mod")


@pytest.fixture
def pom_xml_path(manifests_dir: Path) -> str:
    """Path to the test pom.xml fixture."""
    return str(manifests_dir / "pom.xml")


@pytest.fixture
def tmp_project(tmp_path: Path) -> Path:
    """Create a temporary project directory with a package.json."""
    pkg = {
        "name": "temp-project",
        "version": "1.0.0",
        "dependencies": {"express": "^4.18.0"},
    }
    import json
    (tmp_path / "package.json").write_text(json.dumps(pkg))
    return tmp_path
