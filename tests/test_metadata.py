"""Repository metadata, documentation, manifest, and discoverability parity tests."""

import json
import tomllib
from pathlib import Path

from prompt_evidence_collector import __version__
from prompt_evidence_collector._version import __version__ as source_version

ROOT = Path(__file__).resolve().parents[1]


def test_version_authoritative_parity():
    """Verify version consistency across _version.py, pyproject.toml, and ellmos-module.v2.json."""
    with (ROOT / "pyproject.toml").open("rb") as handle:
        pyproject = tomllib.load(handle)
    with (ROOT / "ellmos-module.v2.json").open(encoding="utf-8") as handle:
        manifest = json.load(handle)

    dynamic = pyproject["project"]["dynamic"]
    version_attr = pyproject["tool"]["setuptools"]["dynamic"]["version"]["attr"]
    assert dynamic == ["version"]
    assert version_attr == "prompt_evidence_collector._version.__version__"
    assert __version__ == source_version == manifest["version"] == "0.4.0"


def test_documentation_links_and_no_file_uris():
    """Verify that all markdown documentation uses portable relative links without file:/// URIs."""
    doc_files = ["README.md", "README_de.md", "llms.txt", "SECURITY.md", "CHANGELOG.md"]
    for filename in doc_files:
        doc_path = ROOT / filename
        assert doc_path.is_file(), f"Expected documentation file {filename} to exist"
        content = doc_path.read_text(encoding="utf-8")
        assert "file:///" not in content, f"Found local file:/// URI in {filename}"


def test_llms_txt_integrity():
    """Verify that llms.txt contains proper discovery metadata and current timestamp."""
    llms_path = ROOT / "llms.txt"
    assert llms_path.is_file()
    content = llms_path.read_text(encoding="utf-8")
    assert "# ellmos-ai / prompt-evidence-collector" in content
    assert "Last-checked: 2026-08-16" in content
    assert "Local-Only Raw Store" in content or "LOCAL-FIRST" in content
    assert "src/prompt_evidence_collector/collector.py" in content
    assert "src/prompt_evidence_collector/authorization.py" in content


def test_readme_badges_and_ecosystem_parity():
    """Verify that README.md and README_de.md include language switchers and essential badges."""
    for filename in ("README.md", "README_de.md"):
        content = (ROOT / filename).read_text(encoding="utf-8")
        assert "Language-English" in content or "Sprache-Deutsch" in content
        assert "ellmos--ai" in content
        assert "open--bricks" in content
        assert "llms.txt" in content


def test_security_policy_invariants():
    """Verify that SECURITY.md defines local-first and zero-egress invariants."""
    security_file = ROOT / "SECURITY.md"
    assert security_file.is_file()
    content = security_file.read_text(encoding="utf-8")
    assert "Local-First" in content
    assert "Zero-Egress" in content
    assert "CaptureGrant" in content
    assert "Ed25519" in content


def test_pyproject_config_integrity():
    """Verify that pyproject.toml defines packaging and development tooling configuration."""
    with (ROOT / "pyproject.toml").open("rb") as handle:
        pyproject = tomllib.load(handle)

    project = pyproject.get("project", {})
    assert project.get("name") == "prompt-evidence-collector"
    assert project.get("requires-python") == ">=3.11"
    assert "cryptography>=43" in project.get("dependencies", [])

    tool = pyproject.get("tool", {})
    assert "pytest" in tool or "pytest" in str(tool)
    assert "ruff" in tool
