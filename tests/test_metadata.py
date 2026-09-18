"""Repository metadata, documentation, manifest, and discoverability parity tests."""

import json
import re
import tomllib
from datetime import date
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
    doc_files = [
        "README.md",
        "README_de.md",
        "llms.txt",
        "SECURITY.md",
        "CHANGELOG.md",
        "CODE_OF_CONDUCT.md",
        "CONTRIBUTING.md",
        "docs/ai-act-note.md",
    ]
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
    match = re.search(r"^Last-checked: (\d{4}-\d{2}-\d{2})$", content, re.MULTILINE)
    assert match
    assert date.fromisoformat(match.group(1)) >= date(2026, 8, 21)
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
    assert project.get("urls", {}).get("Repository") == (
        "https://github.com/ellmos-ai/prompt-evidence-collector"
    )
    assert "Development Status :: 4 - Beta" in project.get("classifiers", [])

    tool = pyproject.get("tool", {})
    assert "pytest" in tool or "pytest" in str(tool)
    assert "ruff" in tool


def _headings(content: str) -> list[int]:
    return [len(match.group(1)) for match in re.finditer(r"^(#{1,6})\s+", content, re.MULTILINE)]


def _code_blocks(content: str) -> list[str]:
    return re.findall(r"```[^\n]*\n(.*?)```", content, re.DOTALL)


def test_readme_language_structure_and_code_parity():
    english = (ROOT / "README.md").read_text(encoding="utf-8")
    german = (ROOT / "README_de.md").read_text(encoding="utf-8")

    assert "Standalone, cloud-safe prompt and workflow evidence module" in english
    assert "Eigenständiges, cloud-sicheres Prompt- und Workflow-Evidenzmodul" in german
    assert "Dieser Pfad prüft" not in english
    assert "## Entwicklung" not in english
    assert _headings(english) == _headings(german)
    assert _code_blocks(english) == _code_blocks(german)


def test_public_documentation_is_neutral_and_complete():
    required = {
        "CODE_OF_CONDUCT.md",
        "CONTRIBUTING.md",
        "THIRD_PARTY_LICENSES.txt",
        "docs/ai-act-note.md",
    }
    assert all((ROOT / name).is_file() for name in required)

    public_text = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (
            ROOT / "README.md",
            ROOT / "README_de.md",
            ROOT / "llms.txt",
            ROOT / "ellmos-module.v2.json",
        )
    )
    for private_name in ("TOM_lm", "build-your-users-mind", "ellmos-development-system"):
        assert private_name not in public_text
    assert not re.search(r"C:[/\\]Users[/\\]", public_text, re.IGNORECASE)

    for name in ("README.md", "README_de.md"):
        content = (ROOT / name).read_text(encoding="utf-8")
        assert "THIRD_PARTY_LICENSES.txt" in content
        assert "docs/ai-act-note.md" in content


def test_gitignore_covers_private_runtime_and_work_files():
    patterns = set((ROOT / ".gitignore").read_text(encoding="utf-8").splitlines())
    for required in (
        ".env",
        ".env.*",
        "LOCK.*.txt",
        "*.db",
        "*.sqlite3",
        "*.pem",
        "*.pyc",
        "data/",
    ):
        assert required in patterns
