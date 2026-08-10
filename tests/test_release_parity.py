"""Package, manifest, and build metadata parity checks."""

import json
import tomllib
from pathlib import Path

from prompt_evidence_collector import __version__
from prompt_evidence_collector._version import __version__ as source_version


ROOT = Path(__file__).resolve().parents[1]


def test_version_source_is_authoritative_across_package_and_manifest():
    with (ROOT / "pyproject.toml").open("rb") as handle:
        pyproject = tomllib.load(handle)
    with (ROOT / "ellmos-module.v2.json").open(encoding="utf-8") as handle:
        manifest = json.load(handle)

    dynamic = pyproject["project"]["dynamic"]
    version_attr = pyproject["tool"]["setuptools"]["dynamic"]["version"]["attr"]
    assert dynamic == ["version"]
    assert version_attr == "prompt_evidence_collector._version.__version__"
    assert __version__ == source_version == manifest["version"]
