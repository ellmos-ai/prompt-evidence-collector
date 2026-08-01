"""Fixed Clutch resolver adapter used by the signed runtime registry."""

from __future__ import annotations

from typing import Any


def resolve_content(locator: Any) -> str:
    """Resolve one signed locator through Clutch's canonical local store."""
    from clutch.evidence_locator import ClutchEvidenceLocator
    from clutch.session_store import SessionStore

    return ClutchEvidenceLocator(SessionStore()).resolve_content(locator)
