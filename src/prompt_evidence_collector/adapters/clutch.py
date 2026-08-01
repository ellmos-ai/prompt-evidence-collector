"""Fixed Clutch resolver adapter used by the signed runtime registry."""

from __future__ import annotations

from typing import Any


def resolve_content(locator: Any) -> str:
    """Resolve one signed locator through Clutch's canonical local store."""
    from clutch.evidence_locator import ClutchEvidenceLocator, PromptEvidenceLocator
    from clutch.session_store import SessionStore

    # The authorization layer deliberately freezes caller input into its own
    # immutable snapshot.  Re-materialize Clutch's public locator value here so
    # Clutch can run its native schema/URI/hash validation without receiving a
    # mutable caller object or depending on the collector's private dataclass.
    native_locator = PromptEvidenceLocator(
        schema=locator.schema,
        provider_code=locator.provider_code,
        locator_id=locator.locator_id,
        source_uri=locator.source_uri,
        content_hash=locator.content_hash,
    )
    return ClutchEvidenceLocator(SessionStore()).resolve_content(native_locator)
