"""Standalone prompt evidence collector."""

from .collector import (
    AmbiguousEvidenceError,
    EvidenceIntegrityError,
    EvidenceNotFoundError,
    PromptEvidenceCollector,
    PromptEvidenceError,
    PromptEvidenceLocatorLike,
    PromptEvidenceReceipt,
    UnsafeEvidenceStoreError,
)

__version__ = "0.2.0"

__all__ = [
    "AmbiguousEvidenceError",
    "EvidenceIntegrityError",
    "EvidenceNotFoundError",
    "PromptEvidenceCollector",
    "PromptEvidenceError",
    "PromptEvidenceLocatorLike",
    "PromptEvidenceReceipt",
    "UnsafeEvidenceStoreError",
    "__version__",
]
