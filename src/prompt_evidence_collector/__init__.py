"""Standalone prompt evidence collector."""

from .collector import (
    AmbiguousEvidenceError,
    EvidenceIntegrityError,
    EvidenceNotFoundError,
    PromptEvidenceCollector,
    PromptEvidenceError,
    PromptEvidenceReceipt,
    UnsafeEvidenceStoreError,
)

__version__ = "0.1.0"

__all__ = [
    "AmbiguousEvidenceError",
    "EvidenceIntegrityError",
    "EvidenceNotFoundError",
    "PromptEvidenceCollector",
    "PromptEvidenceError",
    "PromptEvidenceReceipt",
    "UnsafeEvidenceStoreError",
    "__version__",
]
