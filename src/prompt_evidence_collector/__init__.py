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
from .authorization import (
    AuthorizedCaptureResult,
    CaptureAuthorizationError,
    CaptureGrant,
    CaptureGrantReplayError,
    CaptureRecoveryRequiredError,
    ResolverRuntimeReceipt,
)

__version__ = "0.3.0"

__all__ = [
    "AmbiguousEvidenceError",
    "AuthorizedCaptureResult",
    "CaptureAuthorizationError",
    "CaptureGrant",
    "CaptureGrantReplayError",
    "CaptureRecoveryRequiredError",
    "EvidenceIntegrityError",
    "EvidenceNotFoundError",
    "PromptEvidenceCollector",
    "PromptEvidenceError",
    "PromptEvidenceLocatorLike",
    "PromptEvidenceReceipt",
    "ResolverRuntimeReceipt",
    "UnsafeEvidenceStoreError",
    "__version__",
]
