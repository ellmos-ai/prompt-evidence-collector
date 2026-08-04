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
    ReadOnlyAuthorizationError,
    ResolverRuntimeReceipt,
)

__version__ = "0.3.1"

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
    "ReadOnlyAuthorizationError",
    "ResolverRuntimeReceipt",
    "UnsafeEvidenceStoreError",
    "__version__",
]
