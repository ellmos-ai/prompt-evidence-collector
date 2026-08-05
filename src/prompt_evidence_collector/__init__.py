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
from .trust_enrollment import (
    TrustActivation,
    TrustEnroller,
    TrustEnrollmentError,
    TrustProposal,
    build_plan as build_trust_enrollment_plan,
)

__version__ = "0.4.0"

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
    "TrustActivation",
    "TrustEnroller",
    "TrustEnrollmentError",
    "TrustProposal",
    "UnsafeEvidenceStoreError",
    "build_trust_enrollment_plan",
    "__version__",
]
