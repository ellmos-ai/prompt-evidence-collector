"""Standalone prompt evidence collector."""

from ._version import __version__
from .authorization import (
    AuthorizedCaptureResult,
    CaptureAuthorizationError,
    CaptureGrant,
    CaptureGrantReplayError,
    CaptureRecoveryRequiredError,
    ReadOnlyAuthorizationError,
    ResolverRuntimeReceipt,
)
from .collector import (
    AmbiguousEvidenceError,
    EvidenceIntegrityError,
    EvidenceNotFoundError,
    PromotionGate,
    PromotionGateError,
    PromptEvidenceCollector,
    PromptEvidenceError,
    PromptEvidenceLocatorLike,
    PromptEvidenceReceipt,
    UnsafeEvidenceStoreError,
)
from .trust_enrollment import (
    TrustActivation,
    TrustEnroller,
    TrustEnrollmentError,
    TrustProposal,
)
from .trust_enrollment import (
    build_plan as build_trust_enrollment_plan,
)

__all__ = [
    "AmbiguousEvidenceError",
    "AuthorizedCaptureResult",
    "CaptureAuthorizationError",
    "CaptureGrant",
    "CaptureGrantReplayError",
    "CaptureRecoveryRequiredError",
    "EvidenceIntegrityError",
    "EvidenceNotFoundError",
    "PromotionGate",
    "PromotionGateError",
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
    "__version__",
    "build_trust_enrollment_plan",
]
