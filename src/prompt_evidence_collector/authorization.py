"""Signed one-shot authorization for live prompt-evidence capture.

This module deliberately keeps authorization separate from evidence storage.
Unsigned caller claims, mutable resolver claims, and replayed grants fail closed.
"""

from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import importlib
import inspect
import json
import marshal
import os
import re
import secrets
import sqlite3
import stat
from contextlib import closing
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


class CaptureAuthorizationError(RuntimeError):
    """A capture grant or one of its trust bindings is invalid."""


class ReadOnlyAuthorizationError(CaptureAuthorizationError):
    """Stable, cloud-safe failure classification for read-only validation."""

    def __init__(self, message: str, *, code: str, exit_code: int) -> None:
        super().__init__(message)
        self.code = code
        self.exit_code = exit_code


class CaptureGrantReplayError(CaptureAuthorizationError):
    """A one-shot grant has already been reserved or consumed."""


class CaptureRecoveryRequiredError(CaptureAuthorizationError):
    """A prepared capture must be recovered before any further action."""


GRANT_SCHEMA = "ellmos.prompt-evidence-capture-grant.v1"
RUNTIME_SCHEMA = "ellmos.resolver-runtime-receipt.v1"
TRUST_SCHEMA = "ellmos.prompt-evidence-trust-store.v1"
TRUST_SCHEMA_V2 = "ellmos.prompt-evidence-trust-store.v2"
CONSUMPTION_SCHEMA = "ellmos.prompt-evidence-capture-consumption-receipt.v1"
ACTION_CODE = "prompt-evidence.capture"
PURPOSE_CODES = {
    "prompt-canonicalization",
    "workflow-extraction",
    "skill-extraction",
    "private-forensic-review",
}
AUTHORITY_SOURCE_CODES = {
    "explicit-user-decision",
    "explicit-capture-policy",
    "delegated-decision-avatar",
}
KEY_ROLES = {"capture-authority", "runtime-release"}
SENSITIVITY_CODES = {"private", "restricted"}
RETENTION_CODES = {"session", "local-review", "until-curated", "legal-hold"}
READ_ONLY_EXIT_INPUT_INVALID = 2
READ_ONLY_EXIT_TRUST_INVALID = 3
READ_ONLY_EXIT_SIGNATURE_INVALID = 4
READ_ONLY_EXIT_NOT_CURRENT = 5
READ_ONLY_EXIT_SCOPE_MISMATCH = 6
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_LOCATOR_ID = re.compile(r"^loc-[0-9a-f]{64}$")
_GRANT_ID = re.compile(r"^cg-[0-9a-f]{64}$")
_RUNTIME_ID = re.compile(r"^rr-[0-9a-f]{64}$")
_AUTHORITY_RECEIPT_ID = re.compile(r"^ar-[0-9a-f]{64}$")
_NONCE = re.compile(r"^[0-9a-f]{32}$")
_SYNC_PARTS = {
    ".sync",
    "box",
    "dropbox",
    "googledrive",
    "icloud",
    "onedrive",
    "sharepoint",
}


def canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _closed_mapping(value: object, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise CaptureAuthorizationError(f"{label} fields do not match the schema")
    return value


def _utc(value: object, label: str) -> datetime:
    if not isinstance(value, str) or not (
        value.endswith("Z") or value.endswith("+00:00")
    ):
        raise CaptureAuthorizationError(f"{label} must be an explicit UTC timestamp")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as error:
        raise CaptureAuthorizationError(f"{label} is invalid") from error
    if parsed.utcoffset() != UTC.utcoffset(parsed):
        raise CaptureAuthorizationError(f"{label} must be UTC")
    return parsed


def utc_text(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
        raise CaptureAuthorizationError("runtime clock must be UTC")
    return value.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _decode_base64(value: object, label: str, *, length: int | None = None) -> bytes:
    if not isinstance(value, str):
        raise CaptureAuthorizationError(f"{label} must be base64 text")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as error:
        raise CaptureAuthorizationError(f"{label} is invalid base64") from error
    if length is not None and len(decoded) != length:
        raise CaptureAuthorizationError(f"{label} has an invalid length")
    return decoded


def validate_trust_key_shape(value: object) -> dict[str, Any]:
    """Validate the exact V1 public trust-key record shared by all trust paths."""
    key = _closed_mapping(
        value,
        {
            "key_fingerprint",
            "public_key_base64",
            "roles",
            "authority_source_codes",
            "status",
            "not_before",
            "expires_at",
        },
        "trusted key",
    )
    fingerprint = key["key_fingerprint"]
    if not isinstance(fingerprint, str) or not _SHA256.fullmatch(fingerprint):
        raise CaptureAuthorizationError("trusted key fingerprint is invalid")
    public_bytes = _decode_base64(
        key["public_key_base64"],
        "trusted public key",
        length=32,
    )
    if hashlib.sha256(public_bytes).hexdigest() != fingerprint:
        raise CaptureAuthorizationError("trusted key fingerprint mismatch")
    roles = key["roles"]
    if (
        not isinstance(roles, list)
        or not roles
        or not all(isinstance(item, str) for item in roles)
        or len(roles) != len(set(roles))
        or not set(roles) <= KEY_ROLES
    ):
        raise CaptureAuthorizationError("trusted key roles are invalid")
    sources = key["authority_source_codes"]
    if (
        not isinstance(sources, list)
        or not all(isinstance(item, str) for item in sources)
        or len(sources) != len(set(sources))
        or not set(sources) <= AUTHORITY_SOURCE_CODES
    ):
        raise CaptureAuthorizationError("trusted key authority scopes are invalid")
    if not isinstance(key["status"], str) or not key["status"]:
        raise CaptureAuthorizationError("trusted key status is invalid")
    not_before = _utc(key["not_before"], "key not_before")
    expires_at = _utc(key["expires_at"], "key expires_at")
    if not_before > expires_at:
        raise CaptureAuthorizationError("trusted key validity order is invalid")
    return key


def validate_trust_constraints(value: object) -> dict[str, Any]:
    constraints = _closed_mapping(
        value,
        {
            "provider_codes",
            "purpose_codes",
            "sensitivity_codes",
            "retention_codes",
            "max_grant_ttl_seconds",
            "one_shot",
            "max_captures",
        },
        "trust constraints",
    )
    allowed = {
        "provider_codes": {"clutch"},
        "purpose_codes": PURPOSE_CODES,
        "sensitivity_codes": SENSITIVITY_CODES,
        "retention_codes": RETENTION_CODES,
    }
    for field, values in allowed.items():
        selected = constraints[field]
        if (
            not isinstance(selected, list)
            or not selected
            or not all(isinstance(item, str) for item in selected)
            or len(selected) != len(set(selected))
            or not set(selected) <= values
        ):
            raise CaptureAuthorizationError(f"trusted {field} are invalid")
    ttl = constraints["max_grant_ttl_seconds"]
    if type(ttl) is not int or not 1 <= ttl <= 3600:
        raise CaptureAuthorizationError("trusted grant TTL is invalid")
    if constraints["one_shot"] is not True or constraints["max_captures"] != 1:
        raise CaptureAuthorizationError("trusted capture cardinality is invalid")
    return constraints


@dataclass(frozen=True)
class CaptureGrant:
    schema: str
    grant_id: str
    action_code: str
    provider_code: str
    purpose_code: str
    locator: dict[str, Any]
    capture_policy: dict[str, Any]
    resolver_binding: dict[str, Any]
    authority: dict[str, Any]
    issued_at: str
    not_before: str
    expires_at: str
    one_shot: bool
    max_captures: int
    nonce: str
    signature_algorithm: str
    signature: str

    @classmethod
    def from_dict(cls, value: object) -> CaptureGrant:
        root = copy.deepcopy(_closed_mapping(
            value,
            {
                "schema",
                "grant_id",
                "action_code",
                "provider_code",
                "purpose_code",
                "locator",
                "capture_policy",
                "resolver_binding",
                "authority",
                "issued_at",
                "not_before",
                "expires_at",
                "one_shot",
                "max_captures",
                "nonce",
                "signature_algorithm",
                "signature",
            },
            "capture grant",
        ))
        grant = cls(**root)
        grant.validate_structure()
        return grant

    def unsigned_body(self) -> dict[str, Any]:
        value = asdict(self)
        value.pop("grant_id")
        value.pop("signature")
        return value

    def signing_bytes(self) -> bytes:
        return canonical_bytes(
            {"grant_id": self.grant_id, "body": self.unsigned_body()}
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def validate_structure(self) -> None:
        if self.schema != GRANT_SCHEMA or self.action_code != ACTION_CODE:
            raise CaptureAuthorizationError("unsupported capture grant schema or action")
        if self.provider_code != "clutch":
            raise CaptureAuthorizationError("capture grant provider is not supported")
        if self.purpose_code not in PURPOSE_CODES:
            raise CaptureAuthorizationError("unsupported capture purpose")
        if (
            self.one_shot is not True
            or type(self.max_captures) is not int
            or self.max_captures != 1
        ):
            raise CaptureAuthorizationError("capture grant must be strictly one-shot")
        if not isinstance(self.nonce, str) or not _NONCE.fullmatch(self.nonce):
            raise CaptureAuthorizationError("capture grant nonce is invalid")
        if self.signature_algorithm != "ed25519":
            raise CaptureAuthorizationError("unsupported capture grant signature")
        _decode_base64(self.signature, "capture grant signature", length=64)

        locator = _closed_mapping(
            self.locator,
            {"schema", "locator_id", "content_hash"},
            "capture grant locator",
        )
        if locator["schema"] != "ellmos.prompt-evidence-locator.v2":
            raise CaptureAuthorizationError("unsupported locator schema")
        if not isinstance(locator["locator_id"], str) or not _LOCATOR_ID.fullmatch(
            locator["locator_id"]
        ):
            raise CaptureAuthorizationError("capture grant locator is invalid")
        if not isinstance(locator["content_hash"], str) or not _SHA256.fullmatch(
            locator["content_hash"]
        ):
            raise CaptureAuthorizationError("capture grant content hash is invalid")

        policy = _closed_mapping(
            self.capture_policy,
            {"sensitivity_code", "retention_code", "promotion_status"},
            "capture policy",
        )
        if policy["sensitivity_code"] not in {"private", "restricted"}:
            raise CaptureAuthorizationError("unsupported capture sensitivity")
        if policy["retention_code"] not in {
            "session",
            "local-review",
            "until-curated",
            "legal-hold",
        }:
            raise CaptureAuthorizationError("unsupported capture retention")
        if policy["promotion_status"] != "not-reviewed":
            raise CaptureAuthorizationError("capture grant cannot authorize promotion")

        resolver = _closed_mapping(
            self.resolver_binding,
            {
                "component_code",
                "source_pin",
                "adapter_sha256",
                "runtime_receipt_sha256",
            },
            "resolver binding",
        )
        if resolver["component_code"] != "clutch":
            raise CaptureAuthorizationError("capture resolver must be Clutch")
        if not isinstance(resolver["source_pin"], str) or not _COMMIT.fullmatch(
            resolver["source_pin"]
        ):
            raise CaptureAuthorizationError("resolver source pin is invalid")
        for key in ("adapter_sha256", "runtime_receipt_sha256"):
            if not isinstance(resolver[key], str) or not _SHA256.fullmatch(resolver[key]):
                raise CaptureAuthorizationError(f"resolver {key} is invalid")

        authority = _closed_mapping(
            self.authority,
            {
                "source_code",
                "source_ref_hash",
                "source_content_hash",
                "resolution_receipt_id",
                "resolution_receipt_sha256",
                "issuer_key_fingerprint",
            },
            "capture authority",
        )
        if authority["source_code"] not in AUTHORITY_SOURCE_CODES:
            raise CaptureAuthorizationError("capture authority source is unsupported")
        for key in (
            "source_ref_hash",
            "source_content_hash",
            "resolution_receipt_sha256",
            "issuer_key_fingerprint",
        ):
            if not isinstance(authority[key], str) or not _SHA256.fullmatch(
                authority[key]
            ):
                raise CaptureAuthorizationError(f"capture authority {key} is invalid")
        if not isinstance(
            authority["resolution_receipt_id"], str
        ) or not _AUTHORITY_RECEIPT_ID.fullmatch(authority["resolution_receipt_id"]):
            raise CaptureAuthorizationError("authority resolution receipt ID is invalid")

        issued = _utc(self.issued_at, "issued_at")
        not_before = _utc(self.not_before, "not_before")
        expires = _utc(self.expires_at, "expires_at")
        if not (issued <= not_before <= expires):
            raise CaptureAuthorizationError("capture grant validity order is invalid")
        if expires - issued > timedelta(hours=1):
            raise CaptureAuthorizationError("capture grant lifetime exceeds one hour")
        expected_id = "cg-" + canonical_sha256(self.unsigned_body())
        if not _GRANT_ID.fullmatch(self.grant_id) or self.grant_id != expected_id:
            raise CaptureAuthorizationError("capture grant ID does not match its body")


@dataclass(frozen=True)
class ResolverRuntimeReceipt:
    schema: str
    receipt_id: str
    component_code: str
    source_pin: str
    adapter_sha256: str
    module_id: str
    qualname: str
    callable_sha256: str
    immutable: bool
    dirty: bool
    issued_at: str
    expires_at: str
    issuer_key_fingerprint: str
    signature_algorithm: str
    signature: str

    @classmethod
    def from_dict(cls, value: object) -> ResolverRuntimeReceipt:
        root = copy.deepcopy(_closed_mapping(
            value,
            {
                "schema",
                "receipt_id",
                "component_code",
                "source_pin",
                "adapter_sha256",
                "module_id",
                "qualname",
                "callable_sha256",
                "immutable",
                "dirty",
                "issued_at",
                "expires_at",
                "issuer_key_fingerprint",
                "signature_algorithm",
                "signature",
            },
            "resolver runtime receipt",
        ))
        receipt = cls(**root)
        receipt.validate_structure()
        return receipt

    def unsigned_body(self) -> dict[str, Any]:
        value = asdict(self)
        value.pop("receipt_id")
        value.pop("signature")
        return value

    def signing_bytes(self) -> bytes:
        return canonical_bytes(
            {"receipt_id": self.receipt_id, "body": self.unsigned_body()}
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def validate_structure(self) -> None:
        if self.schema != RUNTIME_SCHEMA or self.component_code != "clutch":
            raise CaptureAuthorizationError("unsupported resolver runtime receipt")
        if not isinstance(self.source_pin, str) or not _COMMIT.fullmatch(self.source_pin):
            raise CaptureAuthorizationError("runtime source pin is invalid")
        for label, value in (
            ("adapter hash", self.adapter_sha256),
            ("callable hash", self.callable_sha256),
            ("issuer fingerprint", self.issuer_key_fingerprint),
        ):
            if not isinstance(value, str) or not _SHA256.fullmatch(value):
                raise CaptureAuthorizationError(f"runtime {label} is invalid")
        if not isinstance(self.module_id, str) or not re.fullmatch(
            r"^[A-Za-z_][A-Za-z0-9_.]*$", self.module_id
        ):
            raise CaptureAuthorizationError("runtime module ID is invalid")
        if not isinstance(self.qualname, str) or not re.fullmatch(
            r"^[A-Za-z_][A-Za-z0-9_.]*$", self.qualname
        ):
            raise CaptureAuthorizationError("runtime callable qualname is invalid")
        if self.immutable is not True or self.dirty is not False:
            raise CaptureAuthorizationError("resolver runtime is mutable or dirty")
        issued = _utc(self.issued_at, "runtime issued_at")
        expires = _utc(self.expires_at, "runtime expires_at")
        if issued > expires or expires - issued > timedelta(days=31):
            raise CaptureAuthorizationError("runtime receipt validity is invalid")
        if self.signature_algorithm != "ed25519":
            raise CaptureAuthorizationError("unsupported runtime signature")
        _decode_base64(self.signature, "runtime signature", length=64)
        expected_id = "rr-" + canonical_sha256(self.unsigned_body())
        if not _RUNTIME_ID.fullmatch(self.receipt_id) or self.receipt_id != expected_id:
            raise CaptureAuthorizationError("runtime receipt ID does not match its body")


@dataclass(frozen=True)
class AuthorizedCaptureResult:
    evidence_receipt: Any
    consumption_receipt: dict[str, Any]


@dataclass(frozen=True, slots=True)
class VerifiedCaptureContext:
    locator: SignedLocatorSnapshot
    resolver: Callable[[Any], str]


class CaptureGrantVerifier:
    """Verifies signed grants and resolver releases against a private trust store."""

    TRUST_FILE = "capture-authorities.v1.json"

    def __init__(
        self,
        store_root: Path,
        *,
        private_path_validator: Callable[[Path], None] | None = None,
    ) -> None:
        self.store_root = store_root.resolve(strict=True)
        self.trust_dir = self.store_root / "trust"
        self._private_path_validator = private_path_validator

    def verify(
        self,
        *,
        grant: CaptureGrant,
        runtime_receipt: ResolverRuntimeReceipt,
        locator: Any,
        now: datetime,
    ) -> VerifiedCaptureContext:
        self.validate_signed_authorization(
            grant=grant,
            runtime_receipt=runtime_receipt,
            now=now,
        )

        try:
            locator_values = {
                "schema": locator.schema,
                "provider_code": locator.provider_code,
                "locator_id": locator.locator_id,
                "content_hash": locator.content_hash,
            }
        except (AttributeError, TypeError) as error:
            raise CaptureAuthorizationError("locator lacks authorization fields") from error
        if locator_values != {
            "schema": grant.locator["schema"],
            "provider_code": grant.provider_code,
            "locator_id": grant.locator["locator_id"],
            "content_hash": grant.locator["content_hash"],
        }:
            raise CaptureAuthorizationError("locator does not match the signed grant")

        binding = grant.resolver_binding
        resolver = load_registered_resolver(runtime_receipt)
        self._verify_resolver_code(
            resolver,
            adapter_sha256=binding["adapter_sha256"],
            module_id=runtime_receipt.module_id,
            qualname=runtime_receipt.qualname,
            callable_sha256=runtime_receipt.callable_sha256,
        )
        return VerifiedCaptureContext(
            locator=SignedLocatorSnapshot(
                schema=grant.locator["schema"],
                provider_code=grant.provider_code,
                locator_id=grant.locator["locator_id"],
                source_uri=(
                    "clutch-local://evidence/" + grant.locator["locator_id"]
                ),
                content_hash=grant.locator["content_hash"],
            ),
            resolver=resolver,
        )

    def preflight_trust_store(self, *, now: datetime) -> dict[str, Any]:
        """Validate the private trust store without resolving or mutating anything."""
        current = now.astimezone(UTC)
        try:
            trust = self._load_trust_store()
        except CaptureAuthorizationError as error:
            raise ReadOnlyAuthorizationError(
                str(error),
                code="trust-store-invalid",
                exit_code=READ_ONLY_EXIT_TRUST_INVALID,
            ) from error

        safe_keys: list[dict[str, Any]] = []
        for raw_key in trust["keys"]:
            try:
                if not isinstance(raw_key, dict):
                    raise CaptureAuthorizationError("trusted key fields do not match the schema")
                fingerprint = raw_key.get("key_fingerprint")
                roles = raw_key.get("roles")
                if not isinstance(fingerprint, str) or not isinstance(roles, list) or not roles:
                    raise CaptureAuthorizationError("trusted key roles are invalid")
                validated = None
                for role in roles:
                    validated = self._trusted_key(
                        trust=trust,
                        fingerprint=fingerprint,
                        role=role,
                        authority_source=None,
                        now=current,
                    )
                assert validated is not None
            except CaptureAuthorizationError as error:
                raise self._classified_error(error, default_code="trust-store-invalid") from error
            safe_keys.append(
                {
                    "key_fingerprint": validated["key_fingerprint"],
                    "roles": sorted(validated["roles"]),
                    "authority_source_codes": sorted(validated["authority_source_codes"]),
                    "status": validated["status"],
                    "ttl_seconds": max(
                        0,
                        int((_utc(validated["expires_at"], "key expires_at") - current).total_seconds()),
                    ),
                }
            )
        return {
            "schema": "ellmos.prompt-evidence-trust-preflight.v1",
            "status": "valid",
            "code": "trust-store-valid",
            "trust_schema": trust["schema"],
            "key_count": len(safe_keys),
            "keys": safe_keys,
        }

    def validate_signed_authorization(
        self,
        *,
        grant: CaptureGrant,
        runtime_receipt: ResolverRuntimeReceipt,
        now: datetime,
    ) -> dict[str, Any]:
        """Pure validation of trust, signatures, time bounds, and resolver binding.

        This method deliberately does not resolve a locator, import resolver code,
        touch the one-shot ledger, capture evidence, call hooks, or use a network.
        """
        try:
            grant.validate_structure()
            runtime_receipt.validate_structure()
        except CaptureAuthorizationError as error:
            raise ReadOnlyAuthorizationError(
                str(error),
                code="input-invalid",
                exit_code=READ_ONLY_EXIT_INPUT_INVALID,
            ) from error

        current = now.astimezone(UTC)
        if not (
            _utc(grant.not_before, "not_before")
            <= current
            <= _utc(grant.expires_at, "expires_at")
        ):
            raise ReadOnlyAuthorizationError(
                "capture grant is not currently valid",
                code="authorization-not-current",
                exit_code=READ_ONLY_EXIT_NOT_CURRENT,
            )
        if not (
            _utc(runtime_receipt.issued_at, "runtime issued_at")
            <= current
            <= _utc(runtime_receipt.expires_at, "runtime expires_at")
        ):
            raise ReadOnlyAuthorizationError(
                "resolver runtime receipt is not current",
                code="runtime-not-current",
                exit_code=READ_ONLY_EXIT_NOT_CURRENT,
            )

        try:
            trust = self._load_trust_store()
        except CaptureAuthorizationError as error:
            raise ReadOnlyAuthorizationError(
                str(error),
                code="trust-store-invalid",
                exit_code=READ_ONLY_EXIT_TRUST_INVALID,
            ) from error
        try:
            self._validate_grant_constraints(trust=trust, grant=grant)
        except CaptureAuthorizationError as error:
            raise ReadOnlyAuthorizationError(
                str(error),
                code="scope-mismatch",
                exit_code=READ_ONLY_EXIT_SCOPE_MISMATCH,
            ) from error
        try:
            self._verify_signed_object(
                trust=trust,
                fingerprint=grant.authority["issuer_key_fingerprint"],
                role="capture-authority",
                authority_source=grant.authority["source_code"],
                signature=grant.signature,
                signing_bytes=grant.signing_bytes(),
                now=current,
            )
            self._verify_signed_object(
                trust=trust,
                fingerprint=runtime_receipt.issuer_key_fingerprint,
                role="runtime-release",
                authority_source=None,
                signature=runtime_receipt.signature,
                signing_bytes=runtime_receipt.signing_bytes(),
                now=current,
            )
        except CaptureAuthorizationError as error:
            raise self._classified_error(error, default_code="trust-store-invalid") from error

        binding = grant.resolver_binding
        if (
            runtime_receipt.component_code != binding["component_code"]
            or runtime_receipt.source_pin != binding["source_pin"]
            or runtime_receipt.adapter_sha256 != binding["adapter_sha256"]
            or canonical_sha256(runtime_receipt.to_dict())
            != binding["runtime_receipt_sha256"]
        ):
            raise ReadOnlyAuthorizationError(
                "resolver runtime does not match the grant",
                code="scope-mismatch",
                exit_code=READ_ONLY_EXIT_SCOPE_MISMATCH,
            )

        return {
            "schema": "ellmos.prompt-evidence-authorization-validation.v1",
            "status": "valid",
            "code": "authorization-valid",
            "grant": {
                "grant_id": grant.grant_id,
                "action_code": grant.action_code,
                "provider_code": grant.provider_code,
                "purpose_code": grant.purpose_code,
                "locator_id": grant.locator["locator_id"],
                "content_hash": grant.locator["content_hash"],
                "sensitivity_code": grant.capture_policy["sensitivity_code"],
                "retention_code": grant.capture_policy["retention_code"],
                "promotion_status": grant.capture_policy["promotion_status"],
                "authority_source_code": grant.authority["source_code"],
                "ttl_seconds": max(
                    0,
                    int((_utc(grant.expires_at, "expires_at") - current).total_seconds()),
                ),
            },
            "runtime": {
                "receipt_id": runtime_receipt.receipt_id,
                "component_code": runtime_receipt.component_code,
                "source_pin": runtime_receipt.source_pin,
                "adapter_sha256": runtime_receipt.adapter_sha256,
                "callable_sha256": runtime_receipt.callable_sha256,
                "immutable": runtime_receipt.immutable,
                "ttl_seconds": max(
                    0,
                    int(
                        (
                            _utc(runtime_receipt.expires_at, "runtime expires_at")
                            - current
                        ).total_seconds()
                    ),
                ),
            },
            "binding": {
                "runtime_receipt_sha256": binding["runtime_receipt_sha256"],
                "status": "matched",
            },
            "trust": {
                "schema": trust["schema"],
                "authority_key_fingerprint": grant.authority["issuer_key_fingerprint"],
                "runtime_key_fingerprint": runtime_receipt.issuer_key_fingerprint,
                "status": "verified",
            },
        }

    @staticmethod
    def _classified_error(
        error: CaptureAuthorizationError,
        *,
        default_code: str,
    ) -> ReadOnlyAuthorizationError:
        message = str(error)
        if "signature verification failed" in message:
            return ReadOnlyAuthorizationError(
                message,
                code="signature-invalid",
                exit_code=READ_ONLY_EXIT_SIGNATURE_INVALID,
            )
        if "not current" in message:
            return ReadOnlyAuthorizationError(
                message,
                code="authorization-not-current",
                exit_code=READ_ONLY_EXIT_NOT_CURRENT,
            )
        if "mis-scoped" in message or "cannot issue this authority source" in message:
            return ReadOnlyAuthorizationError(
                message,
                code="scope-mismatch",
                exit_code=READ_ONLY_EXIT_SCOPE_MISMATCH,
            )
        return ReadOnlyAuthorizationError(
            message,
            code=default_code,
            exit_code=READ_ONLY_EXIT_TRUST_INVALID,
        )

    def _verify_signed_object(
        self,
        *,
        trust: dict[str, Any],
        fingerprint: str,
        role: str,
        authority_source: str | None,
        signature: str,
        signing_bytes: bytes,
        now: datetime,
    ) -> None:
        key = self._trusted_key(
            trust=trust,
            fingerprint=fingerprint,
            role=role,
            authority_source=authority_source,
            now=now,
        )
        public_bytes = _decode_base64(
            key["public_key_base64"],
            "trusted public key",
            length=32,
        )
        try:
            Ed25519PublicKey.from_public_bytes(public_bytes).verify(
                _decode_base64(signature, "signature", length=64),
                signing_bytes,
            )
        except InvalidSignature as error:
            raise CaptureAuthorizationError("signature verification failed") from error

    def _trusted_key(
        self,
        *,
        trust: dict[str, Any],
        fingerprint: str,
        role: str,
        authority_source: str | None,
        now: datetime,
    ) -> dict[str, Any]:
        matches = [
            item
            for item in trust["keys"]
            if isinstance(item, dict) and item.get("key_fingerprint") == fingerprint
        ]
        if len(matches) != 1:
            raise CaptureAuthorizationError("trusted issuer key is missing or ambiguous")
        key = self._validate_trust_key_shape(matches[0])
        if key["status"] != "active" or role not in key["roles"]:
            raise CaptureAuthorizationError("trusted issuer key is inactive or mis-scoped")
        if (
            authority_source is not None
            and authority_source not in key["authority_source_codes"]
        ):
            raise CaptureAuthorizationError("trusted key cannot issue this authority source")
        if not (
            _utc(key["not_before"], "key not_before")
            <= now
            <= _utc(key["expires_at"], "key expires_at")
        ):
            raise CaptureAuthorizationError("trusted issuer key is not current")
        return key

    def _load_trust_store(self) -> dict[str, Any]:
        trust_dir = self.trust_dir
        path = trust_dir / self.TRUST_FILE
        try:
            metadata = path.lstat()
            attributes = getattr(metadata, "st_file_attributes", 0)
            if (
                trust_dir.is_symlink()
                or path.is_symlink()
                or metadata.st_nlink != 1
                or attributes
                & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
            ):
                raise CaptureAuthorizationError("capture trust store is a symlink")
            resolved_dir = trust_dir.resolve(strict=True)
            resolved_path = path.resolve(strict=True)
            resolved_path.relative_to(resolved_dir)
            if resolved_dir.parent != self.store_root or not resolved_path.is_file():
                raise CaptureAuthorizationError("capture trust store escaped its root")
            if self._private_path_validator is not None:
                self._private_path_validator(resolved_dir)
                self._private_path_validator(resolved_path)
            elif os.name == "nt":
                raise CaptureAuthorizationError(
                    "capture trust security validator is unavailable"
                )
            elif (
                stat.S_IMODE(resolved_dir.stat().st_mode) & 0o077
                or stat.S_IMODE(resolved_path.stat().st_mode) & 0o077
            ):
                raise CaptureAuthorizationError("capture trust store is not private")
            value = json.loads(resolved_path.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError) as error:
            if isinstance(error, CaptureAuthorizationError):
                raise
            raise CaptureAuthorizationError("capture trust store is unavailable") from error
        if not isinstance(value, dict):
            raise CaptureAuthorizationError("capture trust store schema is invalid")
        schema = value.get("schema")
        if schema == TRUST_SCHEMA:
            trust = _closed_mapping(value, {"schema", "keys"}, "capture trust store")
        elif schema == TRUST_SCHEMA_V2:
            trust = _closed_mapping(
                value,
                {"schema", "keys", "constraints"},
                "capture trust store",
            )
            trust["constraints"] = validate_trust_constraints(trust["constraints"])
        else:
            raise CaptureAuthorizationError("capture trust store schema is invalid")
        if not isinstance(trust["keys"], list):
            raise CaptureAuthorizationError("capture trust store schema is invalid")
        validated_keys = [self._validate_trust_key_shape(item) for item in trust["keys"]]
        fingerprints = [item["key_fingerprint"] for item in validated_keys]
        if len(fingerprints) != len(set(fingerprints)):
            raise CaptureAuthorizationError("trusted issuer key is missing or ambiguous")
        trust["keys"] = validated_keys
        return trust

    @staticmethod
    def _validate_grant_constraints(
        *, trust: dict[str, Any], grant: CaptureGrant
    ) -> None:
        if trust["schema"] == TRUST_SCHEMA:
            return
        constraints = validate_trust_constraints(trust["constraints"])
        policy = grant.capture_policy
        issued = _utc(grant.issued_at, "issued_at")
        expires = _utc(grant.expires_at, "expires_at")
        if (
            grant.provider_code not in constraints["provider_codes"]
            or grant.purpose_code not in constraints["purpose_codes"]
            or policy["sensitivity_code"] not in constraints["sensitivity_codes"]
            or policy["retention_code"] not in constraints["retention_codes"]
            or int((expires - issued).total_seconds())
            > constraints["max_grant_ttl_seconds"]
            or grant.one_shot is not constraints["one_shot"]
            or grant.max_captures != constraints["max_captures"]
        ):
            raise CaptureAuthorizationError("capture grant exceeds trusted constraints")

    @staticmethod
    def _validate_trust_key_shape(value: object) -> dict[str, Any]:
        return validate_trust_key_shape(value)

    @staticmethod
    def _verify_resolver_code(
        resolver: Callable[[Any], str],
        *,
        adapter_sha256: str,
        module_id: str,
        qualname: str,
        callable_sha256: str,
    ) -> None:
        target, source = resolver_identity(resolver)
        if target.__module__ != module_id or target.__qualname__ != qualname:
            raise CaptureAuthorizationError("resolver callable identity mismatch")
        if not source:
            raise CaptureAuthorizationError("resolver source is unavailable")
        path = Path(source)
        try:
            if path.is_symlink():
                raise CaptureAuthorizationError("resolver source is a symlink")
            resolved = path.resolve(strict=True)
        except OSError as error:
            raise CaptureAuthorizationError("resolver source is unavailable") from error
        if any(part.casefold() in _SYNC_PARTS for part in resolved.parts):
            raise CaptureAuthorizationError("resolver source is inside a sync root")
        if hashlib.sha256(resolved.read_bytes()).hexdigest() != adapter_sha256:
            raise CaptureAuthorizationError("resolver adapter hash mismatch")
        if callable_fingerprint(resolver) != callable_sha256:
            raise CaptureAuthorizationError("resolver callable hash mismatch")


@dataclass(frozen=True, slots=True)
class SignedLocatorSnapshot:
    schema: str
    provider_code: str
    locator_id: str
    source_uri: str
    content_hash: str


def resolver_identity(resolver: Callable[[Any], str]) -> tuple[Any, str]:
    if not inspect.isfunction(resolver):
        raise CaptureAuthorizationError("resolver must be an exact registered function")
    target = resolver
    if target.__closure__:
        raise CaptureAuthorizationError("resolver closures are forbidden")
    source = inspect.getsourcefile(target)
    if not source:
        raise CaptureAuthorizationError("resolver source is unavailable")
    return target, source


_REGISTERED_RESOLVERS = {
    "clutch": (
        "prompt_evidence_collector.adapters.clutch",
        "resolve_content",
    ),
}


def load_registered_resolver(
    runtime_receipt: ResolverRuntimeReceipt,
) -> Callable[[Any], str]:
    """Resolve a fixed package-owned adapter; callers cannot inject code."""
    expected = _REGISTERED_RESOLVERS.get(runtime_receipt.component_code)
    if expected != (runtime_receipt.module_id, runtime_receipt.qualname):
        raise CaptureAuthorizationError("resolver is not in the internal registry")
    try:
        module = importlib.import_module(runtime_receipt.module_id)
        resolver = getattr(module, runtime_receipt.qualname)
    except (ImportError, AttributeError) as error:
        raise CaptureAuthorizationError("registered resolver is unavailable") from error
    if not inspect.isfunction(resolver):
        raise CaptureAuthorizationError("registered resolver export is not a function")
    return resolver


def callable_fingerprint(resolver: Callable[[Any], str]) -> str:
    target, _ = resolver_identity(resolver)
    module = inspect.getmodule(target)
    if module is None or module.__name__ != target.__module__:
        raise CaptureAuthorizationError("resolver module identity is unavailable")
    globals_projection: list[dict[str, str]] = []
    for name in sorted(set(target.__code__.co_names)):
        if name not in module.__dict__:
            continue
        value = module.__dict__[name]
        if inspect.isfunction(value):
            item = {
                "name": name,
                "kind": "function",
                "module": value.__module__,
                "qualname": value.__qualname__,
                "code_sha256": hashlib.sha256(
                    marshal.dumps(value.__code__)
                ).hexdigest(),
            }
        elif inspect.isclass(value):
            item = {
                "name": name,
                "kind": "class",
                "module": value.__module__,
                "qualname": value.__qualname__,
            }
        elif inspect.ismodule(value):
            item = {"name": name, "kind": "module", "module": value.__name__}
        elif isinstance(value, (str, int, float, bool, type(None))):
            item = {
                "name": name,
                "kind": "constant",
                "value_sha256": canonical_sha256(value),
            }
        else:
            item = {
                "name": name,
                "kind": "object",
                "module": type(value).__module__,
                "qualname": type(value).__qualname__,
            }
        globals_projection.append(item)
    return canonical_sha256(
        {
            "module_id": target.__module__,
            "qualname": target.__qualname__,
            "code_sha256": hashlib.sha256(
                marshal.dumps(target.__code__)
            ).hexdigest(),
            "referenced_globals": globals_projection,
        }
    )


class CaptureGrantLedger:
    """Private SQLite one-shot ledger. Every reservation is terminal."""

    def __init__(self, store_root: Path) -> None:
        self.store_root = store_root.resolve(strict=True)
        self.path = self.store_root / "capture-grants.sqlite3"
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        if self.path.parent.resolve(strict=True) != self.store_root:
            raise CaptureAuthorizationError("capture grant ledger escaped its root")
        if self.path.exists():
            metadata = self.path.lstat()
            attributes = getattr(metadata, "st_file_attributes", 0)
            if (
                self.path.is_symlink()
                or metadata.st_nlink != 1
                or attributes
                & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
            ):
                raise CaptureAuthorizationError("capture grant ledger is not private")
        connection = sqlite3.connect(str(self.path), timeout=10, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 10000")
        connection.execute("PRAGMA journal_mode = DELETE")
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    def _initialize(self) -> None:
        try:
            with closing(self._connect()) as connection:
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS capture_grants (
                      grant_id TEXT PRIMARY KEY,
                      grant_hash TEXT NOT NULL,
                      state TEXT NOT NULL CHECK(state IN ('reserved','prepared','consumed','failed')),
                      reserved_at TEXT NOT NULL,
                      finished_at TEXT,
                      evidence_id TEXT,
                      attempt_id TEXT NOT NULL,
                      consumption_receipt_json TEXT
                    )
                    """
                )
                self._validate_schema(connection)
        except sqlite3.Error as error:
            raise CaptureAuthorizationError("capture grant ledger is unavailable") from error
        if os.name != "nt":
            os.chmod(self.path, 0o600)

    @staticmethod
    def _validate_schema(connection: sqlite3.Connection) -> None:
        columns = connection.execute(
            "PRAGMA table_info(capture_grants)"
        ).fetchall()
        observed = [(row["name"], row["type"], row["pk"]) for row in columns]
        expected = [
            ("grant_id", "TEXT", 1),
            ("grant_hash", "TEXT", 0),
            ("state", "TEXT", 0),
            ("reserved_at", "TEXT", 0),
            ("finished_at", "TEXT", 0),
            ("evidence_id", "TEXT", 0),
            ("attempt_id", "TEXT", 0),
            ("consumption_receipt_json", "TEXT", 0),
        ]
        triggers = connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'trigger'"
        ).fetchall()
        if observed != expected or triggers:
            raise CaptureAuthorizationError("capture grant ledger schema is unsafe")

    def reserve(
        self,
        *,
        grant_id: str,
        grant_hash: str,
        reserved_at: str,
        attempt_id: str,
    ) -> None:
        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    """INSERT INTO capture_grants
                       (grant_id, grant_hash, state, reserved_at, attempt_id)
                       VALUES (?, ?, 'reserved', ?, ?)""",
                    (grant_id, grant_hash, reserved_at, attempt_id),
                )
                connection.commit()
        except sqlite3.IntegrityError as error:
            raise CaptureGrantReplayError("capture grant was already reserved") from error
        except sqlite3.Error as error:
            raise CaptureAuthorizationError("capture grant reservation failed") from error

    def prepare(
        self,
        *,
        grant_id: str,
        finished_at: str,
        evidence_id: str,
        consumption_receipt: dict[str, Any],
    ) -> None:
        self._transition(
            grant_id=grant_id,
            source="reserved",
            target="prepared",
            finished_at=finished_at,
            evidence_id=evidence_id,
            consumption_receipt_json=json.dumps(
                consumption_receipt,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ),
        )

    def consume_prepared(self, *, grant_id: str, finished_at: str) -> None:
        record = self.record(grant_id)
        if record is None or record["state"] != "prepared":
            raise CaptureAuthorizationError("capture grant is not prepared")
        self._transition(
            grant_id=grant_id,
            source="prepared",
            target="consumed",
            finished_at=finished_at,
            evidence_id=str(record["evidence_id"]),
            consumption_receipt_json=str(record["consumption_receipt_json"]),
        )

    def fail_if_reserved(self, *, grant_id: str, finished_at: str) -> None:
        try:
            self._transition(
                grant_id=grant_id,
                source="reserved",
                target="failed",
                finished_at=finished_at,
                evidence_id=None,
                consumption_receipt_json=None,
            )
        except CaptureAuthorizationError:
            if self.state(grant_id) != "consumed":
                raise

    def _transition(
        self,
        *,
        grant_id: str,
        source: str,
        target: str,
        finished_at: str,
        evidence_id: str | None,
        consumption_receipt_json: str | None,
    ) -> None:
        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                cursor = connection.execute(
                    """UPDATE capture_grants
                       SET state = ?, finished_at = ?, evidence_id = ?,
                           consumption_receipt_json = ?
                       WHERE grant_id = ? AND state = ?""",
                    (
                        target,
                        finished_at,
                        evidence_id,
                        consumption_receipt_json,
                        grant_id,
                        source,
                    ),
                )
                if cursor.rowcount != 1:
                    connection.rollback()
                    raise CaptureAuthorizationError(
                        f"capture grant is not in the {source} state"
                    )
                connection.commit()
        except sqlite3.Error as error:
            raise CaptureAuthorizationError("capture grant ledger update failed") from error

    def state(self, grant_id: str) -> str | None:
        try:
            with closing(self._connect()) as connection:
                row = connection.execute(
                    "SELECT state FROM capture_grants WHERE grant_id = ?",
                    (grant_id,),
                ).fetchone()
        except sqlite3.Error as error:
            raise CaptureAuthorizationError("capture grant ledger read failed") from error
        return str(row["state"]) if row else None

    def record(self, grant_id: str) -> dict[str, Any] | None:
        try:
            with closing(self._connect()) as connection:
                row = connection.execute(
                    "SELECT * FROM capture_grants WHERE grant_id = ?",
                    (grant_id,),
                ).fetchone()
        except sqlite3.Error as error:
            raise CaptureAuthorizationError("capture grant ledger read failed") from error
        return dict(row) if row else None


def build_consumption_receipt(
    *,
    grant: CaptureGrant,
    runtime_receipt: ResolverRuntimeReceipt,
    evidence_id: str,
    consumed_at: str,
) -> dict[str, Any]:
    body = {
        "schema": CONSUMPTION_SCHEMA,
        "grant_id": grant.grant_id,
        "evidence_id": evidence_id,
        "provider_code": grant.provider_code,
        "purpose_code": grant.purpose_code,
        "authority_source_code": grant.authority["source_code"],
        "authority_ref_hash": grant.authority["source_ref_hash"],
        "locator_id": grant.locator["locator_id"],
        "content_hash": grant.locator["content_hash"],
        "resolver_component_code": runtime_receipt.component_code,
        "resolver_source_pin": runtime_receipt.source_pin,
        "resolver_adapter_sha256": runtime_receipt.adapter_sha256,
        "runtime_receipt_sha256": grant.resolver_binding[
            "runtime_receipt_sha256"
        ],
        "issued_at": grant.issued_at,
        "expires_at": grant.expires_at,
        "consumed_at": consumed_at,
        "one_shot": True,
        "consumption_status": "consumed",
        "promotion_status": "not-reviewed",
    }
    return body | {"receipt_sha256": canonical_sha256(body)}


def attempt_id(grant_id: str, now: str) -> str:
    material = "\n".join((grant_id, now, secrets.token_hex(16)))
    return "attempt-" + hashlib.sha256(material.encode("utf-8")).hexdigest()
