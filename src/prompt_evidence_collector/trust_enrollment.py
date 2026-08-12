"""Fail-closed enrollment of capture-authority public keys.

Enrollment is deliberately separate from key generation and signing.  The
collector accepts only a proposal approved by a key from its fixed, private,
host-local bootstrap trust file.  Callers cannot select another trust root.
"""

from __future__ import annotations

import base64
import binascii
import ctypes
import hashlib
import json
import os
import re
import secrets
import stat
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .authorization import (
    AUTHORITY_SOURCE_CODES,
    PURPOSE_CODES,
    TRUST_SCHEMA_V2,
    CaptureAuthorizationError,
    CaptureGrantVerifier,
    canonical_bytes,
    canonical_sha256,
    utc_text,
    validate_trust_key_shape,
)
from .collector import (
    PromptEvidenceCollector,
    UnsafeEvidenceStoreError,
    store_lifecycle_lock,
)

PROPOSAL_SCHEMA = "ellmos.prompt-evidence-trust-proposal.v1"
PLAN_SCHEMA = "ellmos.prompt-evidence-trust-enrollment-plan.v1"
ACTIVATION_SCHEMA = "ellmos.prompt-evidence-trust-activation.v1"
BOOTSTRAP_SCHEMA = "ellmos.prompt-evidence-bootstrap-trust.v1"
RESULT_SCHEMA = "ellmos.prompt-evidence-trust-enrollment-result.v1"
ROLLBACK_SCHEMA = "ellmos.prompt-evidence-trust-rollback-result.v1"
ACTION_CODE = "prompt-evidence.trust.activate"
DECISION_REF = "D-20260731-004"
BOOTSTRAP_DIR = "bootstrap"
BOOTSTRAP_FILE = "trust-activation-authorities.v1.json"
TRUST_DIR = "trust"
TRUST_FILE = "capture-authorities.v1.json"
PROVIDERS = {"clutch"}
SENSITIVITY_CODES = {"private", "restricted"}
RETENTION_CODES = {"session", "local-review", "until-curated", "legal-hold"}
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{1,127}$")
_FORBIDDEN_KEY_PARTS = ("private", "secret", "seed", "token", "password")


class TrustEnrollmentError(RuntimeError):
    """The proposal, activation, bootstrap trust, or apply state is invalid."""


def _closed(value: object, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise TrustEnrollmentError(f"{label} fields do not match the schema")
    return value


def _reject_private_material(value: object, *, label: str = "document") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise TrustEnrollmentError(f"{label} field name is invalid")
            folded = key.casefold().replace("-", "_")
            if any(part in folded for part in _FORBIDDEN_KEY_PARTS):
                raise TrustEnrollmentError(f"{label} contains forbidden private material")
            _reject_private_material(item, label=label)
    elif isinstance(value, list):
        for item in value:
            _reject_private_material(item, label=label)


def _utc(value: object, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith(("Z", "+00:00")):
        raise TrustEnrollmentError(f"{label} must be an explicit UTC timestamp")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as error:
        raise TrustEnrollmentError(f"{label} is invalid") from error
    if parsed.utcoffset() != UTC.utcoffset(parsed):
        raise TrustEnrollmentError(f"{label} must be UTC")
    return parsed


def _string_list(value: object, allowed: set[str], label: str) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or not all(isinstance(item, str) for item in value)
        or len(value) != len(set(value))
        or not set(value) <= allowed
    ):
        raise TrustEnrollmentError(f"{label} is invalid")
    return sorted(value)


def _id_list(value: object, label: str) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or not all(isinstance(item, str) and _ID.fullmatch(item) for item in value)
        or len(value) != len(set(value))
    ):
        raise TrustEnrollmentError(f"{label} is invalid")
    return sorted(value)


def _public_key(value: object, fingerprint: object, label: str) -> bytes:
    if not isinstance(value, str) or not isinstance(fingerprint, str) or not _SHA256.fullmatch(fingerprint):
        raise TrustEnrollmentError(f"{label} is invalid")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as error:
        raise TrustEnrollmentError(f"{label} is invalid") from error
    if len(decoded) != 32 or hashlib.sha256(decoded).hexdigest() != fingerprint:
        raise TrustEnrollmentError(f"{label} fingerprint mismatch")
    return decoded


@dataclass(frozen=True)
class TrustProposal:
    schema: str
    proposal_id: str
    action_code: str
    system_id: str
    host_id: str
    decision_ref: str
    issued_at: str
    not_before: str
    expires_at: str
    review_at: str
    constraints: dict[str, Any]
    keys: list[dict[str, Any]]

    @classmethod
    def from_dict(cls, value: object) -> TrustProposal:
        _reject_private_material(value, label="trust proposal")
        root = _closed(
            value,
            {
                "schema", "proposal_id", "action_code", "system_id", "host_id",
                "decision_ref", "issued_at", "not_before", "expires_at", "review_at",
                "constraints", "keys",
            },
            "trust proposal",
        )
        proposal = cls(**root)
        try:
            proposal.validate()
        except CaptureAuthorizationError as error:
            raise TrustEnrollmentError(str(error)) from error
        return proposal

    def unsigned_body(self) -> dict[str, Any]:
        value = asdict(self)
        value.pop("proposal_id")
        return value

    def validate(self) -> None:
        if self.schema != PROPOSAL_SCHEMA or self.action_code != ACTION_CODE:
            raise TrustEnrollmentError("unsupported trust proposal")
        for label, value in (("system ID", self.system_id), ("host ID", self.host_id)):
            if not isinstance(value, str) or not _ID.fullmatch(value):
                raise TrustEnrollmentError(f"{label} is invalid")
        if self.decision_ref != DECISION_REF:
            raise TrustEnrollmentError("trust proposal decision is not authorized")
        issued = _utc(self.issued_at, "proposal issued_at")
        not_before = _utc(self.not_before, "proposal not_before")
        review = _utc(self.review_at, "proposal review_at")
        expires = _utc(self.expires_at, "proposal expires_at")
        if not (issued <= not_before <= review <= expires):
            raise TrustEnrollmentError("trust proposal validity order is invalid")
        if expires - issued > timedelta(days=366):
            raise TrustEnrollmentError("trust proposal lifetime exceeds one year")

        constraints = _closed(
            self.constraints,
            {
                "provider_codes", "purpose_codes", "sensitivity_codes",
                "retention_codes", "max_grant_ttl_seconds", "one_shot", "max_captures",
            },
            "trust constraints",
        )
        _string_list(constraints["provider_codes"], PROVIDERS, "provider constraints")
        _string_list(constraints["purpose_codes"], PURPOSE_CODES, "purpose constraints")
        _string_list(
            constraints["sensitivity_codes"], SENSITIVITY_CODES, "sensitivity constraints"
        )
        _string_list(constraints["retention_codes"], RETENTION_CODES, "retention constraints")
        ttl = constraints["max_grant_ttl_seconds"]
        if type(ttl) is not int or not 1 <= ttl <= 3600:
            raise TrustEnrollmentError("grant TTL constraint is invalid")
        if constraints["one_shot"] is not True or constraints["max_captures"] != 1:
            raise TrustEnrollmentError("capture constraints must be one-shot")

        if not isinstance(self.keys, list) or len(self.keys) != 2:
            raise TrustEnrollmentError("exactly two trust keys are required")
        validated = [validate_trust_key_shape(item) for item in self.keys]
        fingerprints = [item["key_fingerprint"] for item in validated]
        if len(set(fingerprints)) != len(fingerprints):
            raise TrustEnrollmentError("duplicate trust key fingerprint")
        role_sets = {tuple(sorted(item["roles"])) for item in validated}
        if role_sets != {("capture-authority",), ("runtime-release",)}:
            raise TrustEnrollmentError("capture and runtime trust roles must use separate keys")
        if any(item["status"] != "active" for item in validated):
            raise TrustEnrollmentError("enrolled trust keys must be active")
        if any(not set(item["authority_source_codes"]) <= AUTHORITY_SOURCE_CODES for item in validated):
            raise TrustEnrollmentError("trust authority scope is invalid")
        capture_key = next(item for item in validated if item["roles"] == ["capture-authority"])
        runtime_key = next(item for item in validated if item["roles"] == ["runtime-release"])
        if not capture_key["authority_source_codes"] or runtime_key["authority_source_codes"]:
            raise TrustEnrollmentError("authority sources belong only to the capture key")
        if any(
            _utc(item["not_before"], "key not_before") > not_before
            or _utc(item["expires_at"], "key expires_at") < expires
            for item in validated
        ):
            raise TrustEnrollmentError("trust key validity does not cover the proposal")
        expected_id = "tp-" + canonical_sha256(self.unsigned_body())
        if self.proposal_id != expected_id:
            raise TrustEnrollmentError("trust proposal ID does not match its body")

    def trust_store(self) -> dict[str, Any]:
        return {
            "schema": TRUST_SCHEMA_V2,
            "keys": self.keys,
            "constraints": self.constraints,
        }


def build_plan(proposal: TrustProposal) -> dict[str, Any]:
    """Build a deterministic, path-free, key-value-free enrollment plan."""
    proposal = TrustProposal.from_dict(asdict(proposal))
    body = {
        "schema": PLAN_SCHEMA,
        "status": "ready-for-activation",
        "proposal_id": proposal.proposal_id,
        "action_code": proposal.action_code,
        "system_id": proposal.system_id,
        "host_id": proposal.host_id,
        "decision_ref": proposal.decision_ref,
        "trust_schema": TRUST_SCHEMA_V2,
        "constraints": proposal.constraints,
        "keys": [
            {
                "key_fingerprint": item["key_fingerprint"],
                "roles": sorted(item["roles"]),
                "authority_source_codes": sorted(item["authority_source_codes"]),
                "not_before": item["not_before"],
                "expires_at": item["expires_at"],
                "status": item["status"],
            }
            for item in sorted(proposal.keys, key=lambda item: item["key_fingerprint"])
        ],
    }
    return {**body, "plan_sha256": canonical_sha256(body)}


@dataclass(frozen=True)
class TrustActivation:
    schema: str
    activation_id: str
    action_code: str
    proposal_id: str
    plan_sha256: str
    system_id: str
    host_id: str
    decision_ref: str
    issuer_id: str
    issuer_key_fingerprint: str
    issued_at: str
    not_before: str
    review_at: str
    expires_at: str
    signature_algorithm: str
    signature: str

    @classmethod
    def from_dict(cls, value: object) -> TrustActivation:
        _reject_private_material(value, label="trust activation")
        root = _closed(value, set(cls.__dataclass_fields__), "trust activation")
        activation = cls(**root)
        activation.validate()
        return activation

    def unsigned_body(self) -> dict[str, Any]:
        value = asdict(self)
        value.pop("activation_id")
        value.pop("signature")
        return value

    def signing_bytes(self) -> bytes:
        return canonical_bytes({"activation_id": self.activation_id, "body": self.unsigned_body()})

    def validate(self) -> None:
        if self.schema != ACTIVATION_SCHEMA or self.action_code != ACTION_CODE:
            raise TrustEnrollmentError("unsupported trust activation")
        if self.decision_ref != DECISION_REF:
            raise TrustEnrollmentError("trust activation decision is not authorized")
        for label, value in (
            ("proposal ID", self.proposal_id), ("plan hash", self.plan_sha256),
            ("issuer fingerprint", self.issuer_key_fingerprint),
        ):
            pattern = re.compile(r"^tp-[0-9a-f]{64}$") if label == "proposal ID" else _SHA256
            if not isinstance(value, str) or not pattern.fullmatch(value):
                raise TrustEnrollmentError(f"{label} is invalid")
        for label, value in (("system ID", self.system_id), ("host ID", self.host_id), ("issuer ID", self.issuer_id)):
            if not isinstance(value, str) or not _ID.fullmatch(value):
                raise TrustEnrollmentError(f"{label} is invalid")
        issued = _utc(self.issued_at, "activation issued_at")
        not_before = _utc(self.not_before, "activation not_before")
        review = _utc(self.review_at, "activation review_at")
        expires = _utc(self.expires_at, "activation expires_at")
        if not (issued <= not_before <= review <= expires) or expires - issued > timedelta(days=31):
            raise TrustEnrollmentError("trust activation validity is invalid")
        if self.signature_algorithm != "ed25519":
            raise TrustEnrollmentError("unsupported trust activation signature")
        try:
            signature = base64.b64decode(self.signature, validate=True)
        except (ValueError, binascii.Error) as error:
            raise TrustEnrollmentError("trust activation signature is invalid") from error
        if len(signature) != 64:
            raise TrustEnrollmentError("trust activation signature is invalid")
        expected_id = "ta-" + canonical_sha256(self.unsigned_body())
        if self.activation_id != expected_id:
            raise TrustEnrollmentError("trust activation ID does not match its body")


class TrustEnroller:
    """Plan and apply trust enrollment against fixed host-local trust roots."""

    def __init__(self, store_root: Path) -> None:
        self.store_root = store_root.resolve(strict=True)
        self.bootstrap_path = self.store_root / BOOTSTRAP_DIR / BOOTSTRAP_FILE
        self.trust_dir = self.store_root / TRUST_DIR
        self.trust_path = self.trust_dir / TRUST_FILE

    def apply(
        self,
        *,
        proposal: TrustProposal,
        activation: TrustActivation,
        expected_plan_sha256: str,
        now: datetime,
    ) -> dict[str, Any]:
        proposal_snapshot = TrustProposal.from_dict(asdict(proposal))
        activation_snapshot = TrustActivation.from_dict(asdict(activation))
        with store_lifecycle_lock(self.store_root):
            return self._apply_locked(
                proposal=proposal_snapshot,
                activation=activation_snapshot,
                expected_plan_sha256=expected_plan_sha256,
                now=now,
            )

    def _apply_locked(
        self,
        *,
        proposal: TrustProposal,
        activation: TrustActivation,
        expected_plan_sha256: str,
        now: datetime,
    ) -> dict[str, Any]:
        plan = build_plan(proposal)
        if not _SHA256.fullmatch(expected_plan_sha256) or plan["plan_sha256"] != expected_plan_sha256:
            raise TrustEnrollmentError("expected plan hash does not match")
        self._validate_activation_binding(proposal, activation, expected_plan_sha256, now)
        issuer = self._load_bootstrap_issuer(activation, now)
        try:
            Ed25519PublicKey.from_public_bytes(issuer).verify(
                base64.b64decode(activation.signature, validate=True),
                activation.signing_bytes(),
            )
        except (InvalidSignature, ValueError, binascii.Error) as error:
            raise TrustEnrollmentError("trust activation signature verification failed") from error

        payload = json.dumps(
            proposal.trust_store(), ensure_ascii=False, sort_keys=True, indent=2
        ) + "\n"
        trust_sha256 = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        self._atomic_publish(payload, now=now)
        return {
            "schema": RESULT_SCHEMA,
            "status": "enrolled",
            "proposal_id": proposal.proposal_id,
            "activation_id": activation.activation_id,
            "plan_sha256": expected_plan_sha256,
            "trust_sha256": trust_sha256,
            "key_fingerprints": sorted(item["key_fingerprint"] for item in proposal.keys),
            "capture_active": False,
        }

    def rollback(self, *, expected_trust_sha256: str) -> dict[str, Any]:
        with store_lifecycle_lock(self.store_root):
            return self._rollback_locked(expected_trust_sha256=expected_trust_sha256)

    def _rollback_locked(self, *, expected_trust_sha256: str) -> dict[str, Any]:
        if not _SHA256.fullmatch(expected_trust_sha256):
            raise TrustEnrollmentError("expected trust hash is invalid")
        self._assert_no_capture_state()
        PromptEvidenceCollector._validate_private_store_child(self.trust_dir)
        PromptEvidenceCollector._validate_private_store_child(self.trust_path)
        current = hashlib.sha256(self.trust_path.read_bytes()).hexdigest()
        if current != expected_trust_sha256:
            raise TrustEnrollmentError("trust hash changed; key retirement is required")
        self._durable_remove_trust()
        try:
            self.trust_dir.rmdir()
            self._sync_directory(self.store_root)
        except OSError:
            pass
        return {
            "schema": ROLLBACK_SCHEMA,
            "status": "rolled-back-before-capture",
            "removed_trust_sha256": current,
            "capture_state_present": False,
        }

    def _validate_activation_binding(
        self,
        proposal: TrustProposal,
        activation: TrustActivation,
        plan_sha256: str,
        now: datetime,
    ) -> None:
        if (
            activation.proposal_id != proposal.proposal_id
            or activation.plan_sha256 != plan_sha256
            or activation.system_id != proposal.system_id
            or activation.host_id != proposal.host_id
            or activation.decision_ref != proposal.decision_ref
        ):
            raise TrustEnrollmentError("trust activation scope does not match the proposal")
        current = now.astimezone(UTC)
        if not (
            _utc(proposal.not_before, "proposal not_before") <= current <= _utc(proposal.expires_at, "proposal expires_at")
            and _utc(activation.not_before, "activation not_before") <= current <= _utc(activation.expires_at, "activation expires_at")
        ):
            raise TrustEnrollmentError("trust enrollment is not current")

    def _load_bootstrap_issuer(self, activation: TrustActivation, now: datetime) -> bytes:
        bootstrap_dir = self.bootstrap_path.parent
        PromptEvidenceCollector._validate_private_store_child(bootstrap_dir)
        PromptEvidenceCollector._validate_private_store_child(self.bootstrap_path)
        value = self._read_private_json(self.bootstrap_path, label="bootstrap trust store")
        _reject_private_material(value, label="bootstrap trust store")
        store = _closed(value, {"schema", "issuers"}, "bootstrap trust store")
        if store["schema"] != BOOTSTRAP_SCHEMA or not isinstance(store["issuers"], list):
            raise TrustEnrollmentError("bootstrap trust store schema is invalid")
        matches = []
        for raw in store["issuers"]:
            issuer = _closed(
                raw,
                {
                    "issuer_id", "key_fingerprint", "public_key_base64", "actions",
                    "decision_refs", "system_ids", "host_ids", "status", "not_before", "expires_at",
                },
                "bootstrap issuer",
            )
            if issuer["issuer_id"] == activation.issuer_id and issuer["key_fingerprint"] == activation.issuer_key_fingerprint:
                matches.append(issuer)
        if len(matches) != 1:
            raise TrustEnrollmentError("bootstrap activation issuer is not trusted")
        issuer = matches[0]
        if (
            issuer["status"] != "active"
            or ACTION_CODE not in _string_list(issuer["actions"], {ACTION_CODE}, "bootstrap actions")
            or DECISION_REF not in _string_list(issuer["decision_refs"], {DECISION_REF}, "bootstrap decisions")
            or activation.system_id not in _id_list(issuer["system_ids"], "bootstrap systems")
            or activation.host_id not in _id_list(issuer["host_ids"], "bootstrap hosts")
        ):
            raise TrustEnrollmentError("bootstrap activation issuer is out of scope")
        current = now.astimezone(UTC)
        if not (_utc(issuer["not_before"], "issuer not_before") <= current <= _utc(issuer["expires_at"], "issuer expires_at")):
            raise TrustEnrollmentError("bootstrap activation issuer is not current")
        return _public_key(issuer["public_key_base64"], issuer["key_fingerprint"], "bootstrap issuer key")

    def _atomic_publish(self, payload: str, *, now: datetime) -> None:
        if self.trust_path.exists():
            raise TrustEnrollmentError("capture trust store already exists")
        if self.trust_dir.exists():
            PromptEvidenceCollector._validate_private_store_child(self.trust_dir)
        else:
            if self.trust_dir.parent != self.store_root:
                raise UnsafeEvidenceStoreError("trust directory escaped its store")
            PromptEvidenceCollector._prepare_secure_store(self.trust_dir)
        temp = self.trust_dir / f".capture-authorities.{secrets.token_hex(16)}.tmp"
        published = False
        rollback_failed = False
        expected_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        try:
            descriptor = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload.encode("utf-8"))
                handle.flush()
                os.fsync(handle.fileno())
            PromptEvidenceCollector._restrict_private_store_child(temp)
            self._publish_no_replace(temp, self.trust_path)
            published = True
            # POSIX publication uses a no-replace hard link.  Publication is
            # committed as soon as the link exists; failure to remove the
            # private temporary alias must therefore never turn a successful
            # enrollment into an error while leaving active trust behind.
            cleanup_error: OSError | None = None
            for _ in range(2):
                try:
                    temp.unlink()
                    cleanup_error = None
                    break
                except FileNotFoundError:
                    cleanup_error = None
                    break
                except OSError as error:
                    cleanup_error = error
            if cleanup_error is not None:
                raise TrustEnrollmentError(
                    "published trust temporary alias cleanup failed"
                ) from cleanup_error
            self._sync_directory(self.trust_dir)
            PromptEvidenceCollector._validate_private_store_child(self.trust_path)
            if self.trust_path.read_text(encoding="utf-8") != payload:
                raise TrustEnrollmentError("capture trust store readback mismatch")
            CaptureGrantVerifier(
                self.store_root,
                private_path_validator=PromptEvidenceCollector._validate_private_store_child,
            ).preflight_trust_store(now=now)
        except FileExistsError as error:
            raise TrustEnrollmentError("capture trust store already exists") from error
        except Exception:
            if published:
                try:
                    actual_hash = hashlib.sha256(self.trust_path.read_bytes()).hexdigest()
                    if actual_hash != expected_hash:
                        rollback_failed = True
                        raise TrustEnrollmentError(
                            "recovery-required: published trust changed during rollback"
                        )
                    self._durable_remove_trust()
                except OSError as rollback_error:
                    rollback_failed = True
                    raise TrustEnrollmentError(
                        "recovery-required: published trust rollback failed"
                    ) from rollback_error
            raise
        finally:
            if not rollback_failed:
                try:
                    temp.unlink()
                except OSError:
                    # The target is the only active trust path.  A private hidden
                    # alias is inert and may be removed by a later hygiene pass.
                    pass

    @staticmethod
    def _sync_directory(directory: Path) -> None:
        """Persist directory-entry changes where the platform exposes fsync."""
        if os.name == "nt":
            return
        descriptor = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    @staticmethod
    def _publish_no_replace(source: Path, target: Path) -> None:
        """Publish atomically without replacement and request durable metadata."""
        if os.name != "nt":
            os.link(source, target)
            return
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.MoveFileExW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
        kernel32.MoveFileExW.restype = wintypes.BOOL
        movefile_write_through = 0x8
        if kernel32.MoveFileExW(str(source), str(target), movefile_write_through):
            return
        error_code = ctypes.get_last_error()
        if target.exists():
            raise FileExistsError(error_code, "capture trust store already exists", str(target))
        raise OSError(error_code, "atomic trust publication failed", str(target))

    def _durable_remove_trust(self) -> None:
        if os.name != "nt":
            self.trust_path.unlink()
            self._sync_directory(self.trust_dir)
            return
        from ctypes import wintypes

        tombstone = self.trust_dir / f".capture-authorities.{secrets.token_hex(16)}.retired"
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.MoveFileExW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
        kernel32.MoveFileExW.restype = wintypes.BOOL
        movefile_write_through = 0x8
        if not kernel32.MoveFileExW(
            str(self.trust_path), str(tombstone), movefile_write_through
        ):
            error_code = ctypes.get_last_error()
            raise OSError(error_code, "durable trust retirement failed", str(self.trust_path))
        try:
            tombstone.unlink()
        except OSError:
            # An inert, hidden tombstone is safer than restoring active trust.
            pass

    @staticmethod
    def _read_private_json(path: Path, *, label: str) -> object:
        PromptEvidenceCollector._validate_private_store_child(path)
        try:
            metadata = path.lstat()
            attributes = getattr(metadata, "st_file_attributes", 0)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_size <= 0
                or metadata.st_size > 1024 * 1024
                or path.is_symlink()
                or attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
            ):
                raise TrustEnrollmentError(f"{label} is not a bounded private file")
            with path.open("rb") as handle:
                opened = os.fstat(handle.fileno())
                if (
                    not stat.S_ISREG(opened.st_mode)
                    or opened.st_size != metadata.st_size
                    or opened.st_dev != metadata.st_dev
                    or (metadata.st_ino and opened.st_ino != metadata.st_ino)
                ):
                    raise TrustEnrollmentError(f"{label} changed before read")
                payload = handle.read(1024 * 1024 + 1)
            if len(payload) != metadata.st_size or len(payload) > 1024 * 1024:
                raise TrustEnrollmentError(f"{label} changed during read")
            return json.loads(payload.decode("utf-8"))
        except (OSError, ValueError, json.JSONDecodeError) as error:
            if isinstance(error, TrustEnrollmentError):
                raise
            raise TrustEnrollmentError(f"{label} is unavailable") from error

    def _assert_no_capture_state(self) -> None:
        candidates = [
            self.store_root / "capture-grants.sqlite3",
            self.store_root / "capture-staging",
            self.store_root / "consumption-receipts",
        ]
        if any(path.exists() for path in candidates):
            raise TrustEnrollmentError("capture state exists; signed key retirement is required")
        for directory in (self.store_root / "raw", self.store_root / "receipts"):
            if directory.exists() and any(directory.iterdir()):
                raise TrustEnrollmentError("evidence exists; signed key retirement is required")


def safe_failure(code: str, exit_code: int) -> dict[str, Any]:
    return {
        "schema": RESULT_SCHEMA,
        "status": "invalid",
        "code": code,
        "exit_code": exit_code,
    }


__all__ = [
    "ACTIVATION_SCHEMA", "BOOTSTRAP_SCHEMA", "PLAN_SCHEMA", "PROPOSAL_SCHEMA",
    "TrustActivation", "TrustEnroller", "TrustEnrollmentError", "TrustProposal",
    "build_plan", "safe_failure", "utc_text",
]
