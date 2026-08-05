"""Standalone prompt evidence collector (extracted from ellmos-core).

Host-private Prompt-Evidence mit strikt redigierten Receipts."""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import re
import stat
import subprocess
from contextlib import contextmanager
from dataclasses import asdict, dataclass, fields
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Protocol
from uuid import UUID

from .authorization import (
    AuthorizedCaptureResult,
    CaptureGrant,
    CaptureGrantLedger,
    CaptureGrantVerifier,
    CaptureRecoveryRequiredError,
    ResolverRuntimeReceipt,
    attempt_id,
    build_consumption_receipt,
    utc_text,
)


class PromptEvidenceError(RuntimeError):
    """Basisklasse für sichere Collector-Fehler."""


class UnsafeEvidenceStoreError(PromptEvidenceError):
    """Der Store ist nicht als app-eigen und host-private belegbar."""


class EvidenceNotFoundError(PromptEvidenceError):
    """Keine Evidence erfüllt die exakten Kriterien."""


class AmbiguousEvidenceError(PromptEvidenceError):
    """Mehrere Evidence-Receipts erfüllen die Kriterien."""


class EvidenceIntegrityError(PromptEvidenceError):
    """Receipt, Hash und Rohspeicher stimmen nicht überein."""


class PromptEvidenceLocatorLike(Protocol):
    """Minimaler Locatorvertrag für den passiven Clutch-Consumer."""

    schema: str
    provider_code: str
    locator_id: str
    source_uri: str
    content_hash: str


_PROVIDERS = {"anthropic", "clutch", "google", "kimi", "ollama", "openai"}
_ORIGINS = {"clutch-session-store", "provider-session-event", "local-import"}
_SENSITIVITY = {"private", "restricted"}
_RETENTION = {"session", "local-review", "until-curated", "legal-hold"}
_PROMOTION = {"not-reviewed", "rejected", "candidate", "curated"}
_OPAQUE_ID = re.compile(r"^(?:pe|loc)-[0-9a-f]{64}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_UTC_TIMESTAMP = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
    r"(?:\.\d{1,6})?(?:Z|\+00:00)$"
)


@contextmanager
def store_lifecycle_lock(root: Path):
    """Cross-process, filesystem-free lock for trust and capture lifecycle."""
    resolved = root.resolve(strict=True)
    lock_id = hashlib.sha256(str(resolved).casefold().encode("utf-8")).hexdigest()
    if os.name == "nt":
        from ctypes import wintypes

        # Global namespace makes the lifecycle lock effective across desktop,
        # RDP, scheduled-task and service sessions on the same Windows host.
        # The kernel object's default DACL is inherited from the creating
        # process token; no permissive NULL security descriptor is supplied.
        name = f"Global\\ellmos-prompt-evidence-{lock_id}"
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
        kernel32.CreateMutexW.restype = wintypes.HANDLE
        kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        kernel32.WaitForSingleObject.restype = wintypes.DWORD
        kernel32.ReleaseMutex.argtypes = [wintypes.HANDLE]
        kernel32.ReleaseMutex.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        handle = kernel32.CreateMutexW(None, False, name)
        if not handle:
            raise UnsafeEvidenceStoreError("failed to create lifecycle mutex")
        acquired = False
        try:
            result = kernel32.WaitForSingleObject(handle, 30_000)
            if result not in {0, 0x80}:  # WAIT_OBJECT_0, WAIT_ABANDONED
                raise UnsafeEvidenceStoreError("lifecycle mutex is unavailable")
            acquired = True
            yield
        finally:
            if acquired:
                kernel32.ReleaseMutex(handle)
            kernel32.CloseHandle(handle)
    else:
        import fcntl

        descriptor = os.open(resolved, os.O_RDONLY)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)


_SYNC_PARTS = {
    ".sync",
    "box",
    "dropbox",
    "googledrive",
    "icloud",
    "onedrive",
    "sharepoint",
}


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class PromptEvidenceReceipt:
    """Cloud-safe Receipt: feste Codes sowie opaque IDs und Hashes."""

    schema: str
    evidence_id: str
    provider_code: str
    origin_code: str
    captured_at: str
    content_hash: str
    sensitivity_code: str
    retention_code: str
    raw_object_id: str
    promotion_status: str
    source_locator_id: str | None
    source_content_hash: str | None

    def __post_init__(self) -> None:
        if self.schema != PromptEvidenceCollector.SCHEMA:
            raise EvidenceIntegrityError(
                "unsupported prompt evidence receipt schema"
            )
        if not isinstance(self.evidence_id, str) or not re.fullmatch(
            r"^pe-[0-9a-f]{64}$",
            self.evidence_id,
        ):
            raise EvidenceIntegrityError("invalid prompt evidence identifier")
        try:
            PromptEvidenceCollector._validate_codes(
                provider_code=self.provider_code,
                origin_code=self.origin_code,
                sensitivity_code=self.sensitivity_code,
                retention_code=self.retention_code,
                promotion_status=self.promotion_status,
            )
            _validate_utc_timestamp(self.captured_at)
        except ValueError as error:
            raise EvidenceIntegrityError(
                "invalid prompt evidence receipt code or timestamp"
            ) from error
        if not isinstance(self.content_hash, str) or not _SHA256.fullmatch(
            self.content_hash
        ):
            raise EvidenceIntegrityError(
                "prompt evidence content hash must be lowercase sha256"
            )
        if self.raw_object_id != self.evidence_id:
            raise EvidenceIntegrityError(
                "raw object identifier must equal evidence identifier"
            )
        if (self.source_locator_id is None) != (
            self.source_content_hash is None
        ):
            raise EvidenceIntegrityError(
                "source locator ID and hash must be supplied together"
            )
        if self.source_locator_id is not None and (
            not isinstance(self.source_locator_id, str)
            or not re.fullmatch(
                r"^loc-[0-9a-f]{64}$",
                self.source_locator_id,
            )
        ):
            raise EvidenceIntegrityError(
                "source locator must be an opaque loc-<sha256> ID"
            )
        if self.source_content_hash is not None and (
            not isinstance(self.source_content_hash, str)
            or not _SHA256.fullmatch(self.source_content_hash)
        ):
            raise EvidenceIntegrityError(
                "source content hash must be lowercase sha256"
            )
        expected_id = _prompt_evidence_id(
            provider_code=self.provider_code,
            origin_code=self.origin_code,
            captured_at=self.captured_at,
            source_locator_id=self.source_locator_id,
            source_content_hash=self.source_content_hash,
            content_hash=self.content_hash,
        )
        if self.evidence_id != expected_id:
            raise EvidenceIntegrityError(
                "prompt evidence identifier does not match receipt content"
            )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class PromptEvidenceCollector:
    """Speichert Rohtext ausschließlich im app-eigenen Local-Data-Root."""

    SCHEMA = "ellmos.prompt-evidence-receipt.v2"
    APP_DIR = "prompt-evidence-collector"
    STORE_DIR = "prompt-evidence"

    def __init__(self) -> None:
        self.root = self._app_store_root()
        self._prepare_secure_store(self.root)
        self.raw_dir = self.root / "raw"
        self.receipt_dir = self.root / "receipts"
        self.raw_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.receipt_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._store_root = self.root.resolve(strict=True)
        self._raw_root = self.raw_dir.resolve(strict=True)
        self._receipt_root = self.receipt_dir.resolve(strict=True)
        self._validate_current_store()

    def _capture(
        self,
        *,
        provider_code: str,
        origin_code: str,
        captured_at: str,
        raw_content: str,
        sensitivity_code: str,
        retention_code: str,
        source_locator_id: str | None = None,
        source_content_hash: str | None = None,
        promotion_status: str = "not-reviewed",
    ) -> PromptEvidenceReceipt:
        """Erfasst Rohtext; das zurückgegebene Receipt bleibt cloud-safe."""
        receipt = self._build_evidence_receipt(
            provider_code=provider_code,
            origin_code=origin_code,
            captured_at=captured_at,
            raw_content=raw_content,
            sensitivity_code=sensitivity_code,
            retention_code=retention_code,
            source_locator_id=source_locator_id,
            source_content_hash=source_content_hash,
            promotion_status=promotion_status,
        )
        self._write_once(
            self.raw_dir / f"{receipt.evidence_id}.txt",
            raw_content,
            expected_parent=self._raw_root,
            suffix=".txt",
        )
        self._write_once(
            self.receipt_dir / f"{receipt.evidence_id}.json",
            json.dumps(receipt.to_dict(), ensure_ascii=False, sort_keys=True, indent=2),
            expected_parent=self._receipt_root,
            suffix=".json",
        )
        return receipt

    def _build_evidence_receipt(
        self,
        *,
        provider_code: str,
        origin_code: str,
        captured_at: str,
        raw_content: str,
        sensitivity_code: str,
        retention_code: str,
        source_locator_id: str | None = None,
        source_content_hash: str | None = None,
        promotion_status: str = "not-reviewed",
    ) -> PromptEvidenceReceipt:
        """Validate capture data and build a receipt without filesystem writes."""
        self._validate_current_store()
        self._validate_codes(
            provider_code=provider_code,
            origin_code=origin_code,
            sensitivity_code=sensitivity_code,
            retention_code=retention_code,
            promotion_status=promotion_status,
        )
        _validate_utc_timestamp(captured_at)
        if not isinstance(raw_content, str) or not raw_content:
            raise ValueError("raw_content must be a non-empty string")
        if (source_locator_id is None) != (source_content_hash is None):
            raise ValueError("source locator ID and hash must be supplied together")
        if source_locator_id is not None and not _OPAQUE_ID.fullmatch(source_locator_id):
            raise ValueError("source locator must be an opaque loc-<sha256> ID")
        if source_content_hash is not None and not _SHA256.fullmatch(source_content_hash):
            raise ValueError("source content hash must be lowercase sha256")

        content_hash = _sha256(raw_content)
        evidence_id = _prompt_evidence_id(
            provider_code=provider_code,
            origin_code=origin_code,
            captured_at=captured_at,
            source_locator_id=source_locator_id,
            source_content_hash=source_content_hash,
            content_hash=content_hash,
        )
        return PromptEvidenceReceipt(
            schema=self.SCHEMA,
            evidence_id=evidence_id,
            provider_code=provider_code,
            origin_code=origin_code,
            captured_at=captured_at,
            content_hash=content_hash,
            sensitivity_code=sensitivity_code,
            retention_code=retention_code,
            raw_object_id=evidence_id,
            promotion_status=promotion_status,
            source_locator_id=source_locator_id,
            source_content_hash=source_content_hash,
        )

    def _capture_from_locator(
        self,
        *,
        locator: PromptEvidenceLocatorLike,
        resolve_content: Callable[[PromptEvidenceLocatorLike], str],
        captured_at: str,
        sensitivity_code: str,
        retention_code: str,
        promotion_status: str = "not-reviewed",
    ) -> PromptEvidenceReceipt:
        """Löst einen geprüften Clutch-Locator lokal auf und erfasst ihn passiv.

        Der Aufrufer stellt den lokalen Resolver bereit. Der Collector öffnet
        weder Netzwerkverbindungen noch Provider-Datenbanken und aktiviert
        keinen Hintergrundlauf. Schema, URI und Hash werden vor dem Write
        fail-closed geprüft. Diese Low-Level-API ist ausschließlich für lokale
        Imports und isolierte Tests bestimmt. Live-Capture muss
        ``authorize_and_capture_from_locator`` verwenden.
        """
        self._validate_current_store()
        self._validate_codes(
            provider_code="clutch",
            origin_code="clutch-session-store",
            sensitivity_code=sensitivity_code,
            retention_code=retention_code,
            promotion_status=promotion_status,
        )
        _validate_utc_timestamp(captured_at)
        if not callable(resolve_content):
            raise ValueError("resolve_content must be callable")

        self._validate_clutch_locator(locator)
        raw_content = self._resolve_locator_content(locator, resolve_content)

        return self._capture(
            provider_code="clutch",
            origin_code="clutch-session-store",
            captured_at=captured_at,
            raw_content=raw_content,
            sensitivity_code=sensitivity_code,
            retention_code=retention_code,
            source_locator_id=locator.locator_id,
            source_content_hash=locator.content_hash,
            promotion_status=promotion_status,
        )

    def authorize_and_capture_from_locator(
        self,
        *,
        locator: PromptEvidenceLocatorLike,
        grant: CaptureGrant | dict[str, Any],
        resolver_runtime_receipt: ResolverRuntimeReceipt | dict[str, Any],
    ) -> AuthorizedCaptureResult:
        """Serialize trust verification, replay reservation, and capture lifecycle."""
        with store_lifecycle_lock(self._store_root):
            return self._authorize_and_capture_from_locator_locked(
                locator=locator,
                grant=grant,
                resolver_runtime_receipt=resolver_runtime_receipt,
            )

    def _authorize_and_capture_from_locator_locked(
        self,
        *,
        locator: PromptEvidenceLocatorLike,
        grant: CaptureGrant | dict[str, Any],
        resolver_runtime_receipt: ResolverRuntimeReceipt | dict[str, Any],
    ) -> AuthorizedCaptureResult:
        """Erfasst genau einen Locator mit signiertem, one-shot Grant.

        Der Grant und das immutable Resolver-Receipt werden gegen den privaten
        lokalen Trust-Store geprüft. Die Replay-Reservierung erfolgt atomar vor
        dem ersten Resolveraufruf. Prediction oder ein caller-supplied Claim
        allein erteilen keine Autorität.
        """
        parsed_grant = CaptureGrant.from_dict(
            grant.to_dict() if isinstance(grant, CaptureGrant) else grant
        )
        runtime_receipt = ResolverRuntimeReceipt.from_dict(
            resolver_runtime_receipt.to_dict()
            if isinstance(resolver_runtime_receipt, ResolverRuntimeReceipt)
            else resolver_runtime_receipt
        )
        now = datetime.now(UTC)
        captured_at = utc_text(now)
        self._validate_current_store()
        verifier = CaptureGrantVerifier(
            self._store_root,
            private_path_validator=self._validate_private_store_child,
        )
        verified = verifier.verify(
            grant=parsed_grant,
            runtime_receipt=runtime_receipt,
            locator=locator,
            now=now,
        )

        ledger = CaptureGrantLedger(self._store_root)
        capture_attempt_id = attempt_id(parsed_grant.grant_id, captured_at)
        ledger.reserve(
            grant_id=parsed_grant.grant_id,
            grant_hash=hashlib.sha256(
                json.dumps(
                    parsed_grant.to_dict(),
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest(),
            reserved_at=captured_at,
            attempt_id=capture_attempt_id,
        )
        stage: Path | None = None
        try:
            policy = parsed_grant.capture_policy
            raw_content = self._resolve_locator_content(
                verified.locator,
                verified.resolver,
            )
            evidence_receipt = self._build_evidence_receipt(
                provider_code="clutch",
                origin_code="clutch-session-store",
                captured_at=captured_at,
                raw_content=raw_content,
                sensitivity_code=policy["sensitivity_code"],
                retention_code=policy["retention_code"],
                source_locator_id=verified.locator.locator_id,
                source_content_hash=verified.locator.content_hash,
                promotion_status=policy["promotion_status"],
            )
            consumption_receipt = build_consumption_receipt(
                grant=parsed_grant,
                runtime_receipt=runtime_receipt,
                evidence_id=evidence_receipt.evidence_id,
                consumed_at=captured_at,
            )
            stage = self._stage_authorized_capture(
                attempt_id_value=capture_attempt_id,
                raw_content=raw_content,
                evidence_receipt=evidence_receipt,
                grant_id=parsed_grant.grant_id,
                consumption_receipt=consumption_receipt,
            )
            ledger.prepare(
                grant_id=parsed_grant.grant_id,
                finished_at=captured_at,
                evidence_id=evidence_receipt.evidence_id,
                consumption_receipt=consumption_receipt,
            )
            self._publish_authorized_stage(
                stage=stage,
                evidence_receipt=evidence_receipt,
                grant_id=parsed_grant.grant_id,
                consumption_receipt=consumption_receipt,
            )
            ledger.consume_prepared(
                grant_id=parsed_grant.grant_id,
                finished_at=captured_at,
            )
            self._cleanup_stage(stage)
            return AuthorizedCaptureResult(
                evidence_receipt=evidence_receipt,
                consumption_receipt=consumption_receipt,
            )
        except Exception as error:
            if ledger.state(parsed_grant.grant_id) == "prepared":
                raise CaptureRecoveryRequiredError(
                    "authorized capture is prepared and requires recovery"
                ) from error
            ledger.fail_if_reserved(
                grant_id=parsed_grant.grant_id,
                finished_at=captured_at,
            )
            if stage is not None:
                self._cleanup_stage(stage)
            raise

    @staticmethod
    def _resolve_locator_content(
        locator: PromptEvidenceLocatorLike,
        resolver: Callable[[PromptEvidenceLocatorLike], str],
    ) -> str:
        try:
            raw_content = resolver(locator)
        except Exception as error:
            raise EvidenceNotFoundError(
                "prompt evidence locator could not be resolved locally"
            ) from error
        if not isinstance(raw_content, str) or not raw_content:
            raise EvidenceNotFoundError(
                "prompt evidence locator resolved to no local content"
            )
        if _sha256(raw_content) != locator.content_hash:
            raise EvidenceIntegrityError(
                "prompt evidence locator content hash mismatch"
            )
        return raw_content

    def _write_consumption_receipt(
        self,
        grant_id: str,
        receipt: dict[str, Any],
    ) -> None:
        if not re.fullmatch(r"^cg-[0-9a-f]{64}$", grant_id):
            raise EvidenceIntegrityError("invalid capture grant identifier")
        directory = self._store_root / "consumption-receipts"
        self._reject_sync_and_reparse(directory)
        directory.mkdir(mode=0o700, parents=False, exist_ok=True)
        if directory.is_symlink() or directory.resolve(strict=True).parent != self._store_root:
            raise UnsafeEvidenceStoreError("capture receipt directory escaped its root")
        if os.name != "nt":
            os.chmod(directory, 0o700)
        path = directory / f"{grant_id}.json"
        payload = json.dumps(
            receipt,
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
        ) + "\n"
        try:
            with path.open("x", encoding="utf-8", newline="\n") as handle:
                handle.write(payload)
            if os.name != "nt":
                os.chmod(path, 0o600)
        except FileExistsError:
            try:
                if path.read_text(encoding="utf-8") != payload:
                    raise EvidenceIntegrityError(
                        "existing capture consumption receipt conflicts"
                    )
            except OSError as error:
                raise EvidenceIntegrityError(
                    "capture consumption receipt cannot be read"
                ) from error
        metadata = path.lstat()
        attributes = getattr(metadata, "st_file_attributes", 0)
        if (
            path.is_symlink()
            or metadata.st_nlink != 1
            or attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
            or path.resolve(strict=True).parent != directory.resolve(strict=True)
        ):
            raise EvidenceIntegrityError("capture consumption receipt escaped its root")

    def _stage_authorized_capture(
        self,
        *,
        attempt_id_value: str,
        raw_content: str,
        evidence_receipt: PromptEvidenceReceipt,
        grant_id: str,
        consumption_receipt: dict[str, Any],
    ) -> Path:
        if not re.fullmatch(r"^attempt-[0-9a-f]{64}$", attempt_id_value):
            raise EvidenceIntegrityError("invalid capture attempt identifier")
        stage_root = self._store_root / "capture-staging"
        self._reject_sync_and_reparse(stage_root)
        stage_root.mkdir(mode=0o700, parents=False, exist_ok=True)
        if stage_root.is_symlink() or stage_root.resolve(strict=True).parent != self._store_root:
            raise UnsafeEvidenceStoreError("capture staging root escaped its store")
        if os.name != "nt":
            os.chmod(stage_root, 0o700)
        stage = stage_root / attempt_id_value
        try:
            stage.mkdir(mode=0o700, parents=False, exist_ok=False)
            payloads = {
                "raw.txt": raw_content,
                "evidence.json": json.dumps(
                    evidence_receipt.to_dict(),
                    ensure_ascii=False,
                    sort_keys=True,
                    indent=2,
                ),
                "consumption.json": json.dumps(
                    consumption_receipt,
                    ensure_ascii=False,
                    sort_keys=True,
                    indent=2,
                ) + "\n",
                "binding.json": json.dumps(
                    {
                        "grant_id": grant_id,
                        "evidence_id": evidence_receipt.evidence_id,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ),
            }
            for name, payload in payloads.items():
                path = stage / name
                with path.open("x", encoding="utf-8", newline="\n") as handle:
                    handle.write(payload)
                    handle.flush()
                    os.fsync(handle.fileno())
                if os.name != "nt":
                    os.chmod(path, 0o600)
            return stage
        except Exception:
            if stage.exists() and stage.parent == stage_root:
                self._cleanup_stage(stage)
            raise

    def _load_authorized_stage(
        self,
        *,
        stage: Path,
        grant_id: str,
        evidence_id: str | None,
        expected_consumption: dict[str, Any] | None,
    ) -> tuple[str, PromptEvidenceReceipt, dict[str, Any]]:
        stage_root = self._store_root / "capture-staging"
        if stage.parent != stage_root or stage.is_symlink():
            raise EvidenceIntegrityError("capture stage escaped its root")
        resolved_stage = stage.resolve(strict=True)
        if resolved_stage.parent != stage_root.resolve(strict=True):
            raise EvidenceIntegrityError("capture stage escaped its root")
        expected_names = {"raw.txt", "evidence.json", "consumption.json", "binding.json"}
        if {path.name for path in stage.iterdir()} != expected_names:
            raise EvidenceIntegrityError("capture stage contents are incomplete")
        for path in stage.iterdir():
            metadata = path.lstat()
            attributes = getattr(metadata, "st_file_attributes", 0)
            if (
                path.is_symlink()
                or not path.is_file()
                or metadata.st_nlink != 1
                or attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
            ):
                raise EvidenceIntegrityError("capture stage contains an unsafe object")
        try:
            raw_content = (stage / "raw.txt").read_text(encoding="utf-8")
            evidence_value = json.loads((stage / "evidence.json").read_text(encoding="utf-8"))
            consumption_value = json.loads(
                (stage / "consumption.json").read_text(encoding="utf-8")
            )
            binding = json.loads((stage / "binding.json").read_text(encoding="utf-8"))
            receipt = PromptEvidenceReceipt(**evidence_value)
        except (OSError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise EvidenceIntegrityError("capture stage is invalid") from error
        if not isinstance(binding, dict) or set(binding) != {"grant_id", "evidence_id"}:
            raise EvidenceIntegrityError("capture stage binding mismatch")
        bound_evidence_id = binding["evidence_id"]
        if binding["grant_id"] != grant_id or not isinstance(
            bound_evidence_id, str
        ) or not re.fullmatch(r"^pe-[0-9a-f]{64}$", bound_evidence_id):
            raise EvidenceIntegrityError("capture stage binding mismatch")
        if evidence_id is not None and bound_evidence_id != evidence_id:
            raise EvidenceIntegrityError("capture stage evidence binding mismatch")
        if receipt.evidence_id != bound_evidence_id:
            raise EvidenceIntegrityError("capture stage receipt mismatch")
        if not isinstance(consumption_value, dict):
            raise EvidenceIntegrityError("capture stage consumption receipt is invalid")
        receipt_hash = consumption_value.get("receipt_sha256")
        consumption_body = dict(consumption_value)
        consumption_body.pop("receipt_sha256", None)
        if (
            receipt_hash != hashlib.sha256(
                json.dumps(
                    consumption_body,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest()
            or consumption_value.get("grant_id") != grant_id
            or consumption_value.get("evidence_id") != bound_evidence_id
        ):
            raise EvidenceIntegrityError("capture stage consumption receipt is invalid")
        if expected_consumption is not None and consumption_value != expected_consumption:
            raise EvidenceIntegrityError("capture stage consumption receipt mismatch")
        if _sha256(raw_content) != receipt.content_hash:
            raise EvidenceIntegrityError("capture stage raw hash mismatch")
        return raw_content, receipt, consumption_value

    def _publish_authorized_stage(
        self,
        *,
        stage: Path,
        evidence_receipt: PromptEvidenceReceipt,
        grant_id: str,
        consumption_receipt: dict[str, Any],
    ) -> None:
        raw_content, staged_receipt, _ = self._load_authorized_stage(
            stage=stage,
            grant_id=grant_id,
            evidence_id=evidence_receipt.evidence_id,
            expected_consumption=consumption_receipt,
        )
        if staged_receipt != evidence_receipt:
            raise EvidenceIntegrityError("capture stage evidence receipt changed")
        self._write_once(
            self.raw_dir / f"{evidence_receipt.evidence_id}.txt",
            raw_content,
            expected_parent=self._raw_root,
            suffix=".txt",
        )
        self._write_once(
            self.receipt_dir / f"{evidence_receipt.evidence_id}.json",
            json.dumps(
                evidence_receipt.to_dict(),
                ensure_ascii=False,
                sort_keys=True,
                indent=2,
            ),
            expected_parent=self._receipt_root,
            suffix=".json",
        )
        self._write_consumption_receipt(grant_id, consumption_receipt)

    def recover_prepared_capture(self, grant_id: str) -> AuthorizedCaptureResult:
        """Idempotently finish a capture that reached the durable prepared state."""
        if not re.fullmatch(r"^cg-[0-9a-f]{64}$", grant_id):
            raise CaptureRecoveryRequiredError("invalid recovery grant identifier")
        ledger = CaptureGrantLedger(self._store_root)
        record = ledger.record(grant_id)
        if record is None or record["state"] not in {"reserved", "prepared", "consumed"}:
            raise CaptureRecoveryRequiredError("capture is not recoverable")
        try:
            if record["state"] == "reserved":
                stage = self._store_root / "capture-staging" / str(record["attempt_id"])
                try:
                    _, evidence_receipt, consumption = self._load_authorized_stage(
                        stage=stage,
                        grant_id=grant_id,
                        evidence_id=None,
                        expected_consumption=None,
                    )
                except Exception as error:
                    ledger.fail_if_reserved(
                        grant_id=grant_id,
                        finished_at=utc_text(datetime.now(UTC)),
                    )
                    if stage.exists():
                        self._cleanup_stage(stage)
                    raise CaptureRecoveryRequiredError(
                        "reserved capture was terminally failed"
                    ) from error
                ledger.prepare(
                    grant_id=grant_id,
                    finished_at=utc_text(datetime.now(UTC)),
                    evidence_id=evidence_receipt.evidence_id,
                    consumption_receipt=consumption,
                )
                record = ledger.record(grant_id)
                if record is None:
                    raise CaptureRecoveryRequiredError(
                        "prepared capture ledger record disappeared"
                    )
            consumption = json.loads(str(record["consumption_receipt_json"]))
            evidence_id = str(record["evidence_id"])
            if record["state"] == "prepared":
                stage = self._store_root / "capture-staging" / str(record["attempt_id"])
                _, evidence_receipt, _ = self._load_authorized_stage(
                    stage=stage,
                    grant_id=grant_id,
                    evidence_id=evidence_id,
                    expected_consumption=consumption,
                )
                self._publish_authorized_stage(
                    stage=stage,
                    evidence_receipt=evidence_receipt,
                    grant_id=grant_id,
                    consumption_receipt=consumption,
                )
                ledger.consume_prepared(
                    grant_id=grant_id,
                    finished_at=utc_text(datetime.now(UTC)),
                )
                self._cleanup_stage(stage)
            else:
                evidence_receipt = self.find_one(evidence_id=evidence_id)
                self.read_raw(evidence_id, expected_hash=evidence_receipt.content_hash)
                self._write_consumption_receipt(grant_id, consumption)
        except Exception as error:
            if isinstance(error, CaptureRecoveryRequiredError):
                raise
            raise CaptureRecoveryRequiredError("prepared capture recovery failed") from error
        return AuthorizedCaptureResult(
            evidence_receipt=evidence_receipt,
            consumption_receipt=consumption,
        )

    def _cleanup_stage(self, stage: Path) -> None:
        stage_root = self._store_root / "capture-staging"
        if stage.parent != stage_root or not re.fullmatch(
            r"^attempt-[0-9a-f]{64}$", stage.name
        ):
            raise EvidenceIntegrityError("refusing to clean an unbound capture stage")
        if not stage.exists():
            return
        for path in stage.iterdir():
            if path.is_symlink() or not path.is_file():
                raise EvidenceIntegrityError("capture stage contains an unsafe object")
            path.unlink()
        stage.rmdir()

    @staticmethod
    def _validate_clutch_locator(locator: PromptEvidenceLocatorLike) -> None:
        try:
            schema = locator.schema
            provider_code = locator.provider_code
            locator_id = locator.locator_id
            source_uri = locator.source_uri
            content_hash = locator.content_hash
        except (AttributeError, TypeError) as error:
            raise EvidenceIntegrityError(
                "prompt evidence locator lacks required fields"
            ) from error
        if schema != "ellmos.prompt-evidence-locator.v2":
            raise EvidenceIntegrityError(
                "unsupported prompt evidence locator schema"
            )
        if provider_code != "clutch":
            raise EvidenceIntegrityError(
                "prompt evidence locator provider is not trusted"
            )
        if not isinstance(locator_id, str) or not re.fullmatch(
            r"^loc-[0-9a-f]{64}$",
            locator_id,
        ):
            raise EvidenceIntegrityError("invalid prompt evidence locator ID")
        if source_uri != f"clutch-local://evidence/{locator_id}":
            raise EvidenceIntegrityError("invalid prompt evidence locator URI")
        if not isinstance(content_hash, str) or not _SHA256.fullmatch(
            content_hash
        ):
            raise EvidenceIntegrityError(
                "prompt evidence locator hash must be lowercase sha256"
            )

    def find_one(
        self,
        *,
        evidence_id: str | None = None,
        provider_code: str | None = None,
        content_hash: str | None = None,
    ) -> PromptEvidenceReceipt:
        """Löst genau ein Receipt auf; null oder mehrere Treffer sind Fehler."""
        if evidence_id is not None and not _OPAQUE_ID.fullmatch(evidence_id):
            raise EvidenceNotFoundError("invalid evidence identifier")
        self._validate_current_store()
        matches: list[PromptEvidenceReceipt] = []
        for path in sorted(self.receipt_dir.glob("pe-*.json")):
            receipt = self._read_receipt(path, self._receipt_root)
            if evidence_id is not None and receipt.evidence_id != evidence_id:
                continue
            if provider_code is not None and receipt.provider_code != provider_code:
                continue
            if content_hash is not None and receipt.content_hash != content_hash:
                continue
            matches.append(receipt)
        if not matches:
            raise EvidenceNotFoundError("no matching prompt evidence receipt")
        if len(matches) != 1:
            raise AmbiguousEvidenceError(
                f"prompt evidence lookup returned {len(matches)} matches"
            )
        return matches[0]

    def read_raw(self, evidence_id: str, *, expected_hash: str) -> str:
        """Liest Rohtext lokal nach strikter ID- und Hash-Prüfung."""
        self._validate_current_store()
        if not _SHA256.fullmatch(expected_hash):
            raise EvidenceIntegrityError("invalid expected evidence hash")
        receipt = self.find_one(evidence_id=evidence_id)
        if receipt.content_hash != expected_hash:
            raise EvidenceIntegrityError("prompt evidence hash mismatch")
        raw_path = self._validated_raw_path(receipt.evidence_id)
        try:
            raw_content = raw_path.read_text(encoding="utf-8")
        except FileNotFoundError as error:
            raise EvidenceNotFoundError("prompt evidence raw object is missing") from error
        if _sha256(raw_content) != expected_hash:
            raise EvidenceIntegrityError("prompt evidence integrity check failed")
        self._validate_current_store(check_acl=False)
        self._validated_store_child(
            raw_path,
            expected_parent=self._raw_root,
            suffix=".txt",
            require_exists=True,
        )
        return raw_content

    def _validate_current_store(self, *, check_acl: bool = True) -> None:
        if self.root != self._store_root:
            raise UnsafeEvidenceStoreError(
                "evidence-store root binding changed after initialization"
            )
        if check_acl:
            self._validate_store_security(self.root)
        else:
            self._reject_sync_and_reparse(self.root)
            try:
                resolved_root = self.root.resolve(strict=True)
            except OSError as error:
                raise UnsafeEvidenceStoreError(
                    "evidence-store root is unavailable"
                ) from error
            if resolved_root != self._store_root or not self.root.is_dir():
                raise UnsafeEvidenceStoreError(
                    "evidence-store root binding changed"
                )
        self._validate_store_directory(
            self.raw_dir,
            self._raw_root,
            "raw",
        )
        self._validate_store_directory(
            self.receipt_dir,
            self._receipt_root,
            "receipt",
        )

    @classmethod
    def _validate_store_directory(
        cls,
        directory: Path,
        expected: Path,
        label: str,
    ) -> None:
        cls._reject_sync_and_reparse(directory)
        try:
            resolved = directory.resolve(strict=True)
        except OSError as error:
            raise UnsafeEvidenceStoreError(
                f"{label} evidence directory is unavailable"
            ) from error
        if resolved != expected or not directory.is_dir():
            raise UnsafeEvidenceStoreError(
                f"{label} evidence directory binding changed"
            )
        if os.name != "nt" and stat.S_IMODE(
            directory.stat().st_mode
        ) & 0o077:
            raise UnsafeEvidenceStoreError(
                f"{label} evidence directory mode is not private"
            )

    def _validated_raw_path(self, evidence_id: str) -> Path:
        if not isinstance(evidence_id, str) or not re.fullmatch(
            r"^pe-[0-9a-f]{64}$",
            evidence_id,
        ):
            raise EvidenceIntegrityError("invalid prompt evidence identifier")
        try:
            candidate = self.raw_dir / f"{evidence_id}.txt"
            resolved = self._validated_store_child(
                candidate,
                expected_parent=self._raw_root,
                suffix=".txt",
                require_exists=True,
            )
        except FileNotFoundError as error:
            raise EvidenceNotFoundError(
                "prompt evidence raw object is missing"
            ) from error
        except OSError as error:
            raise EvidenceIntegrityError(
                "prompt evidence raw object cannot be resolved safely"
            ) from error
        try:
            relative = resolved.relative_to(self._raw_root)
        except ValueError as error:
            raise EvidenceIntegrityError(
                "prompt evidence raw object escaped the raw store"
            ) from error
        if len(relative.parts) != 1:
            raise EvidenceIntegrityError(
                "prompt evidence raw object escaped the raw store"
            )
        return resolved

    def _validated_store_child(
        self,
        path: Path,
        *,
        expected_parent: Path,
        suffix: str,
        require_exists: bool,
    ) -> Path:
        expected_name = re.compile(
            rf"^pe-[0-9a-f]{{64}}{re.escape(suffix)}$"
        )
        if path.parent != expected_parent or not expected_name.fullmatch(
            path.name
        ):
            raise EvidenceIntegrityError(
                "evidence object path is outside its bound store"
            )
        try:
            parent = path.parent.resolve(strict=True)
        except OSError as error:
            raise UnsafeEvidenceStoreError(
                "evidence object parent is unavailable"
            ) from error
        if parent != expected_parent:
            raise UnsafeEvidenceStoreError(
                "evidence object parent binding changed"
            )
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            if require_exists:
                raise
            return path
        attributes = getattr(metadata, "st_file_attributes", 0)
        if path.is_symlink() or attributes & getattr(
            stat,
            "FILE_ATTRIBUTE_REPARSE_POINT",
            0,
        ):
            raise EvidenceIntegrityError("evidence object is a reparse point")
        if not path.is_file():
            raise EvidenceIntegrityError(
                "evidence object is not a regular file"
            )
        try:
            resolved = path.resolve(strict=True)
            relative = resolved.relative_to(expected_parent)
        except (OSError, ValueError) as error:
            raise EvidenceIntegrityError(
                "evidence object escaped its bound store"
            ) from error
        if len(relative.parts) != 1:
            raise EvidenceIntegrityError(
                "evidence object escaped its bound store"
            )
        return resolved

    @classmethod
    def _app_store_root(cls) -> Path:
        if os.name == "nt":
            local_data = os.environ.get("LOCALAPPDATA")
            if not local_data:
                raise UnsafeEvidenceStoreError("LOCALAPPDATA is required")
            known_base = cls._known_local_app_data().resolve(strict=True)
            configured_base = Path(local_data).expanduser()
            cls._reject_sync_and_reparse(configured_base)
            base = configured_base.resolve(strict=True)
            if base != known_base:
                raise UnsafeEvidenceStoreError(
                    "LOCALAPPDATA does not match the Windows Known Folder"
                )
        else:
            xdg = os.environ.get("XDG_DATA_HOME")
            configured_base = (
                Path(xdg).expanduser()
                if xdg
                else Path.home() / ".local" / "share"
            )
            configured_base.mkdir(mode=0o700, parents=True, exist_ok=True)
            cls._reject_sync_and_reparse(configured_base)
            base = configured_base.resolve()
            base.mkdir(mode=0o700, parents=True, exist_ok=True)
        return (base / cls.APP_DIR / cls.STORE_DIR).resolve()

    @classmethod
    def existing_store_root(cls) -> Path:
        """Resolve and validate the canonical local store without creating it."""
        if os.name == "nt":
            local_data = os.environ.get("LOCALAPPDATA")
            if not local_data:
                raise UnsafeEvidenceStoreError("LOCALAPPDATA is required")
            known_base = cls._known_local_app_data().resolve(strict=True)
            configured_base = Path(local_data).expanduser()
            cls._reject_sync_and_reparse(configured_base)
            base = configured_base.resolve(strict=True)
            if base != known_base:
                raise UnsafeEvidenceStoreError(
                    "LOCALAPPDATA does not match the Windows Known Folder"
                )
        else:
            import pwd

            base = cls._existing_posix_base(
                native_home=Path(pwd.getpwuid(os.getuid()).pw_dir),
                configured_home=os.environ.get("HOME"),
                xdg=os.environ.get("XDG_DATA_HOME"),
            )

        expected = base / cls.APP_DIR / cls.STORE_DIR
        cls._reject_sync_and_reparse(expected)
        try:
            root = expected.resolve(strict=True)
        except OSError as error:
            raise UnsafeEvidenceStoreError("evidence-store root is unavailable") from error
        if root != expected or not root.is_dir():
            raise UnsafeEvidenceStoreError("evidence-store root binding changed")
        cls._validate_store_security(root)
        return root

    @classmethod
    def _existing_posix_base(
        cls,
        *,
        native_home: Path,
        configured_home: str | None,
        xdg: str | None,
    ) -> Path:
        """Resolve the fixed POSIX user-data base without trusting XDG redirection."""
        trusted_home = native_home.resolve(strict=True)
        if configured_home:
            supplied_home = Path(configured_home).resolve(strict=True)
            if supplied_home != trusted_home:
                raise UnsafeEvidenceStoreError(
                    "HOME does not match the native account home"
                )
        canonical_candidate = trusted_home / ".local" / "share"
        cls._reject_sync_and_reparse(canonical_candidate)
        canonical = canonical_candidate.resolve(strict=True)
        if xdg:
            configured_candidate = Path(xdg).expanduser()
            cls._reject_sync_and_reparse(configured_candidate)
            configured = configured_candidate.resolve(strict=True)
            if configured != canonical:
                raise UnsafeEvidenceStoreError(
                    "XDG_DATA_HOME does not match the canonical local user-data root"
                )
        return canonical

    @classmethod
    def _prepare_secure_store(cls, root: Path) -> None:
        cls._reject_sync_and_reparse(root)
        if os.name == "nt":
            anchor = root.anchor
            if not anchor or anchor.startswith("\\\\"):
                raise UnsafeEvidenceStoreError("remote evidence roots are forbidden")
            drive_type = ctypes.windll.kernel32.GetDriveTypeW(anchor)
            if drive_type != 3:  # DRIVE_FIXED
                raise UnsafeEvidenceStoreError("evidence root must be on a fixed local drive")
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if os.name == "nt":
            current_sid = cls._current_windows_sid()
            result = subprocess.run(
                [
                    "icacls",
                    str(root),
                    "/inheritance:r",
                    "/remove:g",
                    "*S-1-3-4",
                    "*S-1-1-0",
                    "*S-1-5-11",
                    "*S-1-5-32-545",
                    "/grant:r",
                    f"*{current_sid}:(OI)(CI)F",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode != 0:
                raise UnsafeEvidenceStoreError("failed to restrict evidence-store ACL")
        else:
            os.chmod(root, 0o700)

    @classmethod
    def _validate_store_security(cls, root: Path) -> None:
        cls._reject_sync_and_reparse(root)
        if os.name == "nt":
            cls._validate_windows_acl_snapshot(cls._read_windows_acl(root))
        elif stat.S_IMODE(root.stat().st_mode) & 0o077:
            raise UnsafeEvidenceStoreError("evidence-store mode is not private")

    @classmethod
    def _validate_private_store_child(cls, path: Path) -> None:
        """Validate an existing private store child without changing its ACL/mode."""
        cls._reject_sync_and_reparse(path)
        try:
            resolved = path.resolve(strict=True)
        except OSError as error:
            raise UnsafeEvidenceStoreError("private store child is unavailable") from error
        if resolved != path or not (resolved.is_dir() or resolved.is_file()):
            raise UnsafeEvidenceStoreError("private store child binding changed")
        if os.name == "nt":
            cls._validate_windows_acl_snapshot(
                cls._read_windows_acl(resolved),
                allow_safe_inherited=True,
            )
        elif stat.S_IMODE(resolved.stat().st_mode) & 0o077:
            raise UnsafeEvidenceStoreError("private store child mode is not private")

    @classmethod
    def _restrict_private_store_child(cls, path: Path) -> None:
        """Remove inherited/public access from an existing store child."""
        cls._reject_sync_and_reparse(path)
        try:
            resolved = path.resolve(strict=True)
        except OSError as error:
            raise UnsafeEvidenceStoreError("private store child is unavailable") from error
        if resolved != path or not (resolved.is_dir() or resolved.is_file()):
            raise UnsafeEvidenceStoreError("private store child binding changed")
        if os.name == "nt":
            current_sid = cls._current_windows_sid()
            grant = f"*{current_sid}:(OI)(CI)F" if resolved.is_dir() else f"*{current_sid}:F"
            result = subprocess.run(
                [
                    "icacls",
                    str(resolved),
                    "/inheritance:r",
                    "/remove:g",
                    "*S-1-3-4",
                    "*S-1-1-0",
                    "*S-1-5-11",
                    "*S-1-5-32-545",
                    "/grant:r",
                    grant,
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode != 0:
                raise UnsafeEvidenceStoreError("failed to restrict private store child ACL")
        else:
            os.chmod(resolved, 0o700 if resolved.is_dir() else 0o600)
        cls._validate_private_store_child(resolved)

    @staticmethod
    def _reject_sync_and_reparse(root: Path) -> None:
        if any(part.casefold() in _SYNC_PARTS for part in root.parts):
            raise UnsafeEvidenceStoreError("known sync roots are forbidden")
        for env_name in (
            "OneDrive",
            "OneDriveConsumer",
            "OneDriveCommercial",
            "Dropbox",
            "GoogleDrive",
        ):
            value = os.environ.get(env_name)
            if value:
                try:
                    root.relative_to(Path(value).expanduser().resolve())
                except ValueError:
                    pass
                else:
                    raise UnsafeEvidenceStoreError("known sync roots are forbidden")
        existing = next((path for path in (root, *root.parents) if path.exists()), None)
        if existing is None:
            raise UnsafeEvidenceStoreError("evidence root has no existing local ancestor")
        for path in (existing, *existing.parents):
            attrs = getattr(path.lstat(), "st_file_attributes", 0)
            if path.is_symlink() or attrs & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0):
                raise UnsafeEvidenceStoreError("reparse-point evidence roots are forbidden")

    @staticmethod
    def _validate_codes(**codes: str) -> None:
        allowed = {
            "provider_code": _PROVIDERS,
            "origin_code": _ORIGINS,
            "sensitivity_code": _SENSITIVITY,
            "retention_code": _RETENTION,
            "promotion_status": _PROMOTION,
        }
        for name, value in codes.items():
            if value not in allowed[name]:
                raise ValueError(f"unsupported {name}")

    @staticmethod
    def _known_local_app_data() -> Path:
        """Löst LocalAppData über die Windows Known Folder API auf."""
        if os.name != "nt":
            raise UnsafeEvidenceStoreError("Windows Known Folder API is unavailable")

        class GUID(ctypes.Structure):
            _fields_ = [
                ("data1", ctypes.c_uint32),
                ("data2", ctypes.c_uint16),
                ("data3", ctypes.c_uint16),
                ("data4", ctypes.c_ubyte * 8),
            ]

        folder_id = GUID.from_buffer_copy(
            UUID("f1b32785-6fba-4fcf-9d55-7b8e7f157091").bytes_le
        )
        output = ctypes.c_wchar_p()
        result = ctypes.windll.shell32.SHGetKnownFolderPath(
            ctypes.byref(folder_id),
            0,
            None,
            ctypes.byref(output),
        )
        if result != 0 or not output.value:
            raise UnsafeEvidenceStoreError("failed to resolve LocalAppData Known Folder")
        try:
            return Path(output.value)
        finally:
            ctypes.windll.ole32.CoTaskMemFree(output)

    @staticmethod
    def _current_windows_sid() -> str:
        script = (
            "[Security.Principal.WindowsIdentity]::GetCurrent().User.Value"
        )
        result = subprocess.run(
            [
                PromptEvidenceCollector._windows_powershell(),
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                script,
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        sid = result.stdout.strip()
        if result.returncode != 0 or not sid.startswith("S-1-"):
            raise UnsafeEvidenceStoreError("current Windows SID is unavailable")
        return sid

    @classmethod
    def _read_windows_acl(cls, root: Path) -> dict[str, Any]:
        script = (
            "$acl=Get-Acl -LiteralPath $env:ELLMOS_ACL_TARGET;"
            "$rules=@($acl.Access|ForEach-Object{"
            "[PSCustomObject]@{"
            "Sid=$_.IdentityReference.Translate("
            "[Security.Principal.SecurityIdentifier]).Value;"
            "Type=$_.AccessControlType.ToString();"
            "Rights=$_.FileSystemRights.ToString();"
            "Inherited=$_.IsInherited}});"
            "[PSCustomObject]@{"
            "CurrentSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;"
            "OwnerSid=([Security.Principal.NTAccount]::new($acl.Owner)).Translate("
            "[Security.Principal.SecurityIdentifier]).Value;"
            "Rules=$rules}|ConvertTo-Json -Compress -Depth 4"
        )
        environment = os.environ.copy()
        environment["ELLMOS_ACL_TARGET"] = str(root)
        powershell = Path(cls._windows_powershell())
        environment["PSModulePath"] = str(powershell.parent / "Modules")
        result = subprocess.run(
            [
                str(powershell),
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                script,
            ],
            capture_output=True,
            text=True,
            check=False,
            env=environment,
        )
        if result.returncode != 0:
            raise UnsafeEvidenceStoreError("failed to read evidence-store ACL")
        try:
            value = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise UnsafeEvidenceStoreError("invalid evidence-store ACL readback") from error
        if not isinstance(value, dict):
            raise UnsafeEvidenceStoreError("invalid evidence-store ACL snapshot")
        return value

    @staticmethod
    def _windows_powershell() -> str:
        buffer = ctypes.create_unicode_buffer(32768)
        length = ctypes.windll.kernel32.GetWindowsDirectoryW(buffer, len(buffer))
        if length <= 0 or length >= len(buffer):
            raise UnsafeEvidenceStoreError("Windows directory is unavailable")
        executable = (
            Path(buffer.value)
            / "System32"
            / "WindowsPowerShell"
            / "v1.0"
            / "powershell.exe"
        )
        if not executable.is_file():
            raise UnsafeEvidenceStoreError("Windows PowerShell is unavailable")
        return str(executable)

    @staticmethod
    def _validate_windows_acl_snapshot(
        snapshot: dict[str, Any],
        *,
        allow_safe_inherited: bool = False,
    ) -> None:
        current_sid = snapshot.get("CurrentSid")
        owner_sid = snapshot.get("OwnerSid")
        if not isinstance(current_sid, str) or not current_sid.startswith("S-1-"):
            raise UnsafeEvidenceStoreError("ACL snapshot lacks current principal")
        if owner_sid not in {current_sid, "S-1-5-32-544"}:
            raise UnsafeEvidenceStoreError("evidence-store owner is not trusted")
        rules = snapshot.get("Rules")
        if isinstance(rules, dict):
            rules = [rules]
        if not isinstance(rules, list):
            raise UnsafeEvidenceStoreError("ACL snapshot lacks access rules")
        allowed_sids = {current_sid, "S-1-5-18", "S-1-5-32-544"}
        if allow_safe_inherited and owner_sid == current_sid:
            allowed_sids.add("S-1-3-4")  # OWNER RIGHTS, bound by owner check above
        current_full_control = False
        for rule in rules:
            if not isinstance(rule, dict):
                raise UnsafeEvidenceStoreError("invalid ACL rule")
            if rule.get("Type") != "Allow":
                continue
            inherited = rule.get("Inherited")
            if inherited not in {True, False}:
                raise UnsafeEvidenceStoreError("ACL rule lacks inheritance state")
            if inherited and not allow_safe_inherited:
                raise UnsafeEvidenceStoreError("inherited Allow ACE is forbidden")
            sid = rule.get("Sid")
            if sid not in allowed_sids:
                raise UnsafeEvidenceStoreError("foreign Allow ACE is forbidden")
            if (
                sid == current_sid
                or (sid == "S-1-3-4" and owner_sid == current_sid)
            ) and "FullControl" in str(rule.get("Rights", "")):
                current_full_control = True
        if not current_full_control:
            raise UnsafeEvidenceStoreError("current principal lacks explicit FullControl")

    def _write_once(
        self,
        path: Path,
        content: str,
        *,
        expected_parent: Path,
        suffix: str,
    ) -> None:
        self._validate_current_store(check_acl=False)
        self._validated_store_child(
            path,
            expected_parent=expected_parent,
            suffix=suffix,
            require_exists=False,
        )
        try:
            with path.open("x", encoding="utf-8", newline="\n") as handle:
                handle.write(content)
            if os.name != "nt":
                os.chmod(path, 0o600)
        except FileExistsError:
            existing = self._validated_store_child(
                path,
                expected_parent=expected_parent,
                suffix=suffix,
                require_exists=True,
            )
            if existing.read_text(encoding="utf-8") != content:
                raise EvidenceIntegrityError(
                    "existing prompt evidence object conflicts with capture"
                ) from None
        self._validate_current_store(check_acl=False)
        self._validated_store_child(
            path,
            expected_parent=expected_parent,
            suffix=suffix,
            require_exists=True,
        )

    def _read_receipt(
        self,
        path: Path,
        receipt_root: Path,
    ) -> PromptEvidenceReceipt:
        try:
            self._validate_current_store(check_acl=False)
            resolved = self._validated_store_child(
                path,
                expected_parent=receipt_root,
                suffix=".json",
                require_exists=True,
            )
            value = json.loads(resolved.read_text(encoding="utf-8"))
            if not isinstance(value, dict):
                raise TypeError("receipt must be a JSON object")
            expected_fields = {
                field.name for field in fields(PromptEvidenceReceipt)
            }
            if set(value) != expected_fields:
                raise TypeError("receipt fields do not match the schema")
            receipt = PromptEvidenceReceipt(**value)
        except (OSError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise EvidenceIntegrityError("invalid prompt evidence receipt") from error
        if path.name != f"{receipt.evidence_id}.json":
            raise EvidenceIntegrityError(
                "prompt evidence receipt filename does not match its identifier"
            )
        self._validate_current_store(check_acl=False)
        self._validated_store_child(
            path,
            expected_parent=receipt_root,
            suffix=".json",
            require_exists=True,
        )
        return receipt


def _validate_utc_timestamp(value: str) -> None:
    if not isinstance(value, str) or not _UTC_TIMESTAMP.fullmatch(value):
        raise ValueError("captured_at must be an explicit UTC timestamp")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as error:
        raise ValueError(
            "captured_at must be an explicit UTC timestamp"
        ) from error
    if parsed.utcoffset() != UTC.utcoffset(parsed):
        raise ValueError("captured_at must be an explicit UTC timestamp")


def _prompt_evidence_id(
    *,
    provider_code: str,
    origin_code: str,
    captured_at: str,
    source_locator_id: str | None,
    source_content_hash: str | None,
    content_hash: str,
) -> str:
    identity = "\n".join(
        [
            provider_code,
            origin_code,
            captured_at,
            source_locator_id or "",
            source_content_hash or "",
            content_hash,
        ]
    )
    return f"pe-{_sha256(identity)}"
