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
from dataclasses import asdict, dataclass, fields
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Protocol
from uuid import UUID


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

    def capture(
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
        receipt = PromptEvidenceReceipt(
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
        self._write_once(
            self.raw_dir / f"{evidence_id}.txt",
            raw_content,
            expected_parent=self._raw_root,
            suffix=".txt",
        )
        self._write_once(
            self.receipt_dir / f"{evidence_id}.json",
            json.dumps(receipt.to_dict(), ensure_ascii=False, sort_keys=True, indent=2),
            expected_parent=self._receipt_root,
            suffix=".json",
        )
        return receipt

    def capture_from_locator(
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
        fail-closed geprüft.
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
        try:
            raw_content = resolve_content(locator)
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

        return self.capture(
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
    def _validate_windows_acl_snapshot(snapshot: dict[str, Any]) -> None:
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
        current_full_control = False
        for rule in rules:
            if not isinstance(rule, dict):
                raise UnsafeEvidenceStoreError("invalid ACL rule")
            if rule.get("Type") != "Allow":
                continue
            if rule.get("Inherited") is not False:
                raise UnsafeEvidenceStoreError("inherited Allow ACE is forbidden")
            sid = rule.get("Sid")
            if sid not in allowed_sids:
                raise UnsafeEvidenceStoreError("foreign Allow ACE is forbidden")
            if sid == current_sid and "FullControl" in str(rule.get("Rights", "")):
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
