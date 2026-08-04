"""Minimal CLI for the standalone prompt evidence collector."""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import stat
from datetime import UTC, datetime
from pathlib import Path

from .authorization import (
    READ_ONLY_EXIT_INPUT_INVALID,
    READ_ONLY_EXIT_TRUST_INVALID,
    CaptureAuthorizationError,
    CaptureGrant,
    CaptureGrantVerifier,
    ReadOnlyAuthorizationError,
    ResolverRuntimeReceipt,
)
from .collector import PromptEvidenceCollector, UnsafeEvidenceStoreError


MAX_AUTHORIZATION_DOCUMENT_BYTES = 1024 * 1024


def _cmd_doctor(args: argparse.Namespace) -> int:
    """Native readback: store root, permissions, receipt directory state."""
    collector = PromptEvidenceCollector()
    report = {
        "schema": "ellmos.prompt-evidence-collector-doctor.v1",
        "store_root": str(collector._store_root),
        "raw_dir_exists": collector.raw_dir.is_dir(),
        "receipt_dir_exists": collector.receipt_dir.is_dir(),
        "receipt_count": len(list(collector.receipt_dir.glob("*.json"))),
    }
    print(json.dumps(report, indent=2))
    return 0


def _emit_failure(*, schema: str, code: str, exit_code: int) -> int:
    print(
        json.dumps(
            {
                "schema": schema,
                "status": "invalid",
                "code": code,
                "exit_code": exit_code,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return exit_code


def _build_verifier() -> CaptureGrantVerifier:
    return CaptureGrantVerifier(
        PromptEvidenceCollector.existing_store_root(),
        private_path_validator=PromptEvidenceCollector._validate_private_store_child,
    )


def _read_local_json(path_text: str) -> object:
    candidate = Path(os.path.abspath(Path(path_text).expanduser()))
    if os.name == "nt":
        anchor = candidate.anchor
        if not anchor or anchor.startswith("\\\\"):
            raise OSError("remote authorization documents are forbidden")
        if ctypes.windll.kernel32.GetDriveTypeW(anchor) != 3:  # DRIVE_FIXED
            raise OSError("authorization document must be on a fixed local drive")
    PromptEvidenceCollector._reject_sync_and_reparse(candidate)
    metadata = candidate.lstat()
    attributes = getattr(metadata, "st_file_attributes", 0)
    if (
        candidate.is_symlink()
        or attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        or metadata.st_nlink != 1
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_size <= 0
        or metadata.st_size > MAX_AUTHORIZATION_DOCUMENT_BYTES
    ):
        raise OSError("authorization document is not a bounded regular local file")
    resolved = candidate.resolve(strict=True)
    with resolved.open("rb") as handle:
        opened = os.fstat(handle.fileno())
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_size != metadata.st_size
            or (metadata.st_ino and opened.st_ino != metadata.st_ino)
            or opened.st_dev != metadata.st_dev
        ):
            raise OSError("authorization document changed before read")
        payload = handle.read(MAX_AUTHORIZATION_DOCUMENT_BYTES + 1)
    if len(payload) != metadata.st_size or len(payload) > MAX_AUTHORIZATION_DOCUMENT_BYTES:
        raise OSError("authorization document changed during read")
    return json.loads(payload.decode("utf-8"))


def _cmd_authorization_preflight(args: argparse.Namespace) -> int:
    schema = "ellmos.prompt-evidence-trust-preflight.v1"
    try:
        verifier = _build_verifier()
        report = verifier.preflight_trust_store(now=datetime.now(UTC))
    except ReadOnlyAuthorizationError as error:
        return _emit_failure(schema=schema, code=error.code, exit_code=error.exit_code)
    except (OSError, UnsafeEvidenceStoreError):
        return _emit_failure(
            schema=schema,
            code="trust-store-invalid",
            exit_code=READ_ONLY_EXIT_TRUST_INVALID,
        )
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


def _cmd_authorization_validate(args: argparse.Namespace) -> int:
    schema = "ellmos.prompt-evidence-authorization-validation.v1"
    try:
        grant = CaptureGrant.from_dict(
            _read_local_json(args.grant)
        )
        runtime_receipt = ResolverRuntimeReceipt.from_dict(
            _read_local_json(args.runtime_receipt)
        )
    except (
        CaptureAuthorizationError,
        OSError,
        UnsafeEvidenceStoreError,
        ValueError,
        json.JSONDecodeError,
    ):
        return _emit_failure(
            schema=schema,
            code="input-invalid",
            exit_code=READ_ONLY_EXIT_INPUT_INVALID,
        )
    try:
        verifier = _build_verifier()
        report = verifier.validate_signed_authorization(
            grant=grant,
            runtime_receipt=runtime_receipt,
            now=datetime.now(UTC),
        )
    except ReadOnlyAuthorizationError as error:
        return _emit_failure(schema=schema, code=error.code, exit_code=error.exit_code)
    except (OSError, UnsafeEvidenceStoreError):
        return _emit_failure(
            schema=schema,
            code="trust-store-invalid",
            exit_code=READ_ONLY_EXIT_TRUST_INVALID,
        )
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="prompt-evidence-collector")
    sub = parser.add_subparsers(dest="command", required=True)
    doctor = sub.add_parser("doctor", help="native store readback (no capture)")
    doctor.set_defaults(func=_cmd_doctor)

    preflight = sub.add_parser(
        "authorization-preflight",
        help="read-only private trust-store preflight",
    )
    preflight.set_defaults(func=_cmd_authorization_preflight)

    validate = sub.add_parser(
        "authorization-validate",
        help="read-only signed grant/runtime validation",
    )
    validate.add_argument("--grant", required=True)
    validate.add_argument("--runtime-receipt", required=True)
    validate.set_defaults(func=_cmd_authorization_validate)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
