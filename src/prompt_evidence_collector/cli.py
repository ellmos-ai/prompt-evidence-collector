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
from .collector import PromptEvidenceCollector, PromptEvidenceError, UnsafeEvidenceStoreError
from .trust_enrollment import (
    PLAN_SCHEMA,
    RESULT_SCHEMA,
    ROLLBACK_SCHEMA,
    TrustActivation,
    TrustEnroller,
    TrustEnrollmentError,
    TrustProposal,
    build_plan,
)


MAX_AUTHORIZATION_DOCUMENT_BYTES = 1024 * 1024
TRUST_ENROLL_EXIT_CONFLICT = 7
TRUST_ENROLL_EXIT_RECOVERY_REQUIRED = 8


def _cmd_doctor(args: argparse.Namespace) -> int:
    """Native readback: store root and crash-safe Raw/Receipt pairing state."""
    try:
        collector = PromptEvidenceCollector()
        report = collector.store_inventory()
    except (OSError, PromptEvidenceError):
        report = {
            "schema": "ellmos.prompt-evidence-collector-doctor.v3",
            "status": "invalid",
            "code": "store-unavailable",
            "exit_code": 3,
        }
        print(json.dumps(report, indent=2, sort_keys=True))
        return 3
    report["store_root"] = str(collector._store_root)
    print(json.dumps(report, indent=2, sort_keys=True))
    return int(report["exit_code"])


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


def _trust_failure(error: Exception, *, schema: str = RESULT_SCHEMA) -> int:
    message = str(error)
    if "recovery-required" in message:
        code, exit_code = "recovery-required", TRUST_ENROLL_EXIT_RECOVERY_REQUIRED
    elif "signature" in message:
        code, exit_code = "signature-invalid", 4
    elif "not current" in message or "validity" in message or "expired" in message:
        code, exit_code = "activation-not-current", 5
    elif "scope" in message or "decision" in message or "binding" in message:
        code, exit_code = "scope-mismatch", 6
    elif "already exists" in message or "changed" in message or "capture state" in message:
        code, exit_code = "state-conflict", TRUST_ENROLL_EXIT_CONFLICT
    elif "bootstrap" in message or "private store" in message or "ACL" in message:
        code, exit_code = "bootstrap-trust-invalid", 3
    else:
        code, exit_code = "input-invalid", 2
    return _emit_failure(schema=schema, code=code, exit_code=exit_code)


def _cmd_trust_enroll_plan(args: argparse.Namespace) -> int:
    try:
        proposal = TrustProposal.from_dict(_read_local_json(args.proposal))
        report = build_plan(proposal)
    except (
        CaptureAuthorizationError,
        TrustEnrollmentError,
        OSError,
        UnsafeEvidenceStoreError,
        ValueError,
        json.JSONDecodeError,
    ) as error:
        return _trust_failure(error, schema=PLAN_SCHEMA)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


def _cmd_trust_enroll_apply(args: argparse.Namespace) -> int:
    try:
        proposal = TrustProposal.from_dict(_read_local_json(args.proposal))
        activation = TrustActivation.from_dict(_read_local_json(args.activation))
        enroller = TrustEnroller(PromptEvidenceCollector.existing_store_root())
        report = enroller.apply(
            proposal=proposal,
            activation=activation,
            expected_plan_sha256=args.expected_plan_sha256,
            now=datetime.now(UTC),
        )
    except (
        CaptureAuthorizationError,
        TrustEnrollmentError,
        OSError,
        UnsafeEvidenceStoreError,
        ValueError,
        json.JSONDecodeError,
    ) as error:
        return _trust_failure(error)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


def _cmd_trust_enroll_rollback(args: argparse.Namespace) -> int:
    try:
        enroller = TrustEnroller(PromptEvidenceCollector.existing_store_root())
        report = enroller.rollback(expected_trust_sha256=args.expected_trust_sha256)
    except (
        TrustEnrollmentError,
        OSError,
        UnsafeEvidenceStoreError,
        ValueError,
    ) as error:
        return _trust_failure(error, schema=ROLLBACK_SCHEMA)
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

    trust_enroll = sub.add_parser(
        "trust-enroll",
        help="plan, apply, or safely roll back capture-authority trust enrollment",
    )
    trust_commands = trust_enroll.add_subparsers(dest="trust_command", required=True)
    trust_plan = trust_commands.add_parser("plan", help="read-only enrollment plan")
    trust_plan.add_argument("--proposal", required=True)
    trust_plan.set_defaults(func=_cmd_trust_enroll_plan)
    trust_apply = trust_commands.add_parser("apply", help="apply an externally approved plan")
    trust_apply.add_argument("--proposal", required=True)
    trust_apply.add_argument("--activation", required=True)
    trust_apply.add_argument("--expected-plan-sha256", required=True)
    trust_apply.set_defaults(func=_cmd_trust_enroll_apply)
    trust_rollback = trust_commands.add_parser(
        "rollback", help="remove first enrollment before any capture state exists"
    )
    trust_rollback.add_argument("--expected-trust-sha256", required=True)
    trust_rollback.set_defaults(func=_cmd_trust_enroll_rollback)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
