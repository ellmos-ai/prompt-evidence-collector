from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
import types
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from prompt_evidence_collector.authorization import (
    ACTION_CODE,
    GRANT_SCHEMA,
    RUNTIME_SCHEMA,
    TRUST_SCHEMA,
    CaptureAuthorizationError,
    CaptureGrantLedger,
    CaptureGrantReplayError,
    CaptureRecoveryRequiredError,
    callable_fingerprint,
    canonical_bytes,
    canonical_sha256,
    resolver_identity,
)
from prompt_evidence_collector.collector import (
    EvidenceIntegrityError,
    EvidenceNotFoundError,
    PromptEvidenceCollector,
)
from prompt_evidence_collector.adapters.clutch import (
    resolve_content as registered_resolver,
)


RAW = "synthetic-authorized-capture"


@dataclass(frozen=True)
class Locator:
    schema: str
    provider_code: str
    locator_id: str
    source_uri: str
    content_hash: str


@dataclass
class MutableLocator:
    schema: str
    provider_code: str
    locator_id: str
    source_uri: str
    content_hash: str


def utc(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def public_bytes(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def fingerprint(private_key: Ed25519PrivateKey) -> str:
    return hashlib.sha256(public_bytes(private_key)).hexdigest()


def locator(raw: str = RAW) -> Locator:
    locator_id = "loc-" + hashlib.sha256(b"synthetic-locator").hexdigest()
    return Locator(
        schema="ellmos.prompt-evidence-locator.v2",
        provider_code="clutch",
        locator_id=locator_id,
        source_uri=f"clutch-local://evidence/{locator_id}",
        content_hash=hashlib.sha256(raw.encode("utf-8")).hexdigest(),
    )


def sign_runtime(
    private_key: Ed25519PrivateKey,
    *,
    adapter_sha256: str,
    resolver,
    now: datetime,
    module_id: str | None = None,
    qualname: str | None = None,
    callable_sha256: str | None = None,
) -> dict:
    target, _ = resolver_identity(resolver)
    body = {
        "schema": RUNTIME_SCHEMA,
        "component_code": "clutch",
        "source_pin": "a" * 40,
        "adapter_sha256": adapter_sha256,
        "module_id": module_id or target.__module__,
        "qualname": qualname or target.__qualname__,
        "callable_sha256": callable_sha256 or callable_fingerprint(resolver),
        "immutable": True,
        "dirty": False,
        "issued_at": utc(now - timedelta(minutes=5)),
        "expires_at": utc(now + timedelta(days=1)),
        "issuer_key_fingerprint": fingerprint(private_key),
        "signature_algorithm": "ed25519",
    }
    receipt_id = "rr-" + canonical_sha256(body)
    signing = canonical_bytes({"receipt_id": receipt_id, "body": body})
    return body | {
        "receipt_id": receipt_id,
        "signature": base64.b64encode(private_key.sign(signing)).decode("ascii"),
    }


def sign_grant(
    private_key: Ed25519PrivateKey,
    *,
    evidence_locator: Locator,
    runtime_receipt: dict,
    adapter_sha256: str,
    now: datetime,
    authority_source: str = "explicit-user-decision",
    purpose_code: str = "workflow-extraction",
    issued_at: datetime | None = None,
    not_before: datetime | None = None,
    expires_at: datetime | None = None,
) -> dict:
    issued_at = issued_at or now - timedelta(minutes=1)
    not_before = not_before or now - timedelta(minutes=1)
    expires_at = expires_at or now + timedelta(minutes=10)
    body = {
        "schema": GRANT_SCHEMA,
        "action_code": ACTION_CODE,
        "provider_code": "clutch",
        "purpose_code": purpose_code,
        "locator": {
            "schema": evidence_locator.schema,
            "locator_id": evidence_locator.locator_id,
            "content_hash": evidence_locator.content_hash,
        },
        "capture_policy": {
            "sensitivity_code": "private",
            "retention_code": "local-review",
            "promotion_status": "not-reviewed",
        },
        "resolver_binding": {
            "component_code": "clutch",
            "source_pin": runtime_receipt["source_pin"],
            "adapter_sha256": adapter_sha256,
            "runtime_receipt_sha256": canonical_sha256(runtime_receipt),
        },
        "authority": {
            "source_code": authority_source,
            "source_ref_hash": "1" * 64,
            "source_content_hash": "2" * 64,
            "resolution_receipt_id": "ar-" + "3" * 64,
            "resolution_receipt_sha256": "4" * 64,
            "issuer_key_fingerprint": fingerprint(private_key),
        },
        "issued_at": utc(issued_at),
        "not_before": utc(not_before),
        "expires_at": utc(expires_at),
        "one_shot": True,
        "max_captures": 1,
        "nonce": "5" * 32,
        "signature_algorithm": "ed25519",
    }
    grant_id = "cg-" + canonical_sha256(body)
    signing = canonical_bytes({"grant_id": grant_id, "body": body})
    return body | {
        "grant_id": grant_id,
        "signature": base64.b64encode(private_key.sign(signing)).decode("ascii"),
    }


def write_trust_store(
    collector: PromptEvidenceCollector,
    authority_key: Ed25519PrivateKey,
    runtime_key: Ed25519PrivateKey,
    *,
    authority_sources: list[str] | None = None,
) -> None:
    now = datetime.now(UTC)
    trust_dir = collector.root / "trust"
    trust_dir.mkdir(mode=0o700, exist_ok=True)
    if os.name != "nt":
        os.chmod(trust_dir, 0o700)
    keys = [
        {
            "key_fingerprint": fingerprint(authority_key),
            "public_key_base64": base64.b64encode(public_bytes(authority_key)).decode(
                "ascii"
            ),
            "roles": ["capture-authority"],
            "authority_source_codes": authority_sources
            or ["explicit-user-decision", "explicit-capture-policy"],
            "status": "active",
            "not_before": utc(now - timedelta(days=1)),
            "expires_at": utc(now + timedelta(days=1)),
        },
        {
            "key_fingerprint": fingerprint(runtime_key),
            "public_key_base64": base64.b64encode(public_bytes(runtime_key)).decode(
                "ascii"
            ),
            "roles": ["runtime-release"],
            "authority_source_codes": [],
            "status": "active",
            "not_before": utc(now - timedelta(days=1)),
            "expires_at": utc(now + timedelta(days=1)),
        },
    ]
    path = trust_dir / "capture-authorities.v1.json"
    path.write_text(
        json.dumps({"schema": TRUST_SCHEMA, "keys": keys}, sort_keys=True),
        encoding="utf-8",
    )
    if os.name != "nt":
        os.chmod(path, 0o600)


def install_fake_clutch(monkeypatch, *, raw: str = RAW) -> dict:
    state = {
        "raw": raw,
        "calls": 0,
        "fail": False,
        "mutate": None,
        "mutate_candidate": False,
        "native_locator_validated": False,
    }

    class SessionStore:
        pass

    @dataclass(frozen=True)
    class PromptEvidenceLocator:
        schema: str
        provider_code: str
        locator_id: str
        source_uri: str
        content_hash: str

        def __post_init__(self):
            state["native_locator_validated"] = True

    class ClutchEvidenceLocator:
        def __init__(self, store):
            self.store = store

        def resolve_content(self, candidate):
            state["calls"] += 1
            candidate.__post_init__()
            if state["mutate_candidate"]:
                candidate.content_hash = "f" * 64
            if state["mutate"] is not None:
                state["mutate"].content_hash = hashlib.sha256(
                    state["raw"].encode("utf-8")
                ).hexdigest()
            if state["fail"]:
                raise RuntimeError("synthetic failure")
            return state["raw"]

    clutch = types.ModuleType("clutch")
    evidence = types.ModuleType("clutch.evidence_locator")
    sessions = types.ModuleType("clutch.session_store")
    evidence.ClutchEvidenceLocator = ClutchEvidenceLocator
    evidence.PromptEvidenceLocator = PromptEvidenceLocator
    sessions.SessionStore = SessionStore
    monkeypatch.setitem(sys.modules, "clutch", clutch)
    monkeypatch.setitem(sys.modules, "clutch.evidence_locator", evidence)
    monkeypatch.setitem(sys.modules, "clutch.session_store", sessions)
    return state


@pytest.fixture
def authorized_context(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    monkeypatch.setattr(
        PromptEvidenceCollector,
        "_known_local_app_data",
        staticmethod(lambda: tmp_path),
    )
    collector = PromptEvidenceCollector()
    backend = install_fake_clutch(monkeypatch)
    authority_key = Ed25519PrivateKey.generate()
    runtime_key = Ed25519PrivateKey.generate()
    write_trust_store(collector, authority_key, runtime_key)
    now = datetime.now(UTC)
    adapter_path = Path(resolver_identity(registered_resolver)[1])
    adapter_hash = hashlib.sha256(adapter_path.read_bytes()).hexdigest()
    runtime = sign_runtime(
        runtime_key,
        adapter_sha256=adapter_hash,
        resolver=registered_resolver,
        now=now,
    )
    evidence_locator = locator()
    grant = sign_grant(
        authority_key,
        evidence_locator=evidence_locator,
        runtime_receipt=runtime,
        adapter_sha256=adapter_hash,
        now=now,
    )
    return {
        "collector": collector,
        "authority_key": authority_key,
        "runtime_key": runtime_key,
        "runtime": runtime,
        "backend": backend,
        "locator": evidence_locator,
        "grant": grant,
        "adapter_hash": adapter_hash,
        "now": now,
    }


def test_valid_grant_captures_once_and_emits_cloud_safe_receipt(authorized_context):
    context = authorized_context
    result = context["collector"].authorize_and_capture_from_locator(
        locator=context["locator"],
        grant=context["grant"],
        resolver_runtime_receipt=context["runtime"],
    )
    assert result.evidence_receipt.content_hash == context["locator"].content_hash
    assert result.consumption_receipt["grant_id"] == context["grant"]["grant_id"]
    assert result.consumption_receipt["consumption_status"] == "consumed"
    assert result.consumption_receipt["promotion_status"] == "not-reviewed"
    receipt_body = dict(result.consumption_receipt)
    receipt_hash = receipt_body.pop("receipt_sha256")
    assert receipt_hash == canonical_sha256(receipt_body)
    serialized = json.dumps(result.consumption_receipt, sort_keys=True)
    for forbidden in (
        RAW,
        str(context["collector"].root),
        "signature",
        "nonce",
        "resolution_receipt_id",
    ):
        assert forbidden not in serialized
    assert CaptureGrantLedger(context["collector"].root).state(
        context["grant"]["grant_id"]
    ) == "consumed"
    assert context["backend"]["native_locator_validated"] is True


def test_public_surface_exposes_only_authorized_capture(authorized_context):
    collector = authorized_context["collector"]
    assert not hasattr(collector, "capture")
    assert not hasattr(collector, "capture_from_locator")
    with pytest.raises(TypeError, match="resolver"):
        collector.authorize_and_capture_from_locator(
            locator=authorized_context["locator"],
            grant=authorized_context["grant"],
            resolver=registered_resolver,
            resolver_runtime_receipt=authorized_context["runtime"],
        )


def test_mutable_input_cannot_change_signed_snapshot(authorized_context):
    context = authorized_context
    signed = context["locator"]
    mutable = MutableLocator(
        schema=signed.schema,
        provider_code=signed.provider_code,
        locator_id=signed.locator_id,
        source_uri=signed.source_uri,
        content_hash=signed.content_hash,
    )
    context["backend"]["raw"] = "unauthorized-content"
    context["backend"]["mutate"] = mutable
    with pytest.raises(EvidenceIntegrityError, match="content hash mismatch"):
        context["collector"].authorize_and_capture_from_locator(
            locator=mutable,
            grant=context["grant"],
            resolver_runtime_receipt=context["runtime"],
        )
    assert mutable.content_hash == hashlib.sha256(
        b"unauthorized-content"
    ).hexdigest()
    assert list(context["collector"].receipt_dir.glob("pe-*.json")) == []


def test_registered_resolver_snapshot_is_frozen(authorized_context):
    context = authorized_context
    context["backend"]["mutate_candidate"] = True
    with pytest.raises(EvidenceNotFoundError):
        context["collector"].authorize_and_capture_from_locator(
            locator=context["locator"],
            grant=context["grant"],
            resolver_runtime_receipt=context["runtime"],
        )
    assert list(context["collector"].receipt_dir.glob("pe-*.json")) == []


def test_unregistered_resolver_export_is_rejected_before_call(authorized_context):
    context = authorized_context
    wrong_runtime = sign_runtime(
        context["runtime_key"],
        adapter_sha256=context["adapter_hash"],
        resolver=registered_resolver,
        qualname="alternate_resolve_content",
        now=context["now"],
    )
    wrong_grant = sign_grant(
        context["authority_key"],
        evidence_locator=context["locator"],
        runtime_receipt=wrong_runtime,
        adapter_sha256=context["adapter_hash"],
        now=context["now"],
    )
    with pytest.raises(CaptureAuthorizationError, match="internal registry"):
        context["collector"].authorize_and_capture_from_locator(
            locator=context["locator"],
            grant=wrong_grant,
            resolver_runtime_receipt=wrong_runtime,
        )
    assert context["backend"]["calls"] == 0


def test_replay_is_rejected_before_resolver(authorized_context):
    context = authorized_context
    context["collector"].authorize_and_capture_from_locator(
        locator=context["locator"],
        grant=context["grant"],
        resolver_runtime_receipt=context["runtime"],
    )
    with pytest.raises(CaptureGrantReplayError):
        context["collector"].authorize_and_capture_from_locator(
            locator=context["locator"],
            grant=context["grant"],
            resolver_runtime_receipt=context["runtime"],
        )
    assert context["backend"]["calls"] == 1


def test_bad_signature_and_expired_grant_fail_before_resolver(authorized_context):
    context = authorized_context
    bad_signature = context["grant"] | {
        "signature": base64.b64encode(b"\0" * 64).decode("ascii")
    }
    with pytest.raises(CaptureAuthorizationError, match="signature"):
        context["collector"].authorize_and_capture_from_locator(
            locator=context["locator"],
            grant=bad_signature,
            resolver_runtime_receipt=context["runtime"],
        )

    expired = sign_grant(
        context["authority_key"],
        evidence_locator=context["locator"],
        runtime_receipt=context["runtime"],
        adapter_sha256=context["adapter_hash"],
        now=context["now"],
        issued_at=context["now"] - timedelta(minutes=20),
        not_before=context["now"] - timedelta(minutes=20),
        expires_at=context["now"] - timedelta(minutes=10),
    )
    with pytest.raises(CaptureAuthorizationError, match="not currently valid"):
        context["collector"].authorize_and_capture_from_locator(
            locator=context["locator"],
            grant=expired,
            resolver_runtime_receipt=context["runtime"],
        )
    assert context["backend"]["calls"] == 0


def test_locator_and_runtime_mismatch_fail_before_resolver(authorized_context):
    context = authorized_context
    wrong_locator = locator("different")
    with pytest.raises(CaptureAuthorizationError, match="locator"):
        context["collector"].authorize_and_capture_from_locator(
            locator=wrong_locator,
            grant=context["grant"],
            resolver_runtime_receipt=context["runtime"],
        )

    wrong_runtime = sign_runtime(
        context["runtime_key"],
        adapter_sha256="f" * 64,
        resolver=registered_resolver,
        now=context["now"],
    )
    wrong_runtime_grant = sign_grant(
        context["authority_key"],
        evidence_locator=context["locator"],
        runtime_receipt=wrong_runtime,
        adapter_sha256="f" * 64,
        now=context["now"],
    )
    with pytest.raises(CaptureAuthorizationError, match="adapter hash mismatch"):
        context["collector"].authorize_and_capture_from_locator(
            locator=context["locator"],
            grant=wrong_runtime_grant,
            resolver_runtime_receipt=wrong_runtime,
        )
    assert context["backend"]["calls"] == 0


def test_failed_capture_consumes_grant_terminally(authorized_context):
    context = authorized_context
    context["backend"]["fail"] = True

    with pytest.raises(EvidenceNotFoundError):
        context["collector"].authorize_and_capture_from_locator(
            locator=context["locator"],
            grant=context["grant"],
            resolver_runtime_receipt=context["runtime"],
        )
    assert CaptureGrantLedger(context["collector"].root).state(
        context["grant"]["grant_id"]
    ) == "failed"
    with pytest.raises(CaptureGrantReplayError):
        context["collector"].authorize_and_capture_from_locator(
            locator=context["locator"],
            grant=context["grant"],
            resolver_runtime_receipt=context["runtime"],
        )
    assert context["backend"]["calls"] == 1
    assert list(context["collector"].raw_dir.glob("pe-*.txt")) == []
    assert list(context["collector"].receipt_dir.glob("pe-*.json")) == []


def test_prepared_capture_recovers_after_partial_publication(
    authorized_context,
    monkeypatch,
):
    context = authorized_context
    collector = context["collector"]
    original = collector._write_consumption_receipt
    calls = 0

    def fail_once(grant_id, receipt):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("synthetic publication interruption")
        return original(grant_id, receipt)

    monkeypatch.setattr(collector, "_write_consumption_receipt", fail_once)
    with pytest.raises(CaptureRecoveryRequiredError, match="requires recovery"):
        collector.authorize_and_capture_from_locator(
            locator=context["locator"],
            grant=context["grant"],
            resolver_runtime_receipt=context["runtime"],
        )
    ledger = CaptureGrantLedger(collector.root)
    assert ledger.state(context["grant"]["grant_id"]) == "prepared"
    assert len(list(collector.raw_dir.glob("pe-*.txt"))) == 1
    assert len(list(collector.receipt_dir.glob("pe-*.json"))) == 1

    recovered = collector.recover_prepared_capture(context["grant"]["grant_id"])
    assert recovered.evidence_receipt.content_hash == context["locator"].content_hash
    assert ledger.state(context["grant"]["grant_id"]) == "consumed"
    assert context["backend"]["calls"] == 1
    assert list((collector.root / "capture-staging").glob("attempt-*")) == []


def test_reserved_without_stage_reconciles_to_failed(
    authorized_context,
    monkeypatch,
):
    context = authorized_context
    collector = context["collector"]

    def crash_before_stage(*args, **kwargs):
        raise SystemExit("synthetic process crash after reservation")

    with monkeypatch.context() as crash:
        crash.setattr(collector, "_resolve_locator_content", crash_before_stage)
        with pytest.raises(SystemExit):
            collector.authorize_and_capture_from_locator(
                locator=context["locator"],
                grant=context["grant"],
                resolver_runtime_receipt=context["runtime"],
            )

    ledger = CaptureGrantLedger(collector.root)
    assert ledger.state(context["grant"]["grant_id"]) == "reserved"
    with pytest.raises(CaptureRecoveryRequiredError, match="terminally failed"):
        collector.recover_prepared_capture(context["grant"]["grant_id"])
    assert ledger.state(context["grant"]["grant_id"]) == "failed"


def test_reserved_with_complete_stage_reconciles_without_reresolution(
    authorized_context,
    monkeypatch,
):
    context = authorized_context
    collector = context["collector"]

    def crash_before_prepare(self, **kwargs):
        raise SystemExit("synthetic process crash before prepare")

    with monkeypatch.context() as crash:
        crash.setattr(CaptureGrantLedger, "prepare", crash_before_prepare)
        with pytest.raises(SystemExit):
            collector.authorize_and_capture_from_locator(
                locator=context["locator"],
                grant=context["grant"],
                resolver_runtime_receipt=context["runtime"],
            )

    ledger = CaptureGrantLedger(collector.root)
    assert ledger.state(context["grant"]["grant_id"]) == "reserved"
    assert len(list((collector.root / "capture-staging").glob("attempt-*"))) == 1
    recovered = collector.recover_prepared_capture(context["grant"]["grant_id"])
    assert recovered.evidence_receipt.content_hash == context["locator"].content_hash
    assert ledger.state(context["grant"]["grant_id"]) == "consumed"
    assert context["backend"]["calls"] == 1
    assert list((collector.root / "capture-staging").glob("attempt-*")) == []

    repeated = collector.recover_prepared_capture(context["grant"]["grant_id"])
    assert repeated.evidence_receipt == recovered.evidence_receipt
    assert context["backend"]["calls"] == 1


def test_concurrent_replay_has_exactly_one_winner(authorized_context):
    context = authorized_context
    def invoke():
        return context["collector"].authorize_and_capture_from_locator(
            locator=context["locator"],
            grant=context["grant"],
            resolver_runtime_receipt=context["runtime"],
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(invoke) for _ in range(2)]
    successes = [future for future in futures if future.exception() is None]
    failures = [future.exception() for future in futures if future.exception()]
    assert len(successes) == 1
    assert len(failures) == 1
    assert isinstance(failures[0], CaptureGrantReplayError)
    assert context["backend"]["calls"] == 1


def test_decision_avatar_requires_explicit_trust_scope(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    monkeypatch.setattr(
        PromptEvidenceCollector,
        "_known_local_app_data",
        staticmethod(lambda: tmp_path),
    )
    collector = PromptEvidenceCollector()
    install_fake_clutch(monkeypatch)
    authority_key = Ed25519PrivateKey.generate()
    runtime_key = Ed25519PrivateKey.generate()
    write_trust_store(collector, authority_key, runtime_key)
    now = datetime.now(UTC)
    adapter_path = Path(resolver_identity(registered_resolver)[1])
    adapter_hash = hashlib.sha256(adapter_path.read_bytes()).hexdigest()
    runtime = sign_runtime(
        runtime_key,
        adapter_sha256=adapter_hash,
        resolver=registered_resolver,
        now=now,
    )
    evidence_locator = locator()
    grant = sign_grant(
        authority_key,
        evidence_locator=evidence_locator,
        runtime_receipt=runtime,
        adapter_sha256=adapter_hash,
        now=now,
        authority_source="delegated-decision-avatar",
    )
    with pytest.raises(CaptureAuthorizationError, match="cannot issue"):
        collector.authorize_and_capture_from_locator(
            locator=evidence_locator,
            grant=grant,
            resolver_runtime_receipt=runtime,
        )
    write_trust_store(
        collector,
        authority_key,
        runtime_key,
        authority_sources=[
            "explicit-user-decision",
            "explicit-capture-policy",
            "delegated-decision-avatar",
        ],
    )
    result = collector.authorize_and_capture_from_locator(
        locator=evidence_locator,
        grant=grant,
        resolver_runtime_receipt=runtime,
    )
    assert result.consumption_receipt["authority_source_code"] == (
        "delegated-decision-avatar"
    )


def test_boolean_max_captures_is_rejected(authorized_context):
    context = authorized_context
    invalid = context["grant"] | {"max_captures": True}
    with pytest.raises(CaptureAuthorizationError, match="one-shot"):
        context["collector"].authorize_and_capture_from_locator(
            locator=context["locator"],
            grant=invalid,
            resolver_runtime_receipt=context["runtime"],
        )
