from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import MethodType, SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from prompt_evidence_collector.authorization import (
    CaptureAuthorizationError,
    CaptureGrantVerifier,
    ReadOnlyAuthorizationError,
    canonical_sha256,
)
from prompt_evidence_collector.cli import main as cli_main
from prompt_evidence_collector.collector import PromptEvidenceCollector
from prompt_evidence_collector.trust_enrollment import (
    ACTION_CODE,
    ACTIVATION_SCHEMA,
    BOOTSTRAP_SCHEMA,
    DECISION_REF,
    PROPOSAL_SCHEMA,
    TrustActivation,
    TrustEnroller,
    TrustEnrollmentError,
    TrustProposal,
    build_plan,
)

# Keep validity fixtures relative to the execution date so CI cannot expire
# merely because the repository is tested after the original fixture day.
NOW = datetime.now(UTC).replace(microsecond=0)


def _time(delta: timedelta) -> str:
    return (NOW + delta).isoformat(timespec="seconds").replace("+00:00", "Z")


def _public(private: Ed25519PrivateKey) -> bytes:
    return private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _key_record(private: Ed25519PrivateKey, role: str) -> dict:
    public = _public(private)
    return {
        "key_fingerprint": hashlib.sha256(public).hexdigest(),
        "public_key_base64": base64.b64encode(public).decode("ascii"),
        "roles": [role],
        "authority_source_codes": (
            ["explicit-user-decision"] if role == "capture-authority" else []
        ),
        "status": "active",
        "not_before": _time(timedelta(minutes=-5)),
        "expires_at": _time(timedelta(days=30)),
    }


def _proposal_value() -> tuple[dict, Ed25519PrivateKey, Ed25519PrivateKey]:
    capture = Ed25519PrivateKey.generate()
    runtime = Ed25519PrivateKey.generate()
    value = {
        "schema": PROPOSAL_SCHEMA,
        "proposal_id": "",
        "action_code": ACTION_CODE,
        "system_id": "ellmos-development-system",
        "host_id": "WORKSTATION-LG",
        "decision_ref": DECISION_REF,
        "issued_at": _time(timedelta(minutes=-5)),
        "not_before": _time(timedelta(minutes=-4)),
        "review_at": _time(timedelta(days=7)),
        "expires_at": _time(timedelta(days=30)),
        "constraints": {
            "provider_codes": ["clutch"],
            "purpose_codes": ["workflow-extraction"],
            "sensitivity_codes": ["private"],
            "retention_codes": ["local-review"],
            "max_grant_ttl_seconds": 900,
            "one_shot": True,
            "max_captures": 1,
        },
        "keys": [
            _key_record(capture, "capture-authority"),
            _key_record(runtime, "runtime-release"),
        ],
    }
    body = {key: item for key, item in value.items() if key != "proposal_id"}
    value["proposal_id"] = "tp-" + canonical_sha256(body)
    return value, capture, runtime


def _activation_value(
    proposal: TrustProposal,
    plan: dict,
    issuer: Ed25519PrivateKey,
) -> dict:
    public = _public(issuer)
    value = {
        "schema": ACTIVATION_SCHEMA,
        "activation_id": "",
        "action_code": ACTION_CODE,
        "proposal_id": proposal.proposal_id,
        "plan_sha256": plan["plan_sha256"],
        "system_id": proposal.system_id,
        "host_id": proposal.host_id,
        "decision_ref": DECISION_REF,
        "issuer_id": "explicit-user-bootstrap",
        "issuer_key_fingerprint": hashlib.sha256(public).hexdigest(),
        "issued_at": _time(timedelta(minutes=-3)),
        "not_before": _time(timedelta(minutes=-2)),
        "review_at": _time(timedelta(days=1)),
        "expires_at": _time(timedelta(days=2)),
        "signature_algorithm": "ed25519",
        "signature": "",
    }
    unsigned = {
        key: item for key, item in value.items() if key not in {"activation_id", "signature"}
    }
    value["activation_id"] = "ta-" + canonical_sha256(unsigned)
    signing = json.dumps(
        {"activation_id": value["activation_id"], "body": unsigned},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    value["signature"] = base64.b64encode(issuer.sign(signing)).decode("ascii")
    return value


def _secure_file(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
    PromptEvidenceCollector._restrict_private_store_child(path)


def _context(tmp_path: Path):
    root = tmp_path / "prompt-evidence"
    PromptEvidenceCollector._prepare_secure_store(root)
    bootstrap = root / "bootstrap"
    PromptEvidenceCollector._prepare_secure_store(bootstrap)
    proposal_value, _, _ = _proposal_value()
    proposal = TrustProposal.from_dict(proposal_value)
    plan = build_plan(proposal)
    issuer = Ed25519PrivateKey.generate()
    issuer_public = _public(issuer)
    activation_value = _activation_value(proposal, plan, issuer)
    bootstrap_value = {
        "schema": BOOTSTRAP_SCHEMA,
        "issuers": [
            {
                "issuer_id": "explicit-user-bootstrap",
                "key_fingerprint": hashlib.sha256(issuer_public).hexdigest(),
                "public_key_base64": base64.b64encode(issuer_public).decode("ascii"),
                "actions": [ACTION_CODE],
                "decision_refs": [DECISION_REF],
                "system_ids": [proposal.system_id],
                "host_ids": [proposal.host_id],
                "status": "active",
                "not_before": _time(timedelta(minutes=-10)),
                "expires_at": _time(timedelta(days=10)),
            }
        ],
    }
    _secure_file(bootstrap / "trust-activation-authorities.v1.json", bootstrap_value)
    return root, proposal, plan, TrustActivation.from_dict(activation_value), activation_value


def test_plan_is_deterministic_read_only_and_redacted(tmp_path):
    proposal_value, _, _ = _proposal_value()
    proposal = TrustProposal.from_dict(proposal_value)
    before = list(tmp_path.iterdir())
    first = build_plan(proposal)
    second = build_plan(proposal)
    assert first == second
    assert list(tmp_path.iterdir()) == before
    rendered = json.dumps(first)
    assert "public_key_base64" not in rendered
    assert "signature" not in rendered
    assert str(tmp_path) not in rendered
    assert first["plan_sha256"] == canonical_sha256(
        {key: value for key, value in first.items() if key != "plan_sha256"}
    )


@pytest.mark.parametrize(
    ("mutator", "match"),
    [
        (lambda value: value.update({"unknown": True}), "fields"),
        (lambda value: value["constraints"].update({"max_grant_ttl_seconds": 3601}), "TTL"),
        (lambda value: value["keys"].append(copy.deepcopy(value["keys"][0])), "two"),
        (
            lambda value: value["keys"][0].update(
                {"roles": ["capture-authority", "runtime-release"]}
            ),
            "separate",
        ),
        (lambda value: value["keys"][0].update({"private_key": "forbidden"}), "private"),
    ],
)
def test_proposal_fails_closed(mutator, match):
    value, _, _ = _proposal_value()
    mutator(value)
    with pytest.raises((TrustEnrollmentError, ValueError), match=match):
        TrustProposal.from_dict(value)


def test_apply_requires_fixed_bootstrap_store(tmp_path):
    value, _, _ = _proposal_value()
    proposal = TrustProposal.from_dict(value)
    plan = build_plan(proposal)
    issuer = Ed25519PrivateKey.generate()
    activation = TrustActivation.from_dict(_activation_value(proposal, plan, issuer))
    root = tmp_path / "store"
    PromptEvidenceCollector._prepare_secure_store(root)
    with pytest.raises(Exception, match="private store child|unavailable"):
        TrustEnroller(root).apply(
            proposal=proposal,
            activation=activation,
            expected_plan_sha256=plan["plan_sha256"],
            now=NOW,
        )


def test_apply_writes_only_v2_trust_and_existing_preflight_accepts_it(tmp_path):
    root, proposal, plan, activation, _ = _context(tmp_path)
    before = {path.relative_to(root).as_posix() for path in root.rglob("*")}
    result = TrustEnroller(root).apply(
        proposal=proposal,
        activation=activation,
        expected_plan_sha256=plan["plan_sha256"],
        now=NOW,
    )
    after = {path.relative_to(root).as_posix() for path in root.rglob("*")}
    assert after - before == {"trust", "trust/capture-authorities.v1.json"}
    assert result["capture_active"] is False
    trust = json.loads((root / "trust" / "capture-authorities.v1.json").read_text())
    assert trust["schema"] == "ellmos.prompt-evidence-trust-store.v2"
    assert trust["constraints"] == proposal.constraints
    report = CaptureGrantVerifier(
        root,
        private_path_validator=PromptEvidenceCollector._validate_private_store_child,
    ).preflight_trust_store(now=NOW)
    assert report["status"] == "valid"
    assert not (root / "capture-grants.sqlite3").exists()
    assert not (root / "consumption-receipts").exists()


def test_apply_rejects_tampered_signature_and_scope(tmp_path):
    root, proposal, plan, _, activation_value = _context(tmp_path)
    tampered = copy.deepcopy(activation_value)
    tampered["signature"] = base64.b64encode(b"x" * 64).decode("ascii")
    with pytest.raises(TrustEnrollmentError, match="signature verification"):
        TrustEnroller(root).apply(
            proposal=proposal,
            activation=TrustActivation.from_dict(tampered),
            expected_plan_sha256=plan["plan_sha256"],
            now=NOW,
        )
    assert not (root / "trust").exists()


def test_apply_is_no_overwrite_and_rollback_is_hash_bound(tmp_path):
    root, proposal, plan, activation, _ = _context(tmp_path)
    enroller = TrustEnroller(root)
    result = enroller.apply(
        proposal=proposal,
        activation=activation,
        expected_plan_sha256=plan["plan_sha256"],
        now=NOW,
    )
    with pytest.raises(TrustEnrollmentError, match="already exists"):
        enroller.apply(
            proposal=proposal,
            activation=activation,
            expected_plan_sha256=plan["plan_sha256"],
            now=NOW,
        )
    with pytest.raises(TrustEnrollmentError, match="changed"):
        enroller.rollback(expected_trust_sha256="0" * 64)
    rolled_back = enroller.rollback(expected_trust_sha256=result["trust_sha256"])
    assert rolled_back["status"] == "rolled-back-before-capture"
    assert not (root / "trust" / "capture-authorities.v1.json").exists()


def test_apply_concurrency_has_exactly_one_winner(tmp_path):
    root, proposal, plan, activation, _ = _context(tmp_path)

    def run():
        try:
            TrustEnroller(root).apply(
                proposal=proposal,
                activation=activation,
                expected_plan_sha256=plan["plan_sha256"],
                now=NOW,
            )
            return "won"
        except TrustEnrollmentError:
            return "lost"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: run(), range(2)))
    assert sorted(results) == ["lost", "won"]


def test_publish_failure_leaves_no_target_or_temp(tmp_path, monkeypatch):
    root, proposal, plan, activation, _ = _context(tmp_path)

    def fail_publish(source, target):
        raise OSError("simulated publish failure")

    monkeypatch.setattr(TrustEnroller, "_publish_no_replace", staticmethod(fail_publish))
    with pytest.raises(OSError, match="simulated"):
        TrustEnroller(root).apply(
            proposal=proposal,
            activation=activation,
            expected_plan_sha256=plan["plan_sha256"],
            now=NOW,
        )
    trust_dir = root / "trust"
    assert not (trust_dir / "capture-authorities.v1.json").exists()
    assert not list(trust_dir.glob("*.tmp"))


def test_published_target_survives_transient_temp_unlink_failure(tmp_path, monkeypatch):
    root, proposal, plan, activation, _ = _context(tmp_path)
    original_unlink = Path.unlink
    failed_once = False

    def link_without_removing_source(source, target):
        os.link(source, target)

    def fail_first_temp_unlink(path, *args, **kwargs):
        nonlocal failed_once
        if path.suffix == ".tmp" and not failed_once:
            failed_once = True
            raise OSError("simulated transient temp cleanup failure")
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(
        TrustEnroller,
        "_publish_no_replace",
        staticmethod(link_without_removing_source),
    )
    monkeypatch.setattr(Path, "unlink", fail_first_temp_unlink)
    result = TrustEnroller(root).apply(
        proposal=proposal,
        activation=activation,
        expected_plan_sha256=plan["plan_sha256"],
        now=NOW,
    )
    trust_dir = root / "trust"
    assert result["status"] == "enrolled"
    assert (trust_dir / "capture-authorities.v1.json").exists()
    assert not list(trust_dir.glob("*.tmp"))


def test_rollback_failure_preserves_fail_closed_hardlink_quarantine(tmp_path, monkeypatch):
    root, proposal, plan, activation, _ = _context(tmp_path)
    original_unlink = Path.unlink
    temp_unlink_calls = 0

    def link_without_removing_source(source, target):
        os.link(source, target)

    def fail_first_two_temp_unlinks(path, *args, **kwargs):
        nonlocal temp_unlink_calls
        if path.suffix == ".tmp":
            temp_unlink_calls += 1
            if temp_unlink_calls <= 2:
                raise OSError("simulated persistent temp cleanup failure")
        return original_unlink(path, *args, **kwargs)

    def fail_target_rollback(self):
        raise OSError("simulated target rollback failure")

    monkeypatch.setattr(
        TrustEnroller,
        "_publish_no_replace",
        staticmethod(link_without_removing_source),
    )
    monkeypatch.setattr(Path, "unlink", fail_first_two_temp_unlinks)
    monkeypatch.setattr(TrustEnroller, "_durable_remove_trust", fail_target_rollback)
    with pytest.raises(TrustEnrollmentError, match="recovery-required"):
        TrustEnroller(root).apply(
            proposal=proposal,
            activation=activation,
            expected_plan_sha256=plan["plan_sha256"],
            now=NOW,
        )
    trust_dir = root / "trust"
    target = trust_dir / "capture-authorities.v1.json"
    temps = list(trust_dir.glob("*.tmp"))
    assert target.exists()
    assert len(temps) == 1
    assert target.stat().st_nlink == 2
    assert temps[0].stat().st_ino == target.stat().st_ino
    assert temp_unlink_calls == 2


def test_cli_reports_recovery_required_with_stable_exit_code(tmp_path, monkeypatch, capsys):
    root, proposal, plan, activation, _ = _context(tmp_path)
    proposal_path = tmp_path / "proposal.json"
    activation_path = tmp_path / "activation.json"
    proposal_path.write_text(json.dumps(asdict(proposal)), encoding="utf-8")
    activation_path.write_text(json.dumps(asdict(activation)), encoding="utf-8")

    monkeypatch.setattr(
        PromptEvidenceCollector,
        "existing_store_root",
        classmethod(lambda cls: root),
    )

    def recovery_required(self, **kwargs):
        raise TrustEnrollmentError(
            "recovery-required: published trust rollback failed"
        )

    monkeypatch.setattr(TrustEnroller, "apply", recovery_required)
    exit_code = cli_main(
        [
            "trust-enroll",
            "apply",
            "--proposal",
            str(proposal_path),
            "--activation",
            str(activation_path),
            "--expected-plan-sha256",
            plan["plan_sha256"],
        ]
    )
    streams = capsys.readouterr()
    output = json.loads(streams.out)
    assert exit_code == 8
    assert output == {
        "schema": "ellmos.prompt-evidence-trust-enrollment-result.v1",
        "status": "invalid",
        "code": "recovery-required",
        "exit_code": 8,
    }
    assert streams.err == ""


def test_post_publish_preflight_failure_removes_exact_target(tmp_path, monkeypatch):
    root, proposal, plan, activation, _ = _context(tmp_path)

    def fail_preflight(self, *, now):
        raise RuntimeError("simulated post-publish failure")

    monkeypatch.setattr(CaptureGrantVerifier, "preflight_trust_store", fail_preflight)
    with pytest.raises(RuntimeError, match="post-publish"):
        TrustEnroller(root).apply(
            proposal=proposal,
            activation=activation,
            expected_plan_sha256=plan["plan_sha256"],
            now=NOW,
        )
    assert not (root / "trust" / "capture-authorities.v1.json").exists()


def test_bootstrap_hardlink_is_rejected(tmp_path):
    root, proposal, plan, activation, _ = _context(tmp_path)
    bootstrap = root / "bootstrap" / "trust-activation-authorities.v1.json"
    alias = root / "bootstrap" / "alias.json"
    try:
        os.link(bootstrap, alias)
    except OSError:
        pytest.skip("hard links are unavailable on this filesystem")
    with pytest.raises(TrustEnrollmentError, match="bounded private file"):
        TrustEnroller(root).apply(
            proposal=proposal,
            activation=activation,
            expected_plan_sha256=plan["plan_sha256"],
            now=NOW,
        )
    assert not (root / "trust").exists()


def test_apply_uses_deep_validated_snapshots_under_mutation(tmp_path, monkeypatch):
    root, proposal, plan, activation, _ = _context(tmp_path)
    original_fingerprints = sorted(item["key_fingerprint"] for item in proposal.keys)
    entered = threading.Event()
    release = threading.Event()
    original_loader = TrustEnroller._load_bootstrap_issuer

    def blocked_loader(self, activation_value, now):
        entered.set()
        assert release.wait(5)
        return original_loader(self, activation_value, now)

    monkeypatch.setattr(TrustEnroller, "_load_bootstrap_issuer", blocked_loader)
    result = {}

    def run_apply():
        result.update(
            TrustEnroller(root).apply(
                proposal=proposal,
                activation=activation,
                expected_plan_sha256=plan["plan_sha256"],
                now=NOW,
            )
        )

    worker = threading.Thread(target=run_apply)
    worker.start()
    assert entered.wait(5)
    proposal.keys[0]["roles"] = ["runtime-release"]
    proposal.constraints["retention_codes"] = ["legal-hold"]
    release.set()
    worker.join(30)
    assert not worker.is_alive()
    trust = json.loads((root / "trust" / "capture-authorities.v1.json").read_text())
    assert sorted(item["key_fingerprint"] for item in trust["keys"]) == original_fingerprints
    assert trust["constraints"]["retention_codes"] == ["local-review"]
    assert result["status"] == "enrolled"


def test_capture_and_rollback_share_lifecycle_lock(tmp_path, monkeypatch):
    root, proposal, plan, activation, _ = _context(tmp_path)
    applied = TrustEnroller(root).apply(
        proposal=proposal,
        activation=activation,
        expected_plan_sha256=plan["plan_sha256"],
        now=NOW,
    )
    collector = object.__new__(PromptEvidenceCollector)
    collector._store_root = root
    entered = threading.Event()
    release = threading.Event()

    def held_capture(self, **kwargs):
        entered.set()
        assert release.wait(5)
        return "capture-finished"

    collector._authorize_and_capture_from_locator_locked = MethodType(held_capture, collector)
    capture_result = {}
    rollback_result = {}

    capture_thread = threading.Thread(
        target=lambda: capture_result.update(
            value=collector.authorize_and_capture_from_locator(
                locator=object(), grant={}, resolver_runtime_receipt={}
            )
        )
    )
    rollback_thread = threading.Thread(
        target=lambda: rollback_result.update(
            TrustEnroller(root).rollback(expected_trust_sha256=applied["trust_sha256"])
        )
    )
    capture_thread.start()
    assert entered.wait(5)
    rollback_thread.start()
    time.sleep(0.2)
    assert rollback_thread.is_alive()
    assert (root / "trust" / "capture-authorities.v1.json").exists()
    release.set()
    capture_thread.join(10)
    rollback_thread.join(10)
    assert capture_result["value"] == "capture-finished"
    assert rollback_result["status"] == "rolled-back-before-capture"


def test_rollback_refuses_after_evidence_state(tmp_path):
    root, proposal, plan, activation, _ = _context(tmp_path)
    enroller = TrustEnroller(root)
    result = enroller.apply(
        proposal=proposal,
        activation=activation,
        expected_plan_sha256=plan["plan_sha256"],
        now=NOW,
    )
    receipts = root / "receipts"
    PromptEvidenceCollector._prepare_secure_store(receipts)
    _secure_file(receipts / ("pe-" + "0" * 64 + ".json"), {})
    with pytest.raises(TrustEnrollmentError, match="retirement"):
        enroller.rollback(expected_trust_sha256=result["trust_sha256"])


def test_v2_constraints_are_enforced_for_future_grants(tmp_path):
    root, proposal, plan, activation, _ = _context(tmp_path)
    TrustEnroller(root).apply(
        proposal=proposal,
        activation=activation,
        expected_plan_sha256=plan["plan_sha256"],
        now=NOW,
    )
    trust = CaptureGrantVerifier(
        root,
        private_path_validator=PromptEvidenceCollector._validate_private_store_child,
    )._load_trust_store()
    grant = SimpleNamespace(
        provider_code="clutch",
        purpose_code="workflow-extraction",
        capture_policy={"sensitivity_code": "private", "retention_code": "local-review"},
        issued_at=_time(timedelta()),
        expires_at=_time(timedelta(minutes=10)),
        one_shot=True,
        max_captures=1,
    )
    CaptureGrantVerifier._validate_grant_constraints(trust=trust, grant=grant)
    grant.capture_policy["retention_code"] = "legal-hold"
    with pytest.raises(CaptureAuthorizationError, match="constraints"):
        CaptureGrantVerifier._validate_grant_constraints(trust=trust, grant=grant)


def test_constraint_violation_is_scope_mismatch_not_invalid_trust(tmp_path, monkeypatch):
    root = tmp_path / "store"
    PromptEvidenceCollector._prepare_secure_store(root)
    verifier = CaptureGrantVerifier(root)
    trust = {
        "schema": "ellmos.prompt-evidence-trust-store.v2",
        "keys": [],
        "constraints": {
            "provider_codes": ["clutch"],
            "purpose_codes": ["workflow-extraction"],
            "sensitivity_codes": ["private"],
            "retention_codes": ["local-review"],
            "max_grant_ttl_seconds": 900,
            "one_shot": True,
            "max_captures": 1,
        },
    }
    monkeypatch.setattr(verifier, "_load_trust_store", lambda: trust)
    grant = SimpleNamespace(
        validate_structure=lambda: None,
        issued_at=_time(timedelta(minutes=-1)),
        not_before=_time(timedelta(minutes=-1)),
        expires_at=_time(timedelta(minutes=10)),
        provider_code="clutch",
        purpose_code="workflow-extraction",
        capture_policy={"sensitivity_code": "private", "retention_code": "legal-hold"},
        one_shot=True,
        max_captures=1,
    )
    runtime = SimpleNamespace(
        validate_structure=lambda: None,
        issued_at=_time(timedelta(minutes=-1)),
        expires_at=_time(timedelta(minutes=10)),
    )
    with pytest.raises(ReadOnlyAuthorizationError) as captured:
        verifier.validate_signed_authorization(
            grant=grant,
            runtime_receipt=runtime,
            now=NOW,
        )
    assert captured.value.code == "scope-mismatch"
    assert captured.value.exit_code == 6


def test_cli_plan_apply_and_rollback_use_canonical_store_only(tmp_path, monkeypatch, capsys):
    root, proposal, plan, activation, _ = _context(tmp_path)
    proposal_path = tmp_path / "proposal.json"
    activation_path = tmp_path / "activation.json"
    proposal_path.write_text(json.dumps(asdict(proposal)), encoding="utf-8")
    activation_path.write_text(json.dumps(asdict(activation)), encoding="utf-8")
    monkeypatch.setattr(
        PromptEvidenceCollector,
        "existing_store_root",
        classmethod(lambda cls: root),
    )
    assert cli_main(["trust-enroll", "plan", "--proposal", str(proposal_path)]) == 0
    plan_output = json.loads(capsys.readouterr().out)
    assert plan_output == plan
    assert cli_main(
        [
            "trust-enroll",
            "apply",
            "--proposal",
            str(proposal_path),
            "--activation",
            str(activation_path),
            "--expected-plan-sha256",
            plan["plan_sha256"],
        ]
    ) == 0
    apply_output = json.loads(capsys.readouterr().out)
    assert apply_output["status"] == "enrolled"
    assert cli_main(
        [
            "trust-enroll",
            "rollback",
            "--expected-trust-sha256",
            apply_output["trust_sha256"],
        ]
    ) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "rolled-back-before-capture"
