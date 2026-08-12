"""Privacy- und Fail-Closed-Tests für Prompt-Evidence."""

import hashlib
import json
import os
from dataclasses import dataclass, replace
from pathlib import Path

import pytest

from prompt_evidence_collector.cli import main as cli_main
from prompt_evidence_collector.collector import (
    AmbiguousEvidenceError,
    EvidenceIntegrityError,
    EvidenceNotFoundError,
    PromotionGate,
    PromotionGateError,
    PromptEvidenceCollector,
    PromptEvidenceReceipt,
    UnsafeEvidenceStoreError,
)


@pytest.fixture
def collector(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    monkeypatch.setattr(
        PromptEvidenceCollector,
        "_known_local_app_data",
        staticmethod(lambda: tmp_path),
    )
    return PromptEvidenceCollector()


def capture(collector, *, raw="streng privat", captured_at="2026-07-30T08:00:00Z"):
    return collector._capture(
        provider_code="clutch",
        origin_code="clutch-session-store",
        captured_at=captured_at,
        raw_content=raw,
        sensitivity_code="private",
        retention_code="local-review",
        source_locator_id="loc-" + "a" * 64,
        source_content_hash="b" * 64,
    )


@dataclass(frozen=True)
class Locator:
    schema: str
    provider_code: str
    locator_id: str
    source_uri: str
    content_hash: str


def locator_for(raw: str = "streng privat") -> Locator:
    content_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    locator_id = "loc-" + "c" * 64
    return Locator(
        schema="ellmos.prompt-evidence-locator.v2",
        provider_code="clutch",
        locator_id=locator_id,
        source_uri=f"clutch-local://evidence/{locator_id}",
        content_hash=content_hash,
    )


def test_capture_from_locator_verifies_and_projects_clutch_evidence(collector):
    raw = "streng privat"
    locator = locator_for(raw)

    receipt = collector._capture_from_locator(
        locator=locator,
        resolve_content=lambda candidate: raw,
        captured_at="2026-08-01T09:00:00Z",
        sensitivity_code="private",
        retention_code="local-review",
    )

    assert receipt.provider_code == "clutch"
    assert receipt.origin_code == "clutch-session-store"
    assert receipt.source_locator_id == locator.locator_id
    assert receipt.source_content_hash == locator.content_hash
    assert receipt.promotion_status == "not-reviewed"
    assert collector.read_raw(
        receipt.evidence_id,
        expected_hash=locator.content_hash,
    ) == raw


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema", "ellmos.prompt-evidence-locator.v1"),
        ("provider_code", "openai"),
        ("locator_id", "not-opaque"),
        ("source_uri", "file:///private/session.db"),
        ("content_hash", "not-a-hash"),
    ],
)
def test_capture_from_locator_rejects_untrusted_locator_before_resolve(
    collector,
    field,
    value,
):
    locator = replace(locator_for(), **{field: value})
    resolver_called = False

    def resolver(candidate):
        nonlocal resolver_called
        resolver_called = True
        return "streng privat"

    with pytest.raises(EvidenceIntegrityError):
        collector._capture_from_locator(
            locator=locator,
            resolve_content=resolver,
            captured_at="2026-08-01T09:00:00Z",
            sensitivity_code="private",
            retention_code="local-review",
        )
    assert resolver_called is False


def test_capture_from_locator_rejects_tampered_or_unavailable_content(collector):
    locator = locator_for("expected")
    with pytest.raises(EvidenceIntegrityError, match="hash mismatch"):
        collector._capture_from_locator(
            locator=locator,
            resolve_content=lambda candidate: "tampered",
            captured_at="2026-08-01T09:00:00Z",
            sensitivity_code="private",
            retention_code="local-review",
        )
    with pytest.raises(EvidenceNotFoundError, match="could not be resolved"):
        collector._capture_from_locator(
            locator=locator,
            resolve_content=lambda candidate: (_ for _ in ()).throw(
                RuntimeError("offline")
            ),
            captured_at="2026-08-01T09:00:00Z",
            sensitivity_code="private",
            retention_code="local-review",
        )


def test_capture_projects_only_codes_opaque_ids_and_hashes(collector):
    receipt = capture(collector)
    projected = receipt.to_dict()
    serialized = json.dumps(projected, sort_keys=True)

    assert receipt.evidence_id.startswith("pe-")
    assert receipt.raw_object_id == receipt.evidence_id
    assert "streng privat" not in serialized
    assert str(collector.root) not in serialized
    assert "://" not in serialized
    assert "?" not in serialized
    assert "#" not in serialized
    assert set(projected) == {
        "schema",
        "evidence_id",
        "provider_code",
        "origin_code",
        "captured_at",
        "content_hash",
        "sensitivity_code",
        "retention_code",
        "raw_object_id",
        "promotion_status",
        "source_locator_id",
        "source_content_hash",
    }


def test_store_is_derived_from_app_local_data_root(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    monkeypatch.setattr(
        PromptEvidenceCollector,
        "_known_local_app_data",
        staticmethod(lambda: tmp_path),
    )
    collector = PromptEvidenceCollector()
    assert collector.root == (
        tmp_path / "prompt-evidence-collector" / "prompt-evidence"
    ).resolve()


def test_known_sync_root_fails_closed(tmp_path, monkeypatch):
    sync_root = tmp_path / "OneDrive"
    sync_root.mkdir()
    monkeypatch.setenv("LOCALAPPDATA", str(sync_root))
    monkeypatch.setenv("XDG_DATA_HOME", str(sync_root))
    monkeypatch.setattr(
        PromptEvidenceCollector,
        "_known_local_app_data",
        staticmethod(lambda: sync_root),
    )
    with pytest.raises(UnsafeEvidenceStoreError):
        PromptEvidenceCollector()


def test_symlink_or_reparse_root_fails_closed(tmp_path, monkeypatch):
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "linked-local-data"
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation is unavailable")
    monkeypatch.setenv("LOCALAPPDATA", str(link))
    monkeypatch.setenv("XDG_DATA_HOME", str(link))
    monkeypatch.setattr(
        PromptEvidenceCollector,
        "_known_local_app_data",
        staticmethod(lambda: link),
    )
    with pytest.raises(UnsafeEvidenceStoreError):
        PromptEvidenceCollector()


@pytest.mark.skipif(
    os.name != "nt",
    reason="LOCALAPPDATA Known Folder validation is Windows-specific",
)
def test_manipulated_localappdata_fails_closed(tmp_path, monkeypatch):
    known = tmp_path / "known"
    configured = tmp_path / "configured"
    known.mkdir()
    configured.mkdir()
    monkeypatch.setenv("LOCALAPPDATA", str(configured))
    monkeypatch.setattr(
        PromptEvidenceCollector,
        "_known_local_app_data",
        staticmethod(lambda: known),
    )
    with pytest.raises(UnsafeEvidenceStoreError, match="Known Folder"):
        PromptEvidenceCollector()


def test_foreign_or_inherited_allow_ace_fails_closed():
    base = {
        "CurrentSid": "S-1-5-21-1000",
        "OwnerSid": "S-1-5-21-1000",
        "Rules": [
            {
                "Sid": "S-1-5-21-1000",
                "Type": "Allow",
                "Rights": "FullControl",
                "Inherited": False,
            }
        ],
    }
    PromptEvidenceCollector._validate_windows_acl_snapshot(base)
    foreign = {
        **base,
        "Rules": [
            *base["Rules"],
            {
                "Sid": "S-1-5-21-9999",
                "Type": "Allow",
                "Rights": "ReadAndExecute",
                "Inherited": False,
            },
        ],
    }
    with pytest.raises(UnsafeEvidenceStoreError, match="foreign"):
        PromptEvidenceCollector._validate_windows_acl_snapshot(foreign)
    inherited = {
        **base,
        "Rules": [{**base["Rules"][0], "Inherited": True}],
    }
    with pytest.raises(UnsafeEvidenceStoreError, match="inherited"):
        PromptEvidenceCollector._validate_windows_acl_snapshot(inherited)


def test_private_child_acl_allows_only_owner_rights_for_current_owner():
    owner_rights = {
        "CurrentSid": "S-1-5-21-1000",
        "OwnerSid": "S-1-5-21-1000",
        "Rules": [
            {
                "Sid": "S-1-3-4",
                "Type": "Allow",
                "Rights": "FullControl",
                "Inherited": True,
            }
        ],
    }
    PromptEvidenceCollector._validate_windows_acl_snapshot(
        owner_rights,
        allow_safe_inherited=True,
    )
    foreign = {
        **owner_rights,
        "Rules": [
            *owner_rights["Rules"],
            {
                "Sid": "S-1-5-21-9999",
                "Type": "Allow",
                "Rights": "ReadAndExecute",
                "Inherited": True,
            },
        ],
    }
    with pytest.raises(UnsafeEvidenceStoreError, match="foreign"):
        PromptEvidenceCollector._validate_windows_acl_snapshot(
            foreign,
            allow_safe_inherited=True,
        )
    wrong_owner = {**owner_rights, "OwnerSid": "S-1-5-32-544"}
    with pytest.raises(UnsafeEvidenceStoreError, match="foreign"):
        PromptEvidenceCollector._validate_windows_acl_snapshot(
            wrong_owner,
            allow_safe_inherited=True,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("provider_code", "custom/provider"),
        ("origin_code", "C:/session.db"),
        ("sensitivity_code", "free text"),
        ("retention_code", "forever maybe"),
        ("promotion_status", "auto-publish"),
        ("source_locator_id", "session-id"),
        ("source_content_hash", "not-a-hash"),
    ],
)
def test_unbounded_receipt_fields_are_rejected(collector, field, value):
    values = {
        "provider_code": "clutch",
        "origin_code": "clutch-session-store",
        "captured_at": "2026-07-30T08:00:00Z",
        "raw_content": "private",
        "sensitivity_code": "private",
        "retention_code": "local-review",
        "source_locator_id": "loc-" + "a" * 64,
        "source_content_hash": "b" * 64,
        "promotion_status": "not-reviewed",
    }
    values[field] = value
    with pytest.raises(ValueError):
        collector._capture(**values)


def test_missing_and_ambiguous_receipts_fail_closed(collector):
    with pytest.raises(EvidenceNotFoundError):
        collector.find_one(provider_code="openai")
    capture(collector, raw="one", captured_at="2026-07-30T08:00:00Z")
    capture(collector, raw="two", captured_at="2026-07-30T08:01:00Z")
    with pytest.raises(AmbiguousEvidenceError):
        collector.find_one(provider_code="clutch")


def test_hash_tampering_fails_closed(collector):
    receipt = capture(collector)
    with pytest.raises(EvidenceIntegrityError):
        collector.read_raw(receipt.evidence_id, expected_hash="0" * 64)


def test_receipt_constructor_rejects_invalid_schema_fields_and_identity(collector):
    receipt = capture(collector)
    with pytest.raises(EvidenceIntegrityError):
        replace(receipt, schema="ellmos.prompt-evidence-receipt.v1")
    with pytest.raises(EvidenceIntegrityError):
        replace(receipt, provider_code="unbounded-provider")
    with pytest.raises(EvidenceIntegrityError):
        replace(receipt, captured_at="2026-07-30T08:00:00+02:00")
    with pytest.raises(EvidenceIntegrityError):
        replace(receipt, content_hash="not-a-hash")
    with pytest.raises(EvidenceIntegrityError):
        replace(receipt, evidence_id="pe-" + "f" * 64)


def test_readback_rejects_unknown_fields_and_raw_object_traversal(collector):
    receipt = capture(collector)
    receipt_path = collector.receipt_dir / f"{receipt.evidence_id}.json"
    value = receipt.to_dict()
    value["unexpected"] = "field"
    receipt_path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(EvidenceIntegrityError):
        collector.find_one(evidence_id=receipt.evidence_id)

    outside_content = "matching outside content"
    outside_path = collector.root / "outside.txt"
    outside_path.write_text(outside_content, encoding="utf-8")
    outside_hash = hashlib.sha256(
        outside_content.encode("utf-8")
    ).hexdigest()
    value = receipt.to_dict()
    value["raw_object_id"] = "../outside"
    value["content_hash"] = outside_hash
    receipt_path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(EvidenceIntegrityError):
        collector.read_raw(receipt.evidence_id, expected_hash=outside_hash)


def test_raw_object_symlink_fails_closed(collector):
    receipt = capture(collector)
    raw_path = collector.raw_dir / f"{receipt.evidence_id}.txt"
    outside = collector.root / "outside-raw.txt"
    outside.write_text("streng privat", encoding="utf-8")
    raw_path.unlink()
    try:
        raw_path.symlink_to(outside)
    except OSError:
        pytest.skip("symlink creation is unavailable")
    with pytest.raises(EvidenceIntegrityError, match="reparse point"):
        collector.read_raw(
            receipt.evidence_id,
            expected_hash=receipt.content_hash,
        )


def test_direct_receipt_construction_requires_exact_source_pair(collector):
    receipt = capture(collector)
    values = receipt.to_dict()
    values["source_content_hash"] = None
    with pytest.raises(EvidenceIntegrityError):
        PromptEvidenceReceipt(**values)


def test_capture_and_readback_revalidate_bound_store_parents(
    collector,
    tmp_path,
):
    raw_outside = tmp_path / "outside-raw-parent"
    raw_outside.mkdir()
    collector.raw_dir = raw_outside
    with pytest.raises(
        UnsafeEvidenceStoreError,
        match="raw evidence directory binding changed",
    ):
        capture(collector)

    collector.raw_dir = collector._raw_root
    receipt_outside = tmp_path / "outside-receipt-parent"
    receipt_outside.mkdir()
    collector.receipt_dir = receipt_outside
    with pytest.raises(
        UnsafeEvidenceStoreError,
        match="receipt evidence directory binding changed",
    ):
        collector.find_one(provider_code="clutch")


def test_capture_revalidates_store_acl_after_initialization(
    collector,
    monkeypatch,
):
    if os.name == "nt":
        monkeypatch.setattr(
            PromptEvidenceCollector,
            "_read_windows_acl",
            classmethod(
                lambda cls, root: {
                    "CurrentSid": "S-1-5-21-1000",
                    "OwnerSid": "S-1-5-21-1000",
                    "Rules": [
                        {
                            "Sid": "S-1-5-21-9999",
                            "Type": "Allow",
                            "Rights": "ReadAndExecute",
                            "Inherited": False,
                        }
                    ],
                }
            ),
        )
        with pytest.raises(UnsafeEvidenceStoreError, match="foreign"):
            capture(collector)
    else:
        os.chmod(collector.root, 0o755)
        try:
            with pytest.raises(
                UnsafeEvidenceStoreError,
                match="mode is not private",
            ):
                capture(collector)
        finally:
            os.chmod(collector.root, 0o700)


def test_existing_reparse_object_is_rejected_without_read(
    collector,
    monkeypatch,
):
    receipt = capture(collector)
    raw_path = collector.raw_dir / f"{receipt.evidence_id}.txt"
    original_is_symlink = Path.is_symlink
    original_read_text = Path.read_text
    read_attempted = False

    def simulated_symlink(path):
        return path == raw_path or original_is_symlink(path)

    def guarded_read(path, *args, **kwargs):
        nonlocal read_attempted
        if path == raw_path:
            read_attempted = True
            raise AssertionError("reparse object must not be read")
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "is_symlink", simulated_symlink)
    monkeypatch.setattr(Path, "read_text", guarded_read)
    with pytest.raises(EvidenceIntegrityError, match="reparse point"):
        capture(collector)
    assert read_attempted is False


@pytest.mark.parametrize("promotion_status", ["rejected", "candidate", "curated"])
def test_capture_cannot_promote_without_explicit_gate(collector, promotion_status):
    with pytest.raises(PromotionGateError, match="explicit gate"):
        collector._capture(
            provider_code="clutch",
            origin_code="clutch-session-store",
            captured_at="2026-07-30T08:00:00Z",
            raw_content="streng privat",
            sensitivity_code="private",
            retention_code="local-review",
            promotion_status=promotion_status,
        )


def test_promotion_gate_is_audited_idempotent_and_preserves_identity(collector):
    receipt = capture(collector)
    gate = PromotionGate.build(
        evidence_id=receipt.evidence_id,
        from_status="not-reviewed",
        to_status="candidate",
        authority_source_code="explicit-user-decision",
        authorization_ref="D-20260810-001",
        issued_at="2026-08-10T08:00:00Z",
    )

    promoted = collector.transition_promotion(evidence_id=receipt.evidence_id, gate=gate)
    repeated = collector.transition_promotion(evidence_id=receipt.evidence_id, gate=gate)

    assert promoted.evidence_id == receipt.evidence_id
    assert promoted.content_hash == receipt.content_hash
    assert promoted.promotion_status == "candidate"
    assert repeated == promoted
    assert collector.read_raw(
        receipt.evidence_id,
        expected_hash=receipt.content_hash,
    ) == "streng privat"
    audit = json.loads(
        (collector.promotion_dir / f"{gate.gate_id}.json").read_bytes().decode("utf-8")
    )
    assert "streng privat" not in json.dumps(audit)
    assert audit["status"] == "applied"


@pytest.mark.parametrize(
    "gate_mutator",
    [
        lambda gate: {**gate.to_dict(), "to_status": "curated"},
        lambda gate: {key: value for key, value in gate.to_dict().items() if key != "authorization_ref"},
    ],
)
def test_invalid_or_stale_promotion_gate_fails_closed(collector, gate_mutator):
    receipt = capture(collector)
    gate = PromotionGate.build(
        evidence_id=receipt.evidence_id,
        from_status="not-reviewed",
        to_status="candidate",
        authority_source_code="explicit-capture-policy",
        authorization_ref="policy-20260810-001",
        issued_at="2026-08-10T08:00:00Z",
    )
    with pytest.raises(PromotionGateError):
        collector.transition_promotion(
            evidence_id=receipt.evidence_id,
            gate=gate_mutator(gate),
        )


@pytest.mark.parametrize(
    "raw",
    [
        "erste\nzweite",
        "erste\r\nzweite",
        "erste\r\nzweite\n",
        "erste\rzweite\n第三行\r\n",
        "ümlaut\n雪\r\nfin",
    ],
)
def test_raw_bytes_and_hash_are_stable_across_line_endings(collector, raw):
    receipt = capture(collector, raw=raw, captured_at="2026-07-30T08:00:00Z")
    expected = raw.encode("utf-8")
    raw_path = collector.raw_dir / f"{receipt.evidence_id}.txt"

    assert raw_path.read_bytes() == expected
    assert receipt.content_hash == hashlib.sha256(expected).hexdigest()
    assert collector.read_raw(receipt.evidence_id, expected_hash=receipt.content_hash) == raw


def test_raw_byte_mutation_still_fails_closed(collector):
    receipt = capture(collector, raw="erste\r\nzweite")
    raw_path = collector.raw_dir / f"{receipt.evidence_id}.txt"
    raw_path.write_bytes(raw_path.read_bytes() + b"x")
    with pytest.raises(EvidenceIntegrityError):
        collector.read_raw(receipt.evidence_id, expected_hash=receipt.content_hash)


def test_doctor_detects_unpaired_and_temporary_capture_objects(collector, monkeypatch):
    original = collector._publish_no_overwrite
    calls = 0

    def fail_after_raw(**kwargs):
        nonlocal calls
        calls += 1
        result = original(**kwargs)
        if calls == 1:
            raise OSError("simulated crash between pair commits")
        return result

    monkeypatch.setattr(collector, "_publish_no_overwrite", fail_after_raw)
    with pytest.raises(OSError, match="simulated crash"):
        capture(collector, raw="crash\r\nfixture")

    inventory = collector.store_inventory()
    assert inventory["status"] == "invalid"
    assert inventory["incomplete_pair_count"] == 1
    assert inventory["orphan_raw_count"] == 1
    assert inventory["pending_pair_count"] == 1
    assert inventory["temporary_file_count"] >= 2


def test_cli_doctor_reports_empty_healthy_store_without_capture(collector, capsys):
    assert cli_main(["doctor"]) == 0
    output = capsys.readouterr().out
    report = json.loads(output)
    assert report["schema"] == "ellmos.prompt-evidence-collector-doctor.v3"
    assert report["status"] == "valid"
    assert report["exit_code"] == 0
    assert report["receipt_count"] == 0
    assert "provider" not in output.lower()
    assert "clutch-local://" not in output


def test_cli_doctor_counts_only_structurally_valid_receipts(collector, capsys):
    receipt = capture(collector, raw="doctor secret")
    receipt_path = collector.receipt_dir / f"{receipt.evidence_id}.json"
    receipt_path.write_bytes(b'{"content_hash": ["not-a-hash"]}')

    before = receipt_path.read_bytes()
    assert cli_main(["doctor"]) == 3
    output = capsys.readouterr().out
    report = json.loads(output)
    assert report["status"] == "invalid"
    assert report["receipt_count"] == 0
    assert report["invalid_receipt_count"] == 1
    assert "doctor secret" not in output
    assert receipt_path.read_bytes() == before


def test_cli_doctor_reports_unknown_objects_and_raw_mismatch(collector, capsys):
    receipt = capture(collector, raw="doctor secret")
    (collector.raw_dir / "unexpected.bin").write_bytes(b"foreign raw text")
    raw_path = collector.raw_dir / f"{receipt.evidence_id}.txt"
    raw_path.write_bytes(raw_path.read_bytes() + b"tampered")

    assert cli_main(["doctor"]) == 3
    output = capsys.readouterr().out
    report = json.loads(output)
    assert report["status"] == "invalid"
    assert report["receipt_count"] == 0
    assert report["structural_receipt_count"] == 1
    assert report["invalid_pair_count"] == 1
    assert report["unknown_object_count"] == 1
    assert "foreign raw text" not in output
    assert "doctor secret" not in output


def test_cli_doctor_reports_orphan_and_pending_objects(collector, capsys):
    receipt = capture(collector, raw="orphan secret")
    raw_path = collector.raw_dir / f"{receipt.evidence_id}.txt"
    raw_path.unlink()
    pending = collector.pair_dir / f"{receipt.evidence_id}.pending.json"
    pending.write_bytes(b'{"schema":"ellmos.prompt-evidence-pair.v1"}')

    assert cli_main(["doctor"]) == 3
    output = capsys.readouterr().out
    report = json.loads(output)
    assert report["status"] == "invalid"
    assert report["receipt_count"] == 0
    assert report["structural_receipt_count"] == 1
    assert report["orphan_receipt_count"] == 1
    assert report["pending_pair_count"] == 1
    assert "orphan secret" not in output


def test_cli_doctor_reports_reparse_objects_without_following_them(collector, capsys):
    outside = collector.root / "outside-doctor-secret.txt"
    outside.write_text("reparse secret", encoding="utf-8")
    link = collector.raw_dir / "unexpected-link.txt"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("symlink creation is unavailable")

    assert cli_main(["doctor"]) == 3
    output = capsys.readouterr().out
    report = json.loads(output)
    assert report["status"] == "invalid"
    assert report["reparse_object_count"] == 1
    assert "reparse secret" not in output


@pytest.mark.parametrize("evidence_id", ["loc-" + "a" * 64, 1, [], {}, None])
def test_find_one_rejects_non_evidence_ids_deterministically(collector, evidence_id):
    with pytest.raises(EvidenceNotFoundError):
        collector.find_one(evidence_id=evidence_id)


@pytest.mark.parametrize("source_locator_id", ["pe-" + "a" * 64, 1, [], {}])
@pytest.mark.parametrize("source_content_hash", ["b" * 64, 1, [], {}])
def test_capture_source_pair_types_fail_before_write(
    collector,
    source_locator_id,
    source_content_hash,
):
    with pytest.raises(ValueError):
        collector._capture(
            provider_code="clutch",
            origin_code="clutch-session-store",
            captured_at="2026-07-30T08:00:00Z",
            raw_content="typed input",
            sensitivity_code="private",
            retention_code="local-review",
            source_locator_id=source_locator_id,
            source_content_hash=source_content_hash,
        )
    assert collector.store_inventory()["receipt_count"] == 0


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("provider_code", []),
        ("origin_code", {}),
        ("sensitivity_code", 1),
        ("retention_code", None),
        ("promotion_status", []),
    ],
)
def test_capture_code_types_fail_closed_without_typeerror(collector, field, value):
    values = {
        "provider_code": "clutch",
        "origin_code": "clutch-session-store",
        "captured_at": "2026-07-30T08:00:00Z",
        "raw_content": "typed input",
        "sensitivity_code": "private",
        "retention_code": "local-review",
        "promotion_status": "not-reviewed",
    }
    values[field] = value
    with pytest.raises(ValueError):
        collector._capture(**values)
    assert collector.store_inventory()["receipt_count"] == 0


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema", []),
        ("provider_code", {}),
        ("locator_id", 1),
        ("source_uri", []),
        ("content_hash", {}),
    ],
)
def test_locator_type_errors_fail_before_resolver_or_write(collector, field, value):
    locator = replace(locator_for(), **{field: value})
    called = False

    def resolver(_candidate):
        nonlocal called
        called = True
        return "typed input"

    with pytest.raises(EvidenceIntegrityError):
        collector._capture_from_locator(
            locator=locator,
            resolve_content=resolver,
            captured_at="2026-08-01T09:00:00Z",
            sensitivity_code="private",
            retention_code="local-review",
        )
    assert called is False
    assert collector.store_inventory()["receipt_count"] == 0


def test_receipt_type_tampering_is_wrapped_as_integrity_error(collector):
    receipt = capture(collector)
    with pytest.raises(EvidenceIntegrityError):
        replace(receipt, promotion_status=[])

    receipt_path = collector.receipt_dir / f"{receipt.evidence_id}.json"
    value = receipt.to_dict()
    value["content_hash"] = []
    receipt_path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(EvidenceIntegrityError):
        collector.find_one(evidence_id=receipt.evidence_id)
