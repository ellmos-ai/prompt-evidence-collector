"""Privacy- und Fail-Closed-Tests für Prompt-Evidence."""

import hashlib
import json
import os
from dataclasses import replace
from pathlib import Path

import pytest

from prompt_evidence_collector.collector import (
    AmbiguousEvidenceError,
    EvidenceIntegrityError,
    EvidenceNotFoundError,
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
    return collector.capture(
        provider_code="clutch",
        origin_code="clutch-session-store",
        captured_at=captured_at,
        raw_content=raw,
        sensitivity_code="private",
        retention_code="local-review",
        source_locator_id="loc-" + "a" * 64,
        source_content_hash="b" * 64,
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
        collector.capture(**values)


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
