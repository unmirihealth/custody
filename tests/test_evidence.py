from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from custody.audit import AuditLog, EventType, LocalFileSink
from custody.evidence import (
    CONTROL_MAPPINGS,
    build_manifest,
    mappings_for,
    write_evidence_pack,
)
from custody.policy.bundle import bundle_path_for, sign_policy


@pytest.fixture
def sink(tmp_path: Path) -> LocalFileSink:
    return LocalFileSink(tmp_path / "audit")


@pytest.fixture
def log(sink: LocalFileSink) -> AuditLog:
    return AuditLog(
        sink=sink,
        signing_key=Ed25519PrivateKey.generate(),
        session_id="sess-1",
        principal="umair",
        checkpoint_every=2,
    )


def _populate(log: AuditLog) -> None:
    log.append(EventType.request, {"tool": "catalog.list"})
    log.append(EventType.decision, {"tool": "catalog.list", "decision": "allow"})
    log.append(EventType.request, {"tool": "sql.query"})
    log.append(
        EventType.decision,
        {"tool": "sql.query", "decision": "require_approval"},
    )
    log.append(EventType.approval, {"status": "requested"})
    log.append(EventType.approval, {"status": "approved"})
    log.append(EventType.result, {"tool": "sql.query", "row_count": 3})
    log.append(EventType.request, {"tool": "nobody.registered.this"})
    log.append(EventType.decision, {"tool": "nobody.registered.this", "decision": "deny"})


class TestBuildManifest:
    def test_counts_event_types_and_decisions(self, log: AuditLog, sink: LocalFileSink) -> None:
        _populate(log)
        manifest = build_manifest(sink)
        assert manifest.entries_in_window == 9
        assert manifest.event_type_counts.request == 3
        assert manifest.event_type_counts.decision == 3
        assert manifest.event_type_counts.approval == 2
        assert manifest.event_type_counts.result == 1
        assert manifest.decision_counts.allow == 1
        assert manifest.decision_counts.deny == 1
        assert manifest.decision_counts.require_approval == 1

    def test_audit_integrity_is_ok_for_a_clean_log(
        self, log: AuditLog, sink: LocalFileSink
    ) -> None:
        _populate(log)
        manifest = build_manifest(sink)
        assert manifest.audit_integrity.ok is True

    def test_window_filters_by_timestamp(self, log: AuditLog, sink: LocalFileSink) -> None:
        _populate(log)
        future = datetime.now(UTC) + timedelta(days=1)
        manifest = build_manifest(sink, since=future)
        assert manifest.entries_in_window == 0

    def test_no_policy_path_means_no_bundle(self, log: AuditLog, sink: LocalFileSink) -> None:
        _populate(log)
        manifest = build_manifest(sink)
        assert manifest.policy_bundle is None

    def test_signed_policy_is_included(
        self, log: AuditLog, sink: LocalFileSink, tmp_path: Path
    ) -> None:
        _populate(log)
        policy = tmp_path / "policy.yaml"
        policy.write_text("rules: []\ndefault: deny\nmodel_allowlist: {}\n")
        bundle = sign_policy(policy, Ed25519PrivateKey.generate())
        bundle_path_for(policy).write_text(bundle.model_dump_json())

        manifest = build_manifest(sink, policy_path=policy)
        assert manifest.policy_bundle is not None
        assert manifest.policy_bundle.policy_sha256 == bundle.policy_sha256

    def test_control_ids_filters_mappings(self, log: AuditLog, sink: LocalFileSink) -> None:
        _populate(log)
        manifest = build_manifest(sink, control_ids=("CC7.2",))
        assert len(manifest.control_mappings) == 1
        assert manifest.control_mappings[0].control_id == "CC7.2"

    def test_disclaimer_is_always_present(self, log: AuditLog, sink: LocalFileSink) -> None:
        _populate(log)
        manifest = build_manifest(sink)
        assert "not a certification" in manifest.disclaimer


class TestMappingsFor:
    def test_no_ids_returns_everything(self) -> None:
        assert mappings_for() == CONTROL_MAPPINGS

    def test_unknown_id_raises(self) -> None:
        with pytest.raises(KeyError):
            mappings_for(("NOT-A-REAL-CONTROL",))


class TestWriteEvidencePack:
    def test_writes_expected_files(
        self, log: AuditLog, sink: LocalFileSink, tmp_path: Path
    ) -> None:
        _populate(log)
        policy = tmp_path / "policy.yaml"
        policy.write_text("rules: []\ndefault: deny\nmodel_allowlist: {}\n")
        bundle = sign_policy(policy, Ed25519PrivateKey.generate())
        bundle_path_for(policy).write_text(bundle.model_dump_json())

        dest = tmp_path / "pack"
        manifest = write_evidence_pack(dest, sink, policy_path=policy)

        assert (dest / "manifest.json").exists()
        assert (dest / "README.md").exists()
        assert (dest / "audit_export.jsonl").exists()
        assert (dest / "policy.yaml").exists()
        assert (dest / "policy.yaml.sig.json").exists()

        exported_lines = (dest / "audit_export.jsonl").read_text().splitlines()
        assert len(exported_lines) == manifest.entries_in_window
        json.loads(exported_lines[0])  # each line is valid JSON

        readme = (dest / "README.md").read_text()
        assert "not a certification" in readme
        assert "CC6.1" in readme

    def test_refuses_a_non_empty_existing_directory(
        self, log: AuditLog, sink: LocalFileSink, tmp_path: Path
    ) -> None:
        _populate(log)
        dest = tmp_path / "pack"
        dest.mkdir()
        (dest / "something").write_text("already here")
        with pytest.raises(FileExistsError):
            write_evidence_pack(dest, sink)

    def test_never_includes_dataset_content(
        self, log: AuditLog, sink: LocalFileSink, tmp_path: Path
    ) -> None:
        """Same guard as test_gateway.py and test_notifier.py: an
        evidence pack is built straight from the audit log, so it
        inherits whatever discipline the log already has, this test
        exists to catch a future change that starts exporting
        something richer."""
        log.append(EventType.result, {"tool": "sql.query", "row_count": 3})
        dest = tmp_path / "pack"
        write_evidence_pack(dest, sink)
        exported = (dest / "audit_export.jsonl").read_text()
        assert "EGFR" not in exported
