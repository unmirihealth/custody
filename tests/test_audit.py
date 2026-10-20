from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from hypothesis import given, settings
from hypothesis import strategies as st

from custody.audit import GENESIS_HASH, AuditLog, EventType, LocalFileSink, verify_sink


@pytest.fixture
def signing_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


@pytest.fixture
def sink(tmp_path: Path) -> LocalFileSink:
    return LocalFileSink(tmp_path / "audit")


@pytest.fixture
def log(sink: LocalFileSink, signing_key: Ed25519PrivateKey) -> AuditLog:
    return AuditLog(
        sink=sink,
        signing_key=signing_key,
        session_id="sess-1",
        principal="umair",
        checkpoint_every=100,
    )


class TestAppendAndChain:
    def test_first_entry_prev_hash_is_genesis(self, log: AuditLog) -> None:
        entry = log.append(EventType.request, {"tool": "catalog.list"})
        assert entry.seq == 0
        assert entry.prev_hash == GENESIS_HASH

    def test_entries_chain_by_hash(self, log: AuditLog) -> None:
        e0 = log.append(EventType.request, {"tool": "catalog.list"})
        e1 = log.append(EventType.decision, {"decision": "allow"})
        assert e1.prev_hash == e0.entry_hash
        assert e1.seq == 1

    def test_payload_round_trips_through_the_sink(self, log: AuditLog, sink: LocalFileSink) -> None:
        log.append(EventType.result, {"rows": 42, "columns": ["gene", "stage"]})
        (stored,) = list(sink.read_entries())
        assert stored.payload == {"rows": 42, "columns": ["gene", "stage"]}

    def test_default_principal_used_when_not_overridden(self, log: AuditLog) -> None:
        entry = log.append(EventType.request, {})
        assert entry.principal == "umair"

    def test_principal_override(self, log: AuditLog) -> None:
        entry = log.append(EventType.approval, {}, principal="data_steward_jane")
        assert entry.principal == "data_steward_jane"


class TestReopen:
    def test_reopening_resumes_seq_and_prev_hash(
        self, sink: LocalFileSink, signing_key: Ed25519PrivateKey
    ) -> None:
        log1 = AuditLog(sink, signing_key, session_id="s1", principal="a")
        log1.append(EventType.request, {"n": 1})
        log1.append(EventType.request, {"n": 2})

        log2 = AuditLog(sink, signing_key, session_id="s1", principal="a")
        entry = log2.append(EventType.request, {"n": 3})
        assert entry.seq == 2

        result = log2.verify()
        assert result.ok
        assert result.entries_checked == 3


class TestCheckpointing:
    def test_manual_checkpoint_verifies(self, log: AuditLog) -> None:
        log.append(EventType.request, {})
        cp = log.checkpoint()
        assert cp.seq == 0
        result = log.verify()
        assert result.ok
        assert result.checkpoints_checked == 1

    def test_checkpoint_every_triggers_automatically(
        self, sink: LocalFileSink, signing_key: Ed25519PrivateKey
    ) -> None:
        log = AuditLog(sink, signing_key, "s", "a", checkpoint_every=3)
        for i in range(3):
            log.append(EventType.request, {"i": i})
        checkpoints = list(sink.read_checkpoints())
        assert len(checkpoints) == 1
        assert checkpoints[0].seq == 2

    def test_checkpoint_on_empty_log_raises(self, log: AuditLog) -> None:
        with pytest.raises(ValueError, match="empty"):
            log.checkpoint()

    def test_multiple_checkpoints_all_verify(self, log: AuditLog) -> None:
        log.append(EventType.request, {})
        log.checkpoint()
        log.append(EventType.request, {})
        log.checkpoint()
        result = log.verify()
        assert result.ok
        assert result.checkpoints_checked == 2


class TestVerifyCleanLog:
    def test_empty_log_verifies_ok(self, log: AuditLog) -> None:
        result = log.verify()
        assert result.ok
        assert result.entries_checked == 0
        assert result.checkpoints_checked == 0

    def test_many_entries_verify_ok(self, log: AuditLog) -> None:
        for i in range(25):
            log.append(EventType.request, {"i": i})
        log.checkpoint()
        result = log.verify()
        assert result.ok
        assert result.entries_checked == 25


class TestVerifyCatchesTampering:
    """Hand-rolled tamper scenarios, each naming the exact kind of
    corruption, before the broader hypothesis property test below."""

    def test_modified_payload_breaks_verify(
        self, sink: LocalFileSink, signing_key: Ed25519PrivateKey
    ) -> None:
        log = AuditLog(sink, signing_key, "s", "a")
        log.append(EventType.request, {"rows": 10})
        log.append(EventType.request, {"rows": 20})

        lines = sink.entries_path.read_text().splitlines()
        tampered = json.loads(lines[0])
        tampered["payload"]["rows"] = 99999
        lines[0] = json.dumps(tampered)
        sink.entries_path.write_text("\n".join(lines) + "\n")

        result = verify_sink(sink)
        assert not result.ok
        assert result.first_broken_seq == 0
        assert "recomputed hash" in (result.reason or "")

    def test_deleted_entry_breaks_verify(
        self, sink: LocalFileSink, signing_key: Ed25519PrivateKey
    ) -> None:
        log = AuditLog(sink, signing_key, "s", "a")
        log.append(EventType.request, {"i": 0})
        log.append(EventType.request, {"i": 1})
        log.append(EventType.request, {"i": 2})

        lines = sink.entries_path.read_text().splitlines()
        del lines[1]  # delete the middle entry
        sink.entries_path.write_text("\n".join(lines) + "\n")

        result = verify_sink(sink)
        assert not result.ok
        assert result.first_broken_seq == 2  # seq 2 now sits where seq 1 should be

    def test_reordered_entries_break_verify(
        self, sink: LocalFileSink, signing_key: Ed25519PrivateKey
    ) -> None:
        log = AuditLog(sink, signing_key, "s", "a")
        log.append(EventType.request, {"i": 0})
        log.append(EventType.request, {"i": 1})

        lines = sink.entries_path.read_text().splitlines()
        lines[0], lines[1] = lines[1], lines[0]
        sink.entries_path.write_text("\n".join(lines) + "\n")

        result = verify_sink(sink)
        assert not result.ok

    def test_tampered_checkpoint_entry_hash_breaks_verify(
        self, sink: LocalFileSink, signing_key: Ed25519PrivateKey
    ) -> None:
        log = AuditLog(sink, signing_key, "s", "a")
        log.append(EventType.request, {})
        log.checkpoint()

        lines = sink.checkpoints_path.read_text().splitlines()
        tampered = json.loads(lines[0])
        tampered["entry_hash"] = "f" * 64
        sink.checkpoints_path.write_text(json.dumps(tampered) + "\n")

        result = verify_sink(sink)
        assert not result.ok
        assert "recorded hash" in (result.reason or "")

    def test_checkpoint_with_forged_signature_breaks_verify(
        self, sink: LocalFileSink, signing_key: Ed25519PrivateKey
    ) -> None:
        log = AuditLog(sink, signing_key, "s", "a")
        log.append(EventType.request, {})
        log.checkpoint()

        lines = sink.checkpoints_path.read_text().splitlines()
        tampered = json.loads(lines[0])
        tampered["signature"] = "00" * 64  # well-formed hex, wrong signature
        sink.checkpoints_path.write_text(json.dumps(tampered) + "\n")

        result = verify_sink(sink)
        assert not result.ok
        assert "does not verify" in (result.reason or "")

    def test_checkpoint_referencing_nonexistent_seq_breaks_verify(
        self, sink: LocalFileSink, signing_key: Ed25519PrivateKey
    ) -> None:
        log = AuditLog(sink, signing_key, "s", "a")
        log.append(EventType.request, {})
        log.checkpoint()

        lines = sink.checkpoints_path.read_text().splitlines()
        tampered = json.loads(lines[0])
        tampered["seq"] = 999
        sink.checkpoints_path.write_text(json.dumps(tampered) + "\n")

        result = verify_sink(sink)
        assert not result.ok
        assert result.first_broken_seq == 999


class TestExport:
    def test_export_jsonl(self, log: AuditLog, tmp_path: Path) -> None:
        log.append(EventType.request, {"i": 1})
        log.append(EventType.request, {"i": 2})
        dest = tmp_path / "out.jsonl"
        log.export("jsonl", dest)
        lines = dest.read_text().splitlines()
        assert len(lines) == 2
        assert json.loads(lines[0])["payload"] == {"i": 1}

    def test_export_csv(self, log: AuditLog, tmp_path: Path) -> None:
        log.append(EventType.request, {"i": 1})
        dest = tmp_path / "out.csv"
        log.export("csv", dest)
        text = dest.read_text()
        assert "seq,timestamp,session_id" in text.splitlines()[0]
        assert "request" in text

    def test_export_since_filters_older_entries(self, log: AuditLog, tmp_path: Path) -> None:
        log.append(EventType.request, {"i": 1})
        cutoff = datetime.now(UTC) + timedelta(milliseconds=5)
        import time

        time.sleep(0.01)
        log.append(EventType.request, {"i": 2})

        dest = tmp_path / "out.jsonl"
        log.export("jsonl", dest, since=cutoff)
        lines = dest.read_text().splitlines()
        assert len(lines) == 1
        assert json.loads(lines[0])["payload"] == {"i": 2}

    def test_export_unsupported_format_raises(self, log: AuditLog, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="unsupported"):
            log.export("xml", tmp_path / "out.xml")  # type: ignore[arg-type]


# ── Property tests: any single-byte modification, deletion, or ──────────
# reordering of audit entries fails verify().

@st.composite
def _entry_count(draw: st.DrawFn) -> int:
    return draw(st.integers(min_value=2, max_value=12))


def _build_log(tmp_path: Path, n: int) -> tuple[AuditLog, LocalFileSink, Ed25519PrivateKey]:
    key = Ed25519PrivateKey.generate()
    sink = LocalFileSink(tmp_path / "audit")
    log = AuditLog(sink, key, "s", "a")
    for i in range(n):
        log.append(EventType.request, {"i": i})
    # Checkpoint the full chain so that deleting the LAST entry is also
    # detectable: without a checkpoint, a deleted tail is a shorter but
    # still internally-consistent chain (truncation is only detectable
    # relative to something that claims how long the chain should be,
    # which is exactly what a checkpoint does).
    log.checkpoint()
    return log, sink, key


class TestTamperPropertyBased:
    @settings(max_examples=25, deadline=None)
    @given(n=_entry_count(), byte_index=st.data())
    def test_single_byte_modification_fails_verify(
        self, tmp_path_factory: pytest.TempPathFactory, n: int, byte_index: st.DataObject
    ) -> None:
        tmp_path = tmp_path_factory.mktemp("tamper_byte")
        log, sink, key = _build_log(tmp_path, n)
        assert log.verify().ok

        raw = bytearray(sink.entries_path.read_bytes())
        # Flip one byte, excluding the newlines that separate records
        # (flipping those would just change line count without touching
        # any field, which is deletion/reordering's job below).
        candidates = [i for i, b in enumerate(raw) if b != ord("\n")]
        idx = byte_index.draw(st.sampled_from(candidates))
        raw[idx] ^= 0xFF
        sink.entries_path.write_bytes(bytes(raw))

        result = verify_sink(sink)
        assert not result.ok

    @settings(max_examples=15, deadline=None)
    @given(n=_entry_count(), data=st.data())
    def test_deleting_a_line_fails_verify(
        self, tmp_path_factory: pytest.TempPathFactory, n: int, data: st.DataObject
    ) -> None:
        tmp_path = tmp_path_factory.mktemp("tamper_delete")
        log, sink, key = _build_log(tmp_path, n)

        lines = sink.entries_path.read_text().splitlines()
        idx = data.draw(st.integers(min_value=0, max_value=len(lines) - 1))
        del lines[idx]
        sink.entries_path.write_text("\n".join(lines) + ("\n" if lines else ""))

        result = verify_sink(sink)
        assert not result.ok

    @settings(max_examples=15, deadline=None)
    @given(n=st.integers(min_value=3, max_value=12), data=st.data())
    def test_reordering_two_lines_fails_verify(
        self, tmp_path_factory: pytest.TempPathFactory, n: int, data: st.DataObject
    ) -> None:
        tmp_path = tmp_path_factory.mktemp("tamper_reorder")
        log, sink, key = _build_log(tmp_path, n)

        lines = sink.entries_path.read_text().splitlines()
        i = data.draw(st.integers(min_value=0, max_value=len(lines) - 1))
        j = data.draw(st.integers(min_value=0, max_value=len(lines) - 1).filter(lambda x: x != i))
        lines[i], lines[j] = lines[j], lines[i]
        sink.entries_path.write_text("\n".join(lines) + "\n")

        result = verify_sink(sink)
        assert not result.ok
