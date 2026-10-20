"""The audit log itself: append, periodic signed checkpoints, and
verification that recomputes the whole chain rather than trusting any
single stored hash. See docs/audit-log.md for the on-disk format and
docs/threat-model.md T3 for exactly what "tamper-evident" does and does
not mean here.
"""

from __future__ import annotations

import csv
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from custody.audit.hashing import (
    GENESIS_HASH,
    canonical_json,
    checkpoint_signing_payload,
    sha256_hex,
)
from custody.audit.keys import public_key_from_hex, public_key_hex
from custody.audit.models import AuditEntry, Checkpoint, EventType, VerifyResult
from custody.audit.sinks import AuditSink, CorruptAuditLogError


def verify_sink(sink: AuditSink) -> VerifyResult:
    """Recompute the whole chain from entry 0 against `sink` and check
    every checkpoint's signature. Reports the first broken link, not just
    pass/fail, see VerifyResult's docstring.

    Deliberately free-standing rather than only an `AuditLog` method: a
    checkpoint carries its own public key, so checking one never needs a
    signing key, and verification should not depend on `AuditLog`'s
    resume-scan succeeding first. A log corrupted enough that resuming it
    would raise CorruptAuditLogError should still be verifiable, that is
    the whole point of a verify command existing, so `custody audit
    verify` calls this directly against a sink, with no key and no
    AuditLog instance required.
    """
    entries: list[AuditEntry] = []
    prev_hash = GENESIS_HASH
    corruption: CorruptAuditLogError | None = None

    try:
        for i, entry in enumerate(sink.read_entries()):
            if entry.seq != i:
                return VerifyResult(
                    ok=False,
                    entries_checked=i,
                    checkpoints_checked=0,
                    first_broken_seq=entry.seq,
                    reason=(
                        f"expected seq {i} at this position, found {entry.seq} "
                        "(an entry was deleted, reordered, or a seq was skipped)"
                    ),
                )
            if entry.prev_hash != prev_hash:
                return VerifyResult(
                    ok=False,
                    entries_checked=i,
                    checkpoints_checked=0,
                    first_broken_seq=entry.seq,
                    reason="prev_hash does not match the preceding entry's entry_hash",
                )
            recomputed = sha256_hex(canonical_json(entry.hashable_fields()))
            if recomputed != entry.entry_hash:
                return VerifyResult(
                    ok=False,
                    entries_checked=i,
                    checkpoints_checked=0,
                    first_broken_seq=entry.seq,
                    reason=(
                        "entry_hash does not match the entry's own recomputed "
                        "hash (its content was modified)"
                    ),
                )
            prev_hash = entry.entry_hash
            entries.append(entry)
    except CorruptAuditLogError as exc:
        corruption = exc

    if corruption is not None:
        return VerifyResult(
            ok=False,
            entries_checked=len(entries),
            checkpoints_checked=0,
            first_broken_seq=len(entries),
            reason=f"audit log is corrupted: {corruption.detail}",
        )

    entries_by_seq = {e.seq: e for e in entries}
    checkpoints_checked = 0
    for cp in sink.read_checkpoints():
        checkpoints_checked += 1
        covered = entries_by_seq.get(cp.seq)
        if covered is None:
            return VerifyResult(
                ok=False,
                entries_checked=len(entries),
                checkpoints_checked=checkpoints_checked,
                first_broken_seq=cp.seq,
                reason=f"checkpoint covers seq {cp.seq}, which is not in the log",
            )
        if covered.entry_hash != cp.entry_hash:
            return VerifyResult(
                ok=False,
                entries_checked=len(entries),
                checkpoints_checked=checkpoints_checked,
                first_broken_seq=cp.seq,
                reason=(
                    f"checkpoint's recorded hash for seq {cp.seq} does not "
                    "match that entry's actual hash"
                ),
            )
        try:
            public_key_from_hex(cp.public_key).verify(
                bytes.fromhex(cp.signature), cp.signed_payload()
            )
        except InvalidSignature:
            return VerifyResult(
                ok=False,
                entries_checked=len(entries),
                checkpoints_checked=checkpoints_checked,
                first_broken_seq=cp.seq,
                reason=f"checkpoint signature for seq {cp.seq} does not verify",
            )

    return VerifyResult(
        ok=True,
        entries_checked=len(entries),
        checkpoints_checked=checkpoints_checked,
    )


class AuditLog:
    """Construct with an `AuditSink` and an Ed25519 signing key. Reopening
    against a sink that already has entries picks up where it left off
    (recovers `seq` and the running `prev_hash` by reading the existing
    chain), so a new `AuditLog` instance across a process restart extends
    the same chain rather than starting a new one.
    """

    def __init__(
        self,
        sink: AuditSink,
        signing_key: Ed25519PrivateKey,
        session_id: str,
        principal: str,
        checkpoint_every: int = 100,
    ) -> None:
        self._sink = sink
        self._signing_key = signing_key
        self._session_id = session_id
        self._principal = principal
        self._checkpoint_every = checkpoint_every

        last: AuditEntry | None = None
        count = 0
        for entry in sink.read_entries():
            last = entry
            count += 1
        self._next_seq = count
        self._prev_hash = last.entry_hash if last is not None else GENESIS_HASH

    def append(
        self,
        event_type: EventType,
        payload: dict[str, object],
        *,
        principal: str | None = None,
    ) -> AuditEntry:
        """Append one entry. `payload` must be JSON-serializable and must
        never carry a raw field value from identified or limited-data-set
        data, see AuditEntry's docstring."""
        seq = self._next_seq
        timestamp = datetime.now(UTC)
        who = principal if principal is not None else self._principal

        hashable = {
            "seq": seq,
            "timestamp": timestamp.isoformat(),
            "session_id": self._session_id,
            "principal": who,
            "event_type": event_type.value,
            "payload": payload,
            "prev_hash": self._prev_hash,
        }
        entry_hash = sha256_hex(canonical_json(hashable))

        entry = AuditEntry(
            seq=seq,
            timestamp=timestamp,
            session_id=self._session_id,
            principal=who,
            event_type=event_type,
            payload=payload,
            prev_hash=self._prev_hash,
            entry_hash=entry_hash,
        )
        self._sink.append_entry(entry)
        self._next_seq += 1
        self._prev_hash = entry_hash

        if self._checkpoint_every > 0 and self._next_seq % self._checkpoint_every == 0:
            self.checkpoint()

        return entry

    def checkpoint(self) -> Checkpoint:
        """Sign a statement covering every entry appended so far. Safe to
        call with no new entries since the last checkpoint (idempotent in
        effect, though it does write a new, identically-covering
        checkpoint record each time, which is harmless)."""
        if self._next_seq == 0:
            raise ValueError("cannot checkpoint an empty audit log")

        last_seq = self._next_seq - 1
        timestamp = datetime.now(UTC)
        payload = checkpoint_signing_payload(last_seq, self._prev_hash, timestamp)
        signature = self._signing_key.sign(payload)

        checkpoint = Checkpoint(
            seq=last_seq,
            entry_hash=self._prev_hash,
            timestamp=timestamp,
            signature=signature.hex(),
            public_key=public_key_hex(self._signing_key),
        )
        self._sink.append_checkpoint(checkpoint)
        return checkpoint

    def verify(self) -> VerifyResult:
        """Recompute the whole chain from entry 0 and check every
        checkpoint's signature. Reports the first broken link, not just
        pass/fail, see VerifyResult's docstring. Delegates to the
        standalone `verify_sink()`, which needs no signing key and no
        resume-scan, see that function's docstring for why that split
        matters for a log that might already be corrupted.
        """
        return verify_sink(self._sink)

    def export(
        self,
        fmt: Literal["jsonl", "csv"],
        dest: Path,
        since: datetime | None = None,
    ) -> Path:
        """Write every entry (optionally since a timestamp) to `dest` for
        compliance review or SIEM ingestion. Checkpoints are not included,
        export is a view of the entries; run `verify()` separately to
        confirm the chain the export was taken from is intact."""
        entries = [
            e for e in self._sink.read_entries() if since is None or e.timestamp >= since
        ]

        if fmt == "jsonl":
            with dest.open("w", encoding="utf-8") as f:
                for e in entries:
                    f.write(e.model_dump_json())
                    f.write("\n")
        elif fmt == "csv":
            with dest.open("w", encoding="utf-8", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(
                    [
                        "seq",
                        "timestamp",
                        "session_id",
                        "principal",
                        "event_type",
                        "payload",
                        "prev_hash",
                        "entry_hash",
                    ]
                )
                for e in entries:
                    writer.writerow(
                        [
                            e.seq,
                            e.timestamp.isoformat(),
                            e.session_id,
                            e.principal,
                            e.event_type.value,
                            json.dumps(e.payload, sort_keys=True),
                            e.prev_hash,
                            e.entry_hash,
                        ]
                    )
        else:
            raise ValueError(f"unsupported export format: {fmt!r}")

        return dest
