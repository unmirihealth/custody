"""Where entries and checkpoints are persisted.

`LocalFileSink` is the only implementation shipped in v0.1: append-only
JSONL files for entries and for checkpoints. An `AuditSink` implementation
for write-once storage (for example S3 Object Lock) is documented in
docs/audit-log.md as the interface a deployment fills in; it is not
implemented here, and Custody does not require AWS to run (ROADMAP.md).
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Protocol

from pydantic import ValidationError

from custody.audit.models import AuditEntry, Checkpoint


class CorruptAuditLogError(Exception):
    """A line in the audit log could not be read back as an entry: not
    valid UTF-8, not valid JSON, or not a valid AuditEntry. This is
    itself a tamper signal (docs/threat-model.md T3), not an I/O error to
    paper over. `AuditLog.verify()` catches this and reports it as a
    broken link rather than letting it crash past verification.
    """

    def __init__(self, line_index: int, detail: str) -> None:
        self.line_index = line_index
        self.detail = detail
        super().__init__(f"entries.jsonl line {line_index} is unreadable: {detail}")


class AuditSink(Protocol):
    """Append-only by contract, not just by convention: an implementation
    should make overwriting or deleting an existing line/object harder
    than appending a new one (a local filesystem can't truly enforce
    this, which is exactly why docs/threat-model.md T3 recommends
    write-once storage for anything that needs to survive a
    compromised host)."""

    def append_entry(self, entry: AuditEntry) -> None: ...
    def append_checkpoint(self, checkpoint: Checkpoint) -> None: ...
    def read_entries(self) -> Iterator[AuditEntry]: ...
    def read_checkpoints(self) -> Iterator[Checkpoint]: ...


class LocalFileSink:
    """Two JSONL files under `directory`: entries.jsonl and
    checkpoints.jsonl. Each append opens the file, writes one line, and
    closes it, so a crash mid-write loses at most the partial last line,
    never corrupts an earlier one.
    """

    def __init__(self, directory: Path) -> None:
        self._dir = directory
        self._dir.mkdir(parents=True, exist_ok=True)
        self.entries_path = self._dir / "entries.jsonl"
        self.checkpoints_path = self._dir / "checkpoints.jsonl"

    def append_entry(self, entry: AuditEntry) -> None:
        with self.entries_path.open("a", encoding="utf-8") as f:
            f.write(entry.model_dump_json())
            f.write("\n")

    def append_checkpoint(self, checkpoint: Checkpoint) -> None:
        with self.checkpoints_path.open("a", encoding="utf-8") as f:
            f.write(checkpoint.model_dump_json())
            f.write("\n")

    def read_entries(self) -> Iterator[AuditEntry]:
        """Yields entries in file order. Raises CorruptAuditLogError
        (rather than letting a raw UnicodeDecodeError, JSONDecodeError,
        or pydantic.ValidationError escape) the moment a line can't be
        read back, so a caller iterating this generator sees every
        entry that parsed fine before the break, then a clear exception
        naming where it broke.
        """
        if not self.entries_path.exists():
            return
        with self.entries_path.open("rb") as f:
            for i, raw_line in enumerate(f):
                stripped = raw_line.strip()
                if not stripped:
                    continue
                try:
                    text = stripped.decode("utf-8")
                    data = json.loads(text)
                    yield AuditEntry.model_validate(data)
                except (UnicodeDecodeError, json.JSONDecodeError, ValidationError) as exc:
                    raise CorruptAuditLogError(i, str(exc)) from exc

    def read_checkpoints(self) -> Iterator[Checkpoint]:
        if not self.checkpoints_path.exists():
            return
        with self.checkpoints_path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                yield Checkpoint.model_validate(json.loads(line))
