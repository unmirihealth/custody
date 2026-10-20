"""Pydantic models for one audit entry and one signed checkpoint. See
docs/audit-log.md for the format and what `verify()` actually checks.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from custody.audit.hashing import GENESIS_HASH, checkpoint_signing_payload


class EventType(StrEnum):
    request = "request"
    decision = "decision"
    approval = "approval"
    execution = "execution"
    result = "result"
    error = "error"


class AuditEntry(BaseModel):
    """One append-only log entry. `payload` must never hold a raw field
    value from an identified or limited-data-set dataset, only
    references, hashes, counts, and column names (docs/threat-model.md
    T6). This model does not enforce that by inspecting payload content,
    it is a discipline requirement on every caller that appends an entry,
    named here so the rule lives beside the field it governs.
    """

    model_config = ConfigDict(frozen=True)

    seq: int = Field(ge=0)
    timestamp: datetime
    session_id: str
    principal: str
    event_type: EventType
    payload: dict[str, Any]
    prev_hash: str
    entry_hash: str

    def hashable_fields(self) -> dict[str, Any]:
        """Every field except `entry_hash` itself, in the exact shape
        that gets canonical-JSON-encoded and hashed. Used both when an
        entry is first created and when `verify()` recomputes it."""
        return {
            "seq": self.seq,
            "timestamp": self.timestamp.isoformat(),
            "session_id": self.session_id,
            "principal": self.principal,
            "event_type": self.event_type.value,
            "payload": self.payload,
            "prev_hash": self.prev_hash,
        }


class Checkpoint(BaseModel):
    """A signed statement: "the chain up to and including entry `seq`
    hashes to `entry_hash`." Self-contained: it carries the public key
    needed to verify its own signature, so `verify()` does not depend on
    separate key distribution to check a checkpoint already on disk.
    """

    model_config = ConfigDict(frozen=True)

    seq: int = Field(ge=0)
    entry_hash: str
    timestamp: datetime
    signature: str  # hex-encoded Ed25519 signature
    public_key: str  # hex-encoded Ed25519 public key

    def signed_payload(self) -> bytes:
        return checkpoint_signing_payload(self.seq, self.entry_hash, self.timestamp)


class VerifyResult(BaseModel):
    """What `custody audit verify` reports. `ok=False` always comes with
    `first_broken_seq` and a human `reason`; "tamper-evident" means this
    is designed to name the exact entry, not just say "something's
    wrong" (docs/threat-model.md T3)."""

    model_config = ConfigDict(frozen=True)

    ok: bool
    entries_checked: int
    checkpoints_checked: int
    first_broken_seq: int | None = None
    reason: str | None = None


__all__ = ["GENESIS_HASH", "AuditEntry", "Checkpoint", "EventType", "VerifyResult"]
