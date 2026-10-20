"""Tamper-evident audit log. Append-only, hash-chained, periodically
signed with Ed25519 checkpoints. `verify()` recomputes the chain from
scratch and reports the first broken link. See docs/audit-log.md and
docs/threat-model.md T3 for exactly what "tamper-evident, not
tamper-proof" means.
"""

from custody.audit.hashing import GENESIS_HASH, canonical_json, sha256_hex
from custody.audit.log import AuditLog, verify_sink
from custody.audit.models import AuditEntry, Checkpoint, EventType, VerifyResult
from custody.audit.sinks import AuditSink, CorruptAuditLogError, LocalFileSink

__all__ = [
    "GENESIS_HASH",
    "AuditEntry",
    "AuditLog",
    "AuditSink",
    "Checkpoint",
    "CorruptAuditLogError",
    "EventType",
    "LocalFileSink",
    "VerifyResult",
    "canonical_json",
    "sha256_hex",
    "verify_sink",
]
