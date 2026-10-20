"""Canonical JSON and hashing used by every entry and checkpoint in the
audit log. One place, so "canonical" means exactly one thing across the
whole module.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

#: The `prev_hash` of the very first entry in a chain. 64 zero characters
#: so it is the same length and shape as every real hash, not a special
#: case a reader (or a verifier) has to remember.
GENESIS_HASH = "0" * 64


def canonical_json(obj: dict[str, Any]) -> bytes:
    """Deterministic JSON encoding: sorted keys, no extra whitespace, so
    the same logical content always hashes to the same bytes regardless
    of dict insertion order or formatting."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode(
        "utf-8"
    )


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def checkpoint_signing_payload(seq: int, entry_hash: str, timestamp: Any) -> bytes:
    """The exact bytes a checkpoint signs over. One definition, used both
    when a checkpoint is created (custody.audit.log) and when its
    signature is re-checked (Checkpoint.signed_payload, verify())."""
    ts = timestamp.isoformat() if hasattr(timestamp, "isoformat") else str(timestamp)
    return canonical_json({"seq": seq, "entry_hash": entry_hash, "timestamp": ts})
