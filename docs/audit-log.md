# Audit log

Append-only, hash-chained, periodically checkpointed with an Ed25519
signature. See docs/threat-model.md T3 for what "tamper-evident, not
tamper-proof" actually means, read that before relying on this for
anything. This page is the format and the mechanics.

## On-disk format

Two JSONL files under `.custody/audit/` (or wherever `ServerPaths`
points `audit_dir`):

- `entries.jsonl` -- one `AuditEntry` per line.
- `checkpoints.jsonl` -- one `Checkpoint` per line.

### `AuditEntry`

```json
{
  "seq": 4,
  "timestamp": "2026-10-20T19:03:11.482193+00:00",
  "session_id": "demo",
  "principal": "demo-agent",
  "event_type": "decision",
  "payload": {"tool": "sql.query", "decision": "allow", "matched_rule_id": "deid-query-ok"},
  "prev_hash": "a94e...c201",
  "entry_hash": "f281...9b3e"
}
```

- `seq` starts at 0 and increments by exactly 1, no gaps, no reuse.
- `event_type` is one of `request`, `decision`, `approval`,
  `execution`, `result`, `error`.
- `payload` is a JSON-serializable dict. **It must never carry a raw
  field value from a `limited_data_set` or `identified` dataset** --
  dataset ids, row counts, column names, content hashes, and redacted
  summaries only, see docs/threat-model.md T6. This is a discipline
  requirement on every caller, not something the model enforces by
  inspecting content. `custody/tools/sql.py` and `shell.py` log a
  SHA-256 of stdout, never stdout itself, as the pattern to follow.
- `prev_hash` is the previous entry's `entry_hash`, or 64 zero
  characters (`GENESIS_HASH`) for entry 0.
- `entry_hash` = `sha256(canonical_json({seq, timestamp, session_id,
  principal, event_type, payload, prev_hash}))`. Canonical JSON means
  sorted keys, no extra whitespace (`custody/audit/hashing.py`), so the
  same logical content always hashes the same way.

### `Checkpoint`

```json
{
  "seq": 99,
  "entry_hash": "f281...9b3e",
  "timestamp": "2026-10-20T19:05:00.001122+00:00",
  "signature": "3a7c...e901",
  "public_key": "9bd4...11ff"
}
```

A statement: "the chain up to and including entry `seq` hashes to
`entry_hash`," signed with Ed25519 over
`canonical_json({seq, entry_hash, timestamp})`. The checkpoint carries
its own public key, so verifying one never needs separate key
distribution. Written automatically every `checkpoint_every` entries
(default 100, configurable on `AuditLog`), and whenever
`AuditLog.checkpoint()` is called explicitly.

## Verification

```bash
custody audit verify
```

Calls `custody.audit.log.verify_sink()`, a free function (not an
`AuditLog` method) that needs no signing key: it recomputes the whole
entry chain from `seq` 0 and checks every checkpoint's signature
against the public key that checkpoint itself carries. It reports the
**first broken link**, not just pass/fail:

```
BROKEN at seq 12: entry_hash does not match the entry's own recomputed hash (its content was modified)
```

Being a free function matters in practice: a log corrupted enough to
break `AuditLog`'s own resume-scan (reading existing entries to
recover `seq` and the running `prev_hash` for new appends) should
still be verifiable, that is the entire point of a verify command
existing.

### What verify catches, and what it can't

- A modified field in any entry: caught (`entry_hash` mismatch).
- A deleted or reordered entry: caught (`seq` no longer matches
  position, or `prev_hash` no longer matches the preceding entry).
- A corrupted line (not valid UTF-8, not valid JSON, not a valid
  `AuditEntry`): caught, reported as "audit log is corrupted," not a
  crash.
- A forged or tampered checkpoint: caught (recorded hash mismatch, or
  the Ed25519 signature doesn't verify).
- **Deleting the very last entries, if they were never covered by a
  checkpoint:** NOT caught by `verify()` alone. A shorter chain is
  still internally consistent; nothing claims it should be longer. A
  checkpoint is exactly the thing that closes this gap for everything
  up to and including the seq it covers, run `custody audit verify`
  (or the gateway's own `checkpoint_every`) often enough that nothing
  of consequence sits un-checkpointed for long, and ship checkpoints
  off-host (see below) so even a compromised host can't erase the
  record of them having existed.

## `custody audit export` and `tail`

```bash
custody audit export out.jsonl [--format jsonl|csv] [--since 2026-10-20T00:00:00]
custody audit tail [-n 20]
```

Export is a view of the entries for compliance review or SIEM
ingestion; it does not include checkpoints, and it does not itself
verify the chain, run `custody audit verify` separately for that.

## Shipping checkpoints to write-once storage

v0.1 shipped one `AuditSink`: `LocalFileSink`, two local JSONL files.
`AuditSink` is a `Protocol` (`custody/audit/sinks.py`) with four
methods (`append_entry`, `append_checkpoint`, `read_entries`,
`read_checkpoints`); a second implementation,
`custody.audit.s3_sink.S3ObjectLockSink`, fills in the write-once-store
hook this section used to describe as undone. It requires the optional
`s3` dependency group (`pip install custody-mcp[s3]`) and is never
imported by `custody.audit`'s own `__init__`, so Custody still does
not require AWS, or any particular cloud, to run unless you choose to
use it. See docs/s3-object-lock-sink.md for setup, the exact
`GOVERNANCE`/`COMPLIANCE` retention tradeoff, and -- importantly -- what
is and is not actually verified against a local test environment
(the write-once guarantee itself needs real AWS or LocalStack Pro to
confirm, not something this project's own CI can check).
