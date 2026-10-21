# S3 Object Lock audit sink

`custody/audit/sinks.py` documents `AuditSink` as a `Protocol`
specifically so a deployment that needs write-once storage can
implement it against S3 Object Lock, or anything else. v0.1 shipped
that interface and `LocalFileSink` only; `custody.audit.s3_sink
.S3ObjectLockSink` is that hook, actually filled in.

## Installing it

S3 support is optional: `boto3` is not a core dependency, only pulled
in by the `s3` extra.

```bash
pip install 'custody-mcp[s3]'
```

`custody.audit.s3_sink` is never imported by `custody.audit`'s own
`__init__`, so a deployment that never configures S3 never needs
`boto3` installed, matching "Custody does not require AWS, or any
particular cloud, to run" (ROADMAP.md).

## One-time bucket setup

Object Lock can only be enabled **at bucket creation time**, an S3
restriction, not something this sink can do for you after the fact:

```bash
aws s3api create-bucket --bucket my-custody-audit-bucket \
  --region us-east-1 --object-lock-enabled-for-bucket
```

## Using it

```python
from custody.audit import AuditLog
from custody.audit.s3_sink import S3ObjectLockSink

sink = S3ObjectLockSink(
    bucket="my-custody-audit-bucket",
    prefix="prod",                 # optional: share a bucket across deployments
    retention_mode="GOVERNANCE",   # or "COMPLIANCE", see below
    retain_for_days=3650,
)
log = AuditLog(sink, signing_key, session_id="...", principal="...")
```

Pass an `S3ObjectLockSink` anywhere a `LocalFileSink` would go (the
`AuditLog` constructor, `verify_sink()`, `custody.evidence
.build_manifest`); nothing else in Custody needs to know which sink
it's talking to, that's the point of `AuditSink` being a `Protocol`.

`custody serve` and the other CLI commands still default to
`LocalFileSink` in this release; wiring a configuration option to pick
`S3ObjectLockSink` instead is the one piece of integration left for a
deployment to do itself, not yet a `custody init` flag.

### `retention_mode`

- `"GOVERNANCE"` (default): a user with the `s3:BypassGovernanceRetention`
  IAM permission can still remove the lock or delete the object early.
  Appropriate for most deployments, it is still a real barrier against
  routine deletion and against anyone without that specific permission.
- `"COMPLIANCE"`: nobody can remove the lock or delete the object
  before the retention period elapses, not even the AWS account root
  user. Choose this only if that is genuinely the guarantee your
  deployment needs; it is irreversible once set.

## What is verified here, and what is not

This sink issues the real boto3 S3 API calls (`put_object` with
`ObjectLockMode` and `ObjectLockRetainUntilDate`, `list_objects_v2`,
`get_object`) that, on actual AWS S3 with Object Lock enabled on the
bucket, make a write genuinely immutable for the retention period.

Tests in this repository (`tests/test_s3_sink.py`) run against a real
LocalStack container, not a mock, and confirm:

- writing and reading an entry round-trips correctly
- entries come back in seq order regardless of write order (S3's
  lexicographic key listing, driven by this sink's zero-padded keys)
- checkpoints and entries stay in separate key spaces
- a `prefix` correctly scopes two sinks sharing one bucket
- a corrupted object raises `CorruptAuditLogError` rather than
  crashing the reader (same contract as `LocalFileSink`)
- the actual request sent to `put_object` carries `ObjectLockMode`
  and `ObjectLockRetainUntilDate`

**What is explicitly NOT verified: the write-once guarantee itself.**
LocalStack's free Community edition accepts Object Lock parameters on
a request but does not enforce the resulting retention, a `DeleteObject`
that should be blocked currently succeeds against LocalStack Community
(confirmed directly while building this: see
https://docs.localstack.cloud/aws/services/s3/, Object Lock enforcement
is a LocalStack Pro feature as of this writing). That means this
project cannot verify, in this development environment, that the one
property an Object Lock sink exists to provide actually holds. It can
only verify that the sink sends the right requests and reads the
resulting data back correctly. Confirming the retention guarantee
itself requires either LocalStack Pro or a real AWS account; treat
that as the deployment's own responsibility to confirm once, the same
way any AWS IAM policy or bucket policy would be confirmed before
relying on it.
