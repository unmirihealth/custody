"""S3 Object Lock audit sink: the write-once-storage `AuditSink`
docs/audit-log.md has documented as a hook since v0.1, actually
implemented. Requires `boto3` (the `s3` optional dependency group,
`pip install custody-mcp[s3]`); this module is never imported by
`custody.audit`'s own `__init__`, so a deployment that never configures
S3 never needs boto3 installed at all, matching "Custody does not
require AWS, or any particular cloud, to run" (ROADMAP.md, now minus
this one item).

**What is and is not verified here.** This module issues the real
boto3 S3 API calls (`put_object` with `ObjectLockMode` and
`ObjectLockRetainUntilDate`, `list_objects_v2`, `get_object`) that, on
actual AWS S3 with Object Lock enabled on the bucket, make a write
genuinely immutable for the retention period: a `DeleteObject` or a
second `PutObject` at the same key fails at the S3 API level. Tests in
this repository run against LocalStack, a local S3-compatible server,
and confirm the read/write/list/ordering behavior end to end. LocalStack's
free Community edition accepts Object Lock parameters on a request but
does **not** actually enforce the resulting retention (a delete that
should be blocked currently succeeds), a known gap in that tier,
documented at https://docs.localstack.cloud/aws/services/s3/ (Object
Lock enforcement is a LocalStack Pro feature as of this writing). So:
the interface and data-flow correctness of this sink is verified
locally; the actual write-once guarantee it is built to provide is
not, and cannot be, verified without either LocalStack Pro or real AWS
S3. See docs/s3-object-lock-sink.md.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import TYPE_CHECKING, Any

from pydantic import ValidationError

from custody.audit.models import AuditEntry, Checkpoint
from custody.audit.sinks import CorruptAuditLogError

if TYPE_CHECKING:
    from datetime import datetime

# Zero-padded wide enough that plain lexicographic S3 key ordering
# (what list_objects_v2 returns) matches numeric seq ordering, the same
# property LocalFileSink gets for free from file-append order.
_SEQ_WIDTH = 20


class S3ObjectLockSink:
    """One object per entry, one object per checkpoint, each key
    carrying its zero-padded seq so a plain `list_objects_v2` call
    returns them in order. Does not create or configure the bucket
    itself (Object Lock must be enabled on the bucket at creation time,
    an S3 restriction, not this class's choice) -- see
    docs/s3-object-lock-sink.md for the one-time bucket setup.
    """

    def __init__(
        self,
        bucket: str,
        prefix: str = "",
        *,
        retention_mode: str = "GOVERNANCE",
        retain_for_days: int = 3650,
        s3_client: Any = None,
    ) -> None:
        """`retention_mode` is "GOVERNANCE" (default; an S3 user with
        the right IAM permission can still remove the lock) or
        "COMPLIANCE" (nobody can, not even the account root user, until
        the retention period elapses -- choose this only if that is
        genuinely what your deployment needs, it cannot be undone
        early). `s3_client`, when given, is used as-is (dependency
        injection for tests against LocalStack); otherwise a real
        `boto3.client("s3")` is constructed using the environment's own
        AWS credential chain.
        """
        if s3_client is not None:
            self._s3 = s3_client
        else:
            import boto3  # local import: boto3 is an optional dependency

            self._s3 = boto3.client("s3")
        self._bucket = bucket
        self._prefix = prefix.rstrip("/")
        self._retention_mode = retention_mode
        self._retain_for_days = retain_for_days

    def _key(self, kind: str, seq: int) -> str:
        base = f"{kind}/{seq:0{_SEQ_WIDTH}d}.json"
        return f"{self._prefix}/{base}" if self._prefix else base

    def _retain_until(self) -> datetime:
        from datetime import UTC, datetime, timedelta

        return datetime.now(UTC) + timedelta(days=self._retain_for_days)

    def append_entry(self, entry: AuditEntry) -> None:
        self._s3.put_object(
            Bucket=self._bucket,
            Key=self._key("entries", entry.seq),
            Body=entry.model_dump_json().encode("utf-8"),
            ContentType="application/json",
            ObjectLockMode=self._retention_mode,
            ObjectLockRetainUntilDate=self._retain_until(),
        )

    def append_checkpoint(self, checkpoint: Checkpoint) -> None:
        self._s3.put_object(
            Bucket=self._bucket,
            Key=self._key("checkpoints", checkpoint.seq),
            Body=checkpoint.model_dump_json().encode("utf-8"),
            ContentType="application/json",
            ObjectLockMode=self._retention_mode,
            ObjectLockRetainUntilDate=self._retain_until(),
        )

    def read_entries(self) -> Iterator[AuditEntry]:
        yield from self._read_objects("entries", AuditEntry)

    def read_checkpoints(self) -> Iterator[Checkpoint]:
        yield from self._read_objects("checkpoints", Checkpoint)

    def _read_objects(self, kind: str, model: type[AuditEntry] | type[Checkpoint]) -> Iterator[Any]:
        key_prefix = f"{self._prefix}/{kind}/" if self._prefix else f"{kind}/"
        paginator = self._s3.get_paginator("list_objects_v2")
        keys: list[str] = []
        for page in paginator.paginate(Bucket=self._bucket, Prefix=key_prefix):
            keys.extend(obj["Key"] for obj in page.get("Contents", []))
        for key in sorted(keys):
            body = self._s3.get_object(Bucket=self._bucket, Key=key)["Body"].read()
            try:
                text = body.decode("utf-8")
                data = json.loads(text)
                yield model.model_validate(data)
            except (UnicodeDecodeError, json.JSONDecodeError, ValidationError) as exc:
                raise CorruptAuditLogError(key, str(exc)) from exc


__all__ = ["S3ObjectLockSink"]
