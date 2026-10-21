"""Tests against a real (local) S3-compatible server, not a mock: the
whole point of this sink is a specific set of real S3 API calls
(Object Lock parameters on `put_object`), so a mocked client could pass
while the real calls were subtly wrong. See
custody/audit/s3_sink.py's module docstring for what LocalStack's free
Community edition does and does not verify -- the retention/WORM
guarantee itself is NOT checked here, only read/write/list/ordering
correctness, because LocalStack Community accepts but does not enforce
Object Lock retention (a known gap, not a bug in this test suite).
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from datetime import UTC, datetime

import pytest

from custody.audit.models import AuditEntry, Checkpoint, EventType
from custody.audit.s3_sink import S3ObjectLockSink
from custody.audit.sinks import CorruptAuditLogError
from tests.conftest import requires_docker

LOCALSTACK_IMAGE = "localstack/localstack:3.0"
_PORT = 14566  # a fixed, unusual port: avoids clashing with a developer's own 4566


def _localstack_available() -> bool:
    try:
        import docker

        docker.from_env().ping()
        return True
    except Exception:  # noqa: BLE001
        return False


requires_localstack = pytest.mark.skipif(
    not _localstack_available(), reason="Docker daemon not reachable for LocalStack"
)


@pytest.fixture(scope="module")
def localstack_endpoint() -> Iterator[str]:
    import docker

    client = docker.from_env()
    name = "custody-test-localstack"
    try:
        client.containers.get(name).remove(force=True)
    except docker.errors.NotFound:
        pass

    container = client.containers.run(
        LOCALSTACK_IMAGE,
        detach=True,
        name=name,
        ports={"4566/tcp": _PORT},
        environment={"SERVICES": "s3"},
    )
    endpoint = f"http://localhost:{_PORT}"
    try:
        _wait_for_ready(endpoint)
        yield endpoint
    finally:
        container.remove(force=True)


def _wait_for_ready(endpoint: str, timeout: float = 30.0) -> None:
    import boto3

    deadline = time.monotonic() + timeout
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            client = boto3.client(
                "s3",
                endpoint_url=endpoint,
                aws_access_key_id="test",
                aws_secret_access_key="test",
                region_name="us-east-1",
            )
            client.list_buckets()
            return
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            time.sleep(0.5)
    raise RuntimeError(f"LocalStack never became ready: {last_exc}")


@pytest.fixture
def s3_client(localstack_endpoint: str):  # type: ignore[no-untyped-def]
    import boto3

    return boto3.client(
        "s3",
        endpoint_url=localstack_endpoint,
        aws_access_key_id="test",
        aws_secret_access_key="test",
        region_name="us-east-1",
    )


@pytest.fixture
def bucket(s3_client) -> str:  # type: ignore[no-untyped-def]
    """A fresh bucket per test: these tests share one LocalStack
    container (module-scoped, expensive to start), so each test needs
    its own bucket rather than a fixed name, or one test's writes would
    leak into the next."""
    import uuid

    name = f"custody-audit-test-{uuid.uuid4().hex[:12]}"
    s3_client.create_bucket(Bucket=name, ObjectLockEnabledForBucket=True)
    return name


@requires_docker
@requires_localstack
class TestS3ObjectLockSink:
    def test_append_and_read_entries_round_trips(self, s3_client, bucket: str) -> None:  # type: ignore[no-untyped-def]
        sink = S3ObjectLockSink(bucket, s3_client=s3_client)
        entry = AuditEntry(
            seq=0,
            timestamp=datetime(2026, 1, 1, tzinfo=UTC),
            session_id="s",
            principal="agent",
            event_type=EventType.request,
            payload={"tool": "catalog.list"},
            prev_hash="0" * 64,
            entry_hash="1" * 64,
        )
        sink.append_entry(entry)
        read_back = list(sink.read_entries())
        assert read_back == [entry]

    def test_entries_come_back_in_seq_order_regardless_of_write_order(
        self, s3_client, bucket: str
    ) -> None:
        sink = S3ObjectLockSink(bucket, s3_client=s3_client)

        def make(seq: int) -> AuditEntry:
            return AuditEntry(
                seq=seq,
                timestamp=datetime(2026, 1, 1, tzinfo=UTC),
                session_id="s",
                principal="agent",
                event_type=EventType.request,
                payload={"n": seq},
                prev_hash="0" * 64,
                entry_hash=f"{seq:064d}",
            )

        for seq in (2, 0, 1):  # deliberately out of order
            sink.append_entry(make(seq))

        seqs = [e.seq for e in sink.read_entries()]
        assert seqs == [0, 1, 2]

    def test_checkpoints_are_separate_from_entries(self, s3_client, bucket: str) -> None:
        sink = S3ObjectLockSink(bucket, s3_client=s3_client)
        checkpoint = Checkpoint(
            seq=0,
            entry_hash="a" * 64,
            timestamp=datetime(2026, 1, 1, tzinfo=UTC),
            signature="b" * 128,
            public_key="c" * 64,
        )
        sink.append_checkpoint(checkpoint)
        assert list(sink.read_checkpoints()) == [checkpoint]
        assert list(sink.read_entries()) == []

    def test_prefix_scopes_keys_so_two_sinks_share_a_bucket_cleanly(
        self, s3_client, bucket: str
    ) -> None:
        sink_a = S3ObjectLockSink(bucket, prefix="deployment-a", s3_client=s3_client)
        sink_b = S3ObjectLockSink(bucket, prefix="deployment-b", s3_client=s3_client)
        entry_a = AuditEntry(
            seq=0,
            timestamp=datetime(2026, 1, 1, tzinfo=UTC),
            session_id="a",
            principal="agent",
            event_type=EventType.request,
            payload={},
            prev_hash="0" * 64,
            entry_hash="a" * 64,
        )
        sink_a.append_entry(entry_a)

        assert list(sink_a.read_entries()) == [entry_a]
        assert list(sink_b.read_entries()) == []

    def test_empty_bucket_reads_as_no_entries(self, s3_client, bucket: str) -> None:
        sink = S3ObjectLockSink(bucket, s3_client=s3_client)
        assert list(sink.read_entries()) == []
        assert list(sink.read_checkpoints()) == []

    def test_put_object_call_actually_requests_object_lock(
        self, s3_client, bucket: str
    ) -> None:
        """Confirms the real request this sink sends carries Object
        Lock parameters -- the part LocalStack Community does not
        enforce (see module docstring), so this test checks the
        request shape itself rather than the (unavailable here)
        enforcement outcome."""
        calls: list[dict[str, object]] = []
        real_put_object = s3_client.put_object

        def recording_put_object(**kwargs: object) -> object:
            calls.append(kwargs)
            return real_put_object(**kwargs)

        s3_client.put_object = recording_put_object
        sink = S3ObjectLockSink(bucket, retention_mode="GOVERNANCE", s3_client=s3_client)
        entry = AuditEntry(
            seq=0,
            timestamp=datetime(2026, 1, 1, tzinfo=UTC),
            session_id="s",
            principal="agent",
            event_type=EventType.request,
            payload={},
            prev_hash="0" * 64,
            entry_hash="e" * 64,
        )
        sink.append_entry(entry)
        assert len(calls) == 1
        assert calls[0]["ObjectLockMode"] == "GOVERNANCE"
        assert "ObjectLockRetainUntilDate" in calls[0]

    def test_a_corrupted_object_raises_rather_than_crashing_the_reader(
        self, s3_client, bucket: str
    ) -> None:
        sink = S3ObjectLockSink(bucket, s3_client=s3_client)
        s3_client.put_object(
            Bucket=bucket,
            Key="entries/00000000000000000000.json",
            Body=b"not valid json at all",
        )
        with pytest.raises(CorruptAuditLogError, match="entries/"):
            list(sink.read_entries())


class TestConstructionWithoutAnInjectedClient:
    """No Docker or LocalStack needed: confirms the default-client
    wiring without ever making a network call."""

    def test_default_construction_builds_a_real_boto3_client(self, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        import boto3

        calls: list[tuple[object, ...]] = []
        real_client = boto3.client

        def recording_client(*args: object, **kwargs: object) -> object:
            calls.append(args)
            return real_client("s3", region_name="us-east-1")

        monkeypatch.setattr(boto3, "client", recording_client)
        S3ObjectLockSink("some-bucket")
        assert calls == [("s3",)]
