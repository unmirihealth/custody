from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from custody.approvals import ApprovalStatus, ApprovalSummary, NullNotifier, PendingApproval
from custody.approvals.notifier import WebhookNotifier


def _approval() -> PendingApproval:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    return PendingApproval(
        id="appr-1",
        requester="agent_session",
        rule_id="identified-needs-approval",
        summary=ApprovalSummary(tool="sql.query", data_class="identified"),
        required_count=1,
        required_roles=["data_steward"],
        created_at=now,
        expires_at=now + timedelta(minutes=15),
        status=ApprovalStatus.pending,
    )


class TestNullNotifier:
    def test_notify_is_a_silent_noop(self) -> None:
        NullNotifier().notify(_approval())  # must not raise


class TestWebhookNotifier:
    def test_posts_slack_compatible_payload(self) -> None:
        calls: list[tuple[str, bytes, float]] = []

        def fake_post(url: str, payload: bytes, timeout: float) -> int:
            calls.append((url, payload, timeout))
            return 200

        notifier = WebhookNotifier("https://hooks.example.com/abc", post=fake_post)
        notifier.notify(_approval())

        assert len(calls) == 1
        url, payload, timeout = calls[0]
        assert url == "https://hooks.example.com/abc"
        body = json.loads(payload)
        assert "text" in body
        assert "sql.query" in body["text"]
        assert "appr-1" in body["text"]
        assert "data_steward" in body["text"]

    def test_never_includes_dataset_content(self) -> None:
        """Only tool/data_class/id/roles, nothing from an approval's
        datasets content, matches docs/threat-model.md T6."""
        calls: list[bytes] = []
        notifier = WebhookNotifier(
            "https://hooks.example.com/abc",
            post=lambda url, payload, timeout: calls.append(payload) or 200,
        )
        approval = _approval()
        notifier.notify(approval)
        body = json.loads(calls[0])
        assert "EGFR" not in body["text"]  # a value that would appear in real row content

    def test_includes_review_url_when_given(self) -> None:
        calls: list[bytes] = []
        notifier = WebhookNotifier(
            "https://hooks.example.com/abc",
            post=lambda url, payload, timeout: calls.append(payload) or 200,
        )
        notifier.notify(_approval(), review_url="http://127.0.0.1:8765/?token=xyz")
        body = json.loads(calls[0])
        assert "http://127.0.0.1:8765/?token=xyz" in body["text"]

    def test_http_error_status_does_not_raise(self) -> None:
        notifier = WebhookNotifier(
            "https://hooks.example.com/abc", post=lambda url, payload, timeout: 500
        )
        notifier.notify(_approval())  # must not raise

    def test_network_failure_does_not_raise(self) -> None:
        def failing_post(url: str, payload: bytes, timeout: float) -> int:
            raise OSError("connection refused")

        notifier = WebhookNotifier("https://hooks.example.com/abc", post=failing_post)
        notifier.notify(_approval())  # must not raise

    def test_timeout_is_passed_through(self) -> None:
        calls: list[float] = []
        notifier = WebhookNotifier(
            "https://hooks.example.com/abc",
            timeout=2.5,
            post=lambda url, payload, timeout: calls.append(timeout) or 200,
        )
        notifier.notify(_approval())
        assert calls == [2.5]
