from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from custody.approvals import (
    ApprovalAlreadyResolvedError,
    ApprovalBroker,
    ApprovalExpiredError,
    ApprovalNotFoundError,
    ApprovalStatus,
    ApprovalStore,
    ApprovalSummary,
    DuplicateApproverError,
    PrincipalDirectory,
    SelfApprovalError,
    UnauthorizedApproverError,
)


class FakeClock:
    """A controllable clock for expiry tests: advance it by hand instead
    of sleeping for real."""

    def __init__(self, start: datetime | None = None) -> None:
        self._now = start or datetime(2026, 1, 1, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self._now

    def advance(self, delta: timedelta) -> None:
        self._now += delta


@pytest.fixture
def principals(fixtures_dir: Path) -> PrincipalDirectory:
    return PrincipalDirectory.load(fixtures_dir / "principals.yaml")


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def broker(tmp_path: Path, principals: PrincipalDirectory, clock: FakeClock) -> ApprovalBroker:
    store = ApprovalStore(tmp_path / "approvals.db")
    return ApprovalBroker(store, principals, clock=clock)


def _summary() -> ApprovalSummary:
    return ApprovalSummary(
        tool="sql.query",
        datasets=["tumor_registry_identified"],
        data_class="identified",
        matched_rule_id="identified-needs-approval",
    )


class TestRequestAndSinglePersonApproval:
    def test_request_creates_pending_approval(self, broker: ApprovalBroker) -> None:
        approval = broker.request(
            requester="agent_session",
            rule_id="identified-needs-approval",
            summary=_summary(),
            required_count=1,
            required_roles=["data_steward"],
        )
        assert approval.status == ApprovalStatus.pending
        assert approval in broker.list_pending()

    def test_single_approval_resolves_approved(self, broker: ApprovalBroker) -> None:
        approval = broker.request(
            requester="agent_session",
            rule_id="r1",
            summary=_summary(),
            required_count=1,
            required_roles=["data_steward"],
        )
        result = broker.decide(
            approval.id, "jane_steward", True, "looks fine, routine cohort query"
        )
        assert result.status == ApprovalStatus.approved
        assert result not in broker.list_pending()

    def test_deny_resolves_denied(self, broker: ApprovalBroker) -> None:
        approval = broker.request(
            requester="agent_session",
            rule_id="r1",
            summary=_summary(),
            required_count=1,
            required_roles=["data_steward"],
        )
        result = broker.decide(approval.id, "jane_steward", False, "not justified")
        assert result.status == ApprovalStatus.denied


class TestTwoPersonApproval:
    def test_one_of_two_stays_pending(self, broker: ApprovalBroker) -> None:
        approval = broker.request(
            requester="agent_session",
            rule_id="export-two-person",
            summary=_summary(),
            required_count=2,
            required_roles=["data_steward", "privacy_officer"],
        )
        result = broker.decide(approval.id, "jane_steward", True, "ok from data side")
        assert result.status == ApprovalStatus.pending

    def test_two_distinct_approvers_resolve_approved(self, broker: ApprovalBroker) -> None:
        approval = broker.request(
            requester="agent_session",
            rule_id="export-two-person",
            summary=_summary(),
            required_count=2,
            required_roles=["data_steward", "privacy_officer"],
        )
        broker.decide(approval.id, "jane_steward", True, "ok from data side")
        result = broker.decide(approval.id, "priya_privacy", True, "ok from privacy side")
        assert result.status == ApprovalStatus.approved

    def test_one_deny_overrides_even_with_a_prior_approve(self, broker: ApprovalBroker) -> None:
        """Fail-fast: a single denial resolves the whole request, it does
        not wait for whatever the second approver might have said."""
        approval = broker.request(
            requester="agent_session",
            rule_id="export-two-person",
            summary=_summary(),
            required_count=2,
            required_roles=["data_steward", "privacy_officer"],
        )
        broker.decide(approval.id, "jane_steward", True, "ok from data side")
        result = broker.decide(approval.id, "priya_privacy", False, "export scope too broad")
        assert result.status == ApprovalStatus.denied

    def test_same_approver_cannot_satisfy_both_slots(self, broker: ApprovalBroker) -> None:
        approval = broker.request(
            requester="agent_session",
            rule_id="export-two-person",
            summary=_summary(),
            required_count=2,
            required_roles=["data_steward", "privacy_officer"],
        )
        broker.decide(approval.id, "sam_both", True, "approving as data steward")
        with pytest.raises(DuplicateApproverError):
            broker.decide(approval.id, "sam_both", True, "approving again as privacy officer")


class TestGuardrails:
    def test_self_approval_rejected(self, broker: ApprovalBroker) -> None:
        approval = broker.request(
            requester="jane_steward",
            rule_id="r1",
            summary=_summary(),
            required_count=1,
            required_roles=["data_steward"],
        )
        with pytest.raises(SelfApprovalError):
            broker.decide(approval.id, "jane_steward", True, "self-approving")

    def test_unauthorized_role_rejected(self, broker: ApprovalBroker) -> None:
        approval = broker.request(
            requester="agent_session",
            rule_id="r1",
            summary=_summary(),
            required_count=1,
            required_roles=["privacy_officer"],
        )
        with pytest.raises(UnauthorizedApproverError):
            broker.decide(approval.id, "jane_steward", True, "I'll approve it anyway")

    def test_unknown_principal_rejected(self, broker: ApprovalBroker) -> None:
        approval = broker.request(
            requester="agent_session",
            rule_id="r1",
            summary=_summary(),
            required_count=1,
            required_roles=["data_steward"],
        )
        with pytest.raises(UnauthorizedApproverError):
            broker.decide(approval.id, "nobody_in_the_directory", True, "trust me")

    def test_deciding_on_unknown_approval_raises(self, broker: ApprovalBroker) -> None:
        with pytest.raises(ApprovalNotFoundError):
            broker.decide("not-a-real-id", "jane_steward", True, "x")

    def test_deciding_twice_on_a_resolved_approval_raises(self, broker: ApprovalBroker) -> None:
        approval = broker.request(
            requester="agent_session",
            rule_id="r1",
            summary=_summary(),
            required_count=1,
            required_roles=["data_steward"],
        )
        broker.decide(approval.id, "jane_steward", True, "fine")
        with pytest.raises(ApprovalAlreadyResolvedError):
            broker.decide(approval.id, "sam_both", True, "also fine")


class TestExpiry:
    def test_get_marks_expired_past_deadline(
        self, broker: ApprovalBroker, clock: FakeClock
    ) -> None:
        approval = broker.request(
            requester="agent_session",
            rule_id="r1",
            summary=_summary(),
            required_count=1,
            required_roles=["data_steward"],
            timeout=timedelta(minutes=15),
        )
        clock.advance(timedelta(minutes=16))
        refreshed = broker.get(approval.id)
        assert refreshed.status == ApprovalStatus.expired

    def test_deciding_on_expired_approval_raises(
        self, broker: ApprovalBroker, clock: FakeClock
    ) -> None:
        approval = broker.request(
            requester="agent_session",
            rule_id="r1",
            summary=_summary(),
            required_count=1,
            required_roles=["data_steward"],
            timeout=timedelta(minutes=15),
        )
        clock.advance(timedelta(minutes=16))
        with pytest.raises(ApprovalExpiredError):
            broker.decide(approval.id, "jane_steward", True, "too late")

    def test_expired_approvals_drop_out_of_list_pending(
        self, broker: ApprovalBroker, clock: FakeClock
    ) -> None:
        broker.request(
            requester="agent_session",
            rule_id="r1",
            summary=_summary(),
            required_count=1,
            required_roles=["data_steward"],
            timeout=timedelta(minutes=5),
        )
        clock.advance(timedelta(minutes=6))
        assert broker.list_pending() == []

    def test_default_timeout_is_fifteen_minutes(
        self, broker: ApprovalBroker, clock: FakeClock
    ) -> None:
        approval = broker.request(
            requester="agent_session",
            rule_id="r1",
            summary=_summary(),
            required_count=1,
            required_roles=["data_steward"],
        )
        assert approval.expires_at - approval.created_at == timedelta(minutes=15)


class TestWait:
    def test_wait_returns_immediately_once_resolved(self, broker: ApprovalBroker) -> None:
        approval = broker.request(
            requester="agent_session",
            rule_id="r1",
            summary=_summary(),
            required_count=1,
            required_roles=["data_steward"],
        )
        broker.decide(approval.id, "jane_steward", True, "fine")

        sleeps: list[float] = []
        status = broker.wait(approval.id, sleep=sleeps.append)
        assert status == ApprovalStatus.approved
        assert sleeps == []  # already resolved: never had to poll

    def test_wait_polls_until_decided(self, broker: ApprovalBroker) -> None:
        approval = broker.request(
            requester="agent_session",
            rule_id="r1",
            summary=_summary(),
            required_count=1,
            required_roles=["data_steward"],
        )

        calls = {"n": 0}

        def fake_sleep(seconds: float) -> None:
            calls["n"] += 1
            if calls["n"] == 2:
                broker.decide(approval.id, "jane_steward", True, "approved on the second poll")

        status = broker.wait(approval.id, sleep=fake_sleep)
        assert status == ApprovalStatus.approved
        assert calls["n"] == 2

    def test_wait_honors_its_own_timeout_without_touching_the_approval(
        self, broker: ApprovalBroker, clock: FakeClock
    ) -> None:
        approval = broker.request(
            requester="agent_session",
            rule_id="r1",
            summary=_summary(),
            required_count=1,
            required_roles=["data_steward"],
            timeout=timedelta(minutes=15),  # the approval itself is far from expiring
        )

        def fake_sleep(_seconds: float) -> None:
            clock.advance(timedelta(seconds=2))

        status = broker.wait(approval.id, timeout=timedelta(seconds=5), sleep=fake_sleep)
        assert status == ApprovalStatus.pending  # caller's wait budget ran out
        # The approval itself is still live, only the caller's own wait gave up.
        assert broker.get(approval.id).status == ApprovalStatus.pending
