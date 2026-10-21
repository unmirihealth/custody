"""The approval broker: turns a policy's `require_approval` decision into
a pending request a human has to act on, and a decision an agent has to
wait for. See docs/threat-model.md T4 for what this does and does not
guarantee about approver identity in v0.1.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

from custody.approvals.models import (
    ApprovalDecision,
    ApprovalStatus,
    ApprovalSummary,
    PendingApproval,
)
from custody.approvals.principals import PrincipalDirectory
from custody.approvals.store import ApprovalStore

DEFAULT_TIMEOUT = timedelta(minutes=15)
DEFAULT_POLL_INTERVAL = timedelta(seconds=1)


class ApprovalNotFoundError(Exception):
    pass


class ApprovalAlreadyResolvedError(Exception):
    def __init__(self, approval_id: str, status: ApprovalStatus) -> None:
        self.approval_id = approval_id
        self.status = status
        super().__init__(f"approval {approval_id!r} is already {status.value}, not pending")


class ApprovalExpiredError(Exception):
    def __init__(self, approval_id: str) -> None:
        self.approval_id = approval_id
        super().__init__(f"approval {approval_id!r} has expired; timeout = deny")


class SelfApprovalError(Exception):
    """The requesting principal tried to decide on their own request.
    Enforced unconditionally: this is a hard rule
    (CLAUDE.md-for-custody's "the agent can never approve its own
    request"), not a policy option."""

    def __init__(self, principal: str) -> None:
        self.principal = principal
        super().__init__(f"{principal!r} is both the requester and the approver")


class UnauthorizedApproverError(Exception):
    def __init__(self, approver: str, required_roles: list[str]) -> None:
        self.approver = approver
        self.required_roles = required_roles
        super().__init__(
            f"{approver!r} does not hold any of the required roles {required_roles}"
        )


class ApprovalBroker:
    def __init__(
        self,
        store: ApprovalStore,
        principals: PrincipalDirectory,
        *,
        default_timeout: timedelta = DEFAULT_TIMEOUT,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._store = store
        self._principals = principals
        self._default_timeout = default_timeout
        self._clock = clock

    @classmethod
    def open(
        cls,
        db_path: Path,
        principals_path: Path,
        *,
        default_timeout: timedelta = DEFAULT_TIMEOUT,
    ) -> ApprovalBroker:
        return cls(
            ApprovalStore(db_path),
            PrincipalDirectory.load(principals_path),
            default_timeout=default_timeout,
        )

    def close(self) -> None:
        self._store.close()

    def request(
        self,
        *,
        requester: str,
        rule_id: str,
        summary: ApprovalSummary,
        required_count: int,
        required_roles: list[str],
        timeout: timedelta | None = None,
    ) -> PendingApproval:
        now = self._clock()
        approval = PendingApproval(
            id=str(uuid.uuid4()),
            requester=requester,
            rule_id=rule_id,
            summary=summary,
            required_count=required_count,
            required_roles=required_roles,
            created_at=now,
            expires_at=now + (timeout or self._default_timeout),
            status=ApprovalStatus.pending,
        )
        self._store.create(approval)
        return approval

    def _resolve_if_expired(self, approval: PendingApproval) -> PendingApproval:
        if approval.status == ApprovalStatus.pending and self._clock() > approval.expires_at:
            self._store.set_status(approval.id, ApprovalStatus.expired)
            return PendingApproval(**{**approval.model_dump(), "status": ApprovalStatus.expired})
        return approval

    def get(self, approval_id: str) -> PendingApproval:
        approval = self._store.get(approval_id)
        if approval is None:
            raise ApprovalNotFoundError(approval_id)
        return self._resolve_if_expired(approval)

    def list_pending(self) -> list[PendingApproval]:
        # Lazily expire anything whose deadline has passed, so a stale
        # list_pending() call doesn't show an approval a `wait()` call
        # would already treat as expired.
        pending = self._store.list_pending()
        fresh = []
        for approval in pending:
            resolved = self._resolve_if_expired(approval)
            if resolved.status == ApprovalStatus.pending:
                fresh.append(resolved)
        return fresh

    def decide(
        self, approval_id: str, approver: str, approve: bool, reason: str
    ) -> PendingApproval:
        """Record one approver's decision. Raises rather than silently
        ignoring a bad decide call: ApprovalNotFoundError,
        ApprovalAlreadyResolvedError, ApprovalExpiredError,
        SelfApprovalError, UnauthorizedApproverError, or (from the store)
        DuplicateApproverError if this approver already decided once.

        A single `approve=False` resolves the whole approval to denied
        immediately (fail-fast): a privacy officer rejecting an export
        should not wait on a second approver who may never show up.
        """
        approval = self.get(approval_id)  # expiry-checked

        if approval.status != ApprovalStatus.pending:
            if approval.status == ApprovalStatus.expired:
                raise ApprovalExpiredError(approval_id)
            raise ApprovalAlreadyResolvedError(approval_id, approval.status)

        if approver == approval.requester:
            raise SelfApprovalError(approver)

        if not self._principals.has_any_role(approver, approval.required_roles):
            raise UnauthorizedApproverError(approver, approval.required_roles)

        decision = ApprovalDecision(
            approval_id=approval_id,
            approver=approver,
            approve=approve,
            reason=reason,
            decided_at=self._clock(),
        )
        self._store.add_decision(decision)  # raises DuplicateApproverError on repeat

        if not approve:
            self._store.set_status(approval_id, ApprovalStatus.denied)
            return self.get(approval_id)

        decisions = self._store.list_decisions(approval_id)
        approve_count = sum(1 for d in decisions if d.approve)
        if approve_count >= approval.required_count:
            self._store.set_status(approval_id, ApprovalStatus.approved)

        return self.get(approval_id)

    def wait(
        self,
        approval_id: str,
        timeout: timedelta | None = None,
        *,
        poll_interval: timedelta = DEFAULT_POLL_INTERVAL,
        sleep: Callable[[float], None] = time.sleep,
    ) -> ApprovalStatus:
        """Block (polling the store) until `approval_id` resolves or its
        own expiry is reached, whichever comes first. `timeout` here only
        shortens how long THIS CALL waits, it does not change the
        approval's own `expires_at`, call `request(..., timeout=...)` for
        that. Returns the resolved status; `expired` and `denied` both
        mean "do not proceed," callers should not treat `expired` as a
        softer outcome than `denied`.
        """
        deadline = (self._clock() + timeout) if timeout is not None else None
        while True:
            approval = self.get(approval_id)
            if approval.status != ApprovalStatus.pending:
                return approval.status
            if deadline is not None and self._clock() >= deadline:
                # Caller's own wait budget ran out, not the approval's.
                return ApprovalStatus.pending
            sleep(poll_interval.total_seconds())
