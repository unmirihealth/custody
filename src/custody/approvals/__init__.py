"""Approval broker. Pending approvals live in SQLite; a decision requires
an approver identity, a reason, and a role the policy's rule actually
asked for. The requester can never approve their own request. A
`require_approval` decision from custody.policy flows into
`ApprovalBroker.request()`; `ApprovalBroker.wait()` is what a gateway
blocks on until a human decides or the approval expires (timeout = deny).
"""

from custody.approvals.broker import (
    DEFAULT_POLL_INTERVAL,
    DEFAULT_TIMEOUT,
    ApprovalAlreadyResolvedError,
    ApprovalBroker,
    ApprovalExpiredError,
    ApprovalNotFoundError,
    SelfApprovalError,
    UnauthorizedApproverError,
)
from custody.approvals.models import (
    ApprovalDecision,
    ApprovalStatus,
    ApprovalSummary,
    PendingApproval,
)
from custody.approvals.notifier import ApprovalNotifier, NullNotifier, WebhookNotifier
from custody.approvals.principals import Principal, PrincipalDirectory
from custody.approvals.store import ApprovalStore, DuplicateApproverError

__all__ = [
    "DEFAULT_POLL_INTERVAL",
    "DEFAULT_TIMEOUT",
    "ApprovalAlreadyResolvedError",
    "ApprovalBroker",
    "ApprovalDecision",
    "ApprovalExpiredError",
    "ApprovalNotFoundError",
    "ApprovalNotifier",
    "ApprovalStatus",
    "ApprovalStore",
    "ApprovalSummary",
    "DuplicateApproverError",
    "NullNotifier",
    "PendingApproval",
    "Principal",
    "PrincipalDirectory",
    "SelfApprovalError",
    "UnauthorizedApproverError",
    "WebhookNotifier",
]
