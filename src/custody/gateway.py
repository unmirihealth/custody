"""The gateway: the seven-step flow from README.md's diagram, as a plain
Python class with no MCP transport dependency, so it is testable without
spinning up a protocol server. `custody/tools/*` call `Gateway.authorize`
before doing anything, then write their own execution/result audit
entries once the work is actually done.

    1. Identify principal + session       -> constructor args
    2. Classify request                   -> policy.evaluate() via catalog
    3. Policy engine                      -> allow | deny | require_approval
    4. Approval broker                    -> wait for a human (timeout = deny)
    5. Executor                           -> left to the caller (custody/tools)
    6. Output guard                       -> left to the caller (custody/tools)
    7. Audit log                          -> every step below, every time
"""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import timedelta

from pydantic import BaseModel, ConfigDict

from custody.approvals import DEFAULT_POLL_INTERVAL, ApprovalBroker, ApprovalStatus, ApprovalSummary
from custody.approvals.notifier import ApprovalNotifier, NullNotifier
from custody.audit import AuditLog, EventType
from custody.catalog import Catalog, DataClass
from custody.policy import Decision, PolicyBackend, PolicyResult, ToolRequest
from custody.routing import ModelRouter


class AuthzResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    allowed: bool
    data_class: DataClass
    reason: str
    policy_result: PolicyResult
    approval_id: str | None = None


class Gateway:
    def __init__(
        self,
        *,
        policy: PolicyBackend,
        catalog: Catalog,
        audit: AuditLog,
        approvals: ApprovalBroker,
        session_id: str,
        principal: str,
        router: ModelRouter | None = None,
        approval_timeout: timedelta | None = None,
        approval_poll_interval: timedelta = DEFAULT_POLL_INTERVAL,
        approval_sleep: Callable[[float], None] = time.sleep,
        notifier: ApprovalNotifier | None = None,
    ) -> None:
        self.policy = policy
        self.catalog = catalog
        self.audit = audit
        self.approvals = approvals
        self.session_id = session_id
        self.principal = principal
        self.router = router or ModelRouter()
        self._approval_timeout = approval_timeout
        self._approval_poll_interval = approval_poll_interval
        self._approval_sleep = approval_sleep
        # No review_url is passed to notify(): the gateway has no way to
        # know the approvals UI's URL or its per-run startup token (see
        # custody/approvals_ui.py), so it would be fabricating a link
        # rather than giving a real one. The approval id and `custody
        # approvals list` / `custody ui` pointer in the notification
        # text is what's actually true.
        self.notifier: ApprovalNotifier = notifier or NullNotifier()

    def close(self) -> None:
        """Release the approval broker's SQLite connection. Safe to skip
        in a short-lived script; a long-running gateway process should
        call this (or use the gateway as a context manager) on shutdown.
        """
        self.approvals.close()

    def __enter__(self) -> Gateway:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def authorize(
        self,
        tool: str,
        *,
        datasets: list[str] | None = None,
        egress: bool = False,
        model: str | None = None,
    ) -> AuthzResult:
        """Run a tool call through policy, model routing, and (if the
        policy requires it) a blocking wait on human approval. Every step
        gets its own audit entry, `payload` carrying only references and
        classifications, never dataset content (docs/threat-model.md T6).
        Does not execute anything, see the module docstring for why.
        """
        request = ToolRequest(tool=tool, datasets=datasets or [], egress=egress, model=model)

        self.audit.append(
            EventType.request,
            {
                "tool": tool,
                "datasets": datasets or [],
                "egress": egress,
                "model": model,
            },
        )

        result = self.policy.evaluate(request, self.catalog)
        self.audit.append(
            EventType.decision,
            {
                "tool": tool,
                "decision": result.decision.value,
                "matched_rule_id": result.matched_rule_id,
                "data_class": result.data_class.value,
                "reason": result.reason,
            },
        )

        if model is not None:
            routing = self.router.check(result.data_class, model, self.policy)
            if not routing.allowed:
                self.audit.append(
                    EventType.decision,
                    {
                        "tool": tool,
                        "decision": "deny",
                        "reason": f"model routing: {routing.reason}",
                        "model": model,
                    },
                )
                return AuthzResult(
                    allowed=False,
                    data_class=result.data_class,
                    reason=f"model routing denied: {routing.reason}",
                    policy_result=result,
                )

        if result.decision == Decision.deny:
            return AuthzResult(
                allowed=False,
                data_class=result.data_class,
                reason=result.reason,
                policy_result=result,
            )

        if result.decision == Decision.allow:
            return AuthzResult(
                allowed=True,
                data_class=result.data_class,
                reason=result.reason,
                policy_result=result,
            )

        # require_approval. Rule's own validation guarantees `approvals`
        # is set whenever decision is require_approval (see
        # policy/models.py's _approvals_match_decision), but that
        # guarantee lives in a different module and a bare assert would
        # vanish under python -O, so check it here too rather than trust
        # it silently.
        if result.approvals is None:
            raise RuntimeError(
                f"policy rule {result.matched_rule_id!r} is require_approval with no "
                "approvals block; this should be impossible, Policy validation should "
                "have rejected it at load time"
            )
        approval = self.approvals.request(
            requester=self.principal,
            rule_id=result.matched_rule_id or "(policy default)",
            summary=ApprovalSummary(
                tool=tool,
                datasets=datasets or [],
                data_class=result.data_class.value,
                matched_rule_id=result.matched_rule_id,
            ),
            required_count=result.approvals.count,
            required_roles=result.approvals.roles,
            timeout=self._approval_timeout,
        )
        self.notifier.notify(approval)
        self.audit.append(
            EventType.approval,
            {"tool": tool, "approval_id": approval.id, "status": "requested"},
        )

        status = self.approvals.wait(
            approval.id,
            poll_interval=self._approval_poll_interval,
            sleep=self._approval_sleep,
        )
        self.audit.append(
            EventType.approval,
            {"tool": tool, "approval_id": approval.id, "status": status.value},
        )

        if status != ApprovalStatus.approved:
            return AuthzResult(
                allowed=False,
                data_class=result.data_class,
                reason=f"approval {status.value}",
                policy_result=result,
                approval_id=approval.id,
            )

        return AuthzResult(
            allowed=True,
            data_class=result.data_class,
            reason="approved",
            policy_result=result,
            approval_id=approval.id,
        )
