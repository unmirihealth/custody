"""Approval broker.

Pending approvals live in SQLite: a request summary (never raw PHI, see
docs/threat-model.md T6), the requesting principal, the roles and count a
rule requires, and an expiry. A decision requires an approver identity and
a free-text reason; the approver must differ from the requester, and a
two-person rule rejects a second decision from an approver who already
decided on that same request. An expired request resolves to deny, the
same as every other ambiguous path.

Three channels reach the same broker: the CLI (`custody approvals
list|approve|deny`), a local web UI bound to 127.0.0.1 with a startup
token, and an optional webhook notifier that sends a link, never request
content, to something like Slack.

Planned surface:
    class PendingApproval(BaseModel): ...
    class ApprovalBroker:
        def request(self, rule: Rule, summary: ApprovalSummary) -> PendingApproval: ...
        def decide(
            self, approval_id: str, approver: str,
            decision: Decision, reason: str,
        ) -> None: ...
        def wait(self, approval_id: str, timeout: timedelta) -> Decision: ...  # timeout -> deny
        def list_pending(self) -> list[PendingApproval]: ...

Not yet implemented.
"""

raise NotImplementedError("custody.approvals is not yet implemented (v0.1 skeleton)")
