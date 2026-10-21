"""approvals.status: let the agent see whether its own earlier request
is pending, approved, or denied. Read-only, scoped to an approval id the
agent already holds, so this deliberately does not go through
Gateway.authorize -- there is nothing here for a policy to gate that
isn't already gated by the agent needing to already know the id.
"""

from __future__ import annotations

from custody.approvals import ApprovalNotFoundError
from custody.tools.context import ToolContext
from custody.tools.models import ToolResult


def approvals_status(ctx: ToolContext, approval_id: str) -> ToolResult:
    try:
        approval = ctx.gateway.approvals.get(approval_id)
    except ApprovalNotFoundError:
        return ToolResult(denied=True, reason="no approval with that id")

    return ToolResult(
        denied=False,
        reason="ok",
        data={
            "status": approval.status.value,
            "required_count": approval.required_count,
            "required_roles": approval.required_roles,
        },
    )
