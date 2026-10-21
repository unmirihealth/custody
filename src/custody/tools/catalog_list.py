"""catalog.list: list datasets and their data classes. Metadata only,
never dataset content, so this is about as low-risk as a tool call gets,
it still goes through `Gateway.authorize` like everything else: policy
is the one place that decides what's low-risk, not this module.
"""

from __future__ import annotations

from custody.audit import EventType
from custody.tools.context import ToolContext
from custody.tools.models import ToolResult


def catalog_list(ctx: ToolContext) -> ToolResult:
    authz = ctx.gateway.authorize("catalog.list")
    if not authz.allowed:
        return ToolResult(denied=True, reason=authz.reason)

    entries = [
        {"id": e.id, "data_class": e.data_class.value, "format": e.format.value}
        for e in ctx.catalog.list()
    ]
    ctx.gateway.audit.append(
        EventType.result, {"tool": "catalog.list", "dataset_count": len(entries)}
    )
    return ToolResult(denied=False, reason=authz.reason, data=entries)
