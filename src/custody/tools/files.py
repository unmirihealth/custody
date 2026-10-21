"""files.write and files.export: the session workspace, and the one
policy-gated way anything leaves it.
"""

from __future__ import annotations

import shutil
from hashlib import sha256
from pathlib import Path

from custody.audit import EventType
from custody.tools.context import ToolContext
from custody.tools.models import ToolResult


def _resolve_in_workspace(workspace_dir: Path, relative_path: str) -> Path | None:
    """Resolves `relative_path` against `workspace_dir` and returns None
    if the result would land outside it (a `../../etc/passwd` style
    escape), rather than letting Path.resolve() silently follow it."""
    target = (workspace_dir / relative_path).resolve()
    workspace_resolved = workspace_dir.resolve()
    if target != workspace_resolved and workspace_resolved not in target.parents:
        return None
    return target


def files_write(ctx: ToolContext, relative_path: str, content: str) -> ToolResult:
    authz = ctx.gateway.authorize("files.write")
    if not authz.allowed:
        return ToolResult(denied=True, reason=authz.reason)

    target = _resolve_in_workspace(ctx.workspace_dir, relative_path)
    if target is None:
        return ToolResult(denied=True, reason="path escapes the session workspace")

    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content)

    content_bytes = content.encode("utf-8")
    ctx.gateway.audit.append(
        EventType.result,
        {
            "tool": "files.write",
            "path": relative_path,
            "bytes": len(content_bytes),
            "content_sha256": sha256(content_bytes).hexdigest(),
        },
    )
    return ToolResult(denied=False, reason="written", data={"path": str(target)})


def files_export(ctx: ToolContext, relative_path: str, destination: Path) -> ToolResult:
    """Always policy-gated (per the brief): a policy with no rule for
    files.export denies by default, same as any other tool with no
    matching rule."""
    authz = ctx.gateway.authorize("files.export")
    if not authz.allowed:
        return ToolResult(denied=True, reason=authz.reason)

    source = _resolve_in_workspace(ctx.workspace_dir, relative_path)
    if source is None or not source.is_file():
        return ToolResult(denied=True, reason="source file not found in the workspace")

    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)

    content_bytes = source.read_bytes()
    ctx.gateway.audit.append(
        EventType.result,
        {
            "tool": "files.export",
            "path": relative_path,
            "destination": str(destination),
            "bytes": len(content_bytes),
            "content_sha256": sha256(content_bytes).hexdigest(),
        },
    )
    return ToolResult(denied=False, reason="exported", data={"destination": str(destination)})
