"""Claude Code `PreToolUse` hook adapter (the secondary integration
mode from README.md). Reads a hook event on stdin, runs it through
Custody's policy engine, and writes a `hookSpecificOutput` decision on
stdout. See docs/integrations/claude-code.md for the settings.json
registration and the exact JSON shapes this reads and writes.

Design note on `require_approval`: a PreToolUse hook has roughly a
30-second execution budget, far shorter than Custody's own default
15-minute approval timeout, so this does NOT call the blocking
`ApprovalBroker.wait()` the way `Gateway.authorize()` does for an MCP
tool call. Instead it creates the pending approval record (so it shows
up in `custody approvals list` / `custody ui` and is on the record for
compliance review) and returns Claude Code's own `"ask"` decision,
handing the immediate interactive moment to Claude Code's permission
prompt, since the developer is presumably sitting right there. `allow`
and `deny` map directly.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

from custody.approvals import ApprovalSummary
from custody.audit import EventType
from custody.gateway import Gateway
from custody.mcp_server import ServerPaths, build_gateway
from custody.policy import Decision, ToolRequest

#: Claude Code tool name -> the policy `tool` identifier Custody checks
#: it against. Namespaced (claude_code.*) so a policy author can write
#: rules for "a raw Bash command from Claude Code" distinctly from
#: Custody's own MCP tools (shell.run etc.), which carry a different
#: risk shape (an MCP tool call already went through sql.query's
#: read-only validation or files.export's gating; a raw Bash command
#: has none of that built in).
_GOVERNED_TOOLS: dict[str, str] = {
    "Bash": "claude_code.bash",
    "Write": "claude_code.write",
    "Edit": "claude_code.edit",
    "WebFetch": "claude_code.web_fetch",
}

_SESSION_PRINCIPAL_ENV = "CUSTODY_PRINCIPAL"
_DEPLOYMENT_DIR_ENV = "CUSTODY_DIR"


def _hook_output(decision: str, reason: str) -> dict[str, Any]:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    }


def handle_event(event: dict[str, Any], gateway: Gateway) -> dict[str, Any]:
    """Pure decision logic, no stdin/stdout/process exit: given a parsed
    hook event and an already-built Gateway, returns the JSON object to
    print. Separated from main() so this is testable without going
    through a subprocess.
    """
    tool_name = event.get("tool_name")
    if not isinstance(tool_name, str) or tool_name not in _GOVERNED_TOOLS:
        # Not one of the four tools this adapter governs: defer to
        # Claude Code's normal permission flow rather than claiming an
        # opinion Custody doesn't actually have.
        return _hook_output("defer", "not a Custody-governed tool")

    policy_tool = _GOVERNED_TOOLS[tool_name]
    # tool_input (the command, file path, or URL) isn't inspected in
    # v0.1: policy decisions here are by tool name and egress only, the
    # same "deliberately blunt" posture as sql.query's allow-list
    # (custody/tools/sql.py), not a parser for Bash commands or paths.
    egress = tool_name == "WebFetch"

    request = ToolRequest(tool=policy_tool, egress=egress)
    gateway.audit.append(
        EventType.request,
        {"source": "claude_code_hook", "tool": policy_tool, "egress": egress},
    )
    result = gateway.policy.evaluate(request, gateway.catalog)
    gateway.audit.append(
        EventType.decision,
        {
            "source": "claude_code_hook",
            "tool": policy_tool,
            "decision": result.decision.value,
            "matched_rule_id": result.matched_rule_id,
            "reason": result.reason,
        },
    )

    if result.decision == Decision.deny:
        return _hook_output("deny", f"Custody policy denied this: {result.reason}")

    if result.decision == Decision.allow:
        return _hook_output("allow", f"Custody policy allowed this: {result.reason}")

    # require_approval: record it, hand the interactive moment to
    # Claude Code's own prompt (see module docstring).
    if result.approvals is None:
        # Policy validation guarantees this can't happen (see
        # gateway.py's identical check and comment), checked again here
        # rather than trusted silently.
        raise RuntimeError(
            f"policy rule {result.matched_rule_id!r} is require_approval with no "
            "approvals block; this should be impossible"
        )
    approval = gateway.approvals.request(
        requester=f"claude_code:{tool_name}",
        rule_id=result.matched_rule_id or "(policy default)",
        summary=ApprovalSummary(tool=policy_tool, data_class=result.data_class.value),
        required_count=result.approvals.count,
        required_roles=result.approvals.roles,
    )
    reason = (
        f"Custody policy requires approval ({result.reason}). Recorded as "
        f"{approval.id}; review with `custody approvals list` or `custody ui`."
    )
    return _hook_output("ask", reason)


def _build_gateway_for_event(event: dict[str, Any]) -> Gateway:
    deployment_dir = Path(os.environ.get(_DEPLOYMENT_DIR_ENV) or event.get("cwd") or ".")
    paths = ServerPaths.under(deployment_dir)
    principal = os.environ.get(_SESSION_PRINCIPAL_ENV) or event.get("session_id") or "claude-code"
    session_id = str(event.get("session_id") or "claude-code-session")
    return build_gateway(paths, session_id=session_id, principal=principal)


def main() -> int:
    try:
        event = json.load(sys.stdin)
    except json.JSONDecodeError:
        # Malformed input: exit 0 with no JSON is a non-blocking error,
        # Claude Code's normal permission flow takes over. A hook that
        # cannot even parse its own input should not pretend to have an
        # opinion about the tool call.
        return 0

    gateway = _build_gateway_for_event(event)
    try:
        output = handle_event(event, gateway)
    finally:
        gateway.close()

    print(json.dumps(output))
    return 0


if __name__ == "__main__":
    sys.exit(main())
