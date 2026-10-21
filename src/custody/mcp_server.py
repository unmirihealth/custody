"""Wires the six built-in tools to a real MCP server (mcp>=2.3, the v2
API: `from mcp.server import MCPServer`, `@mcp.tool()`). `custody serve`
is the thin CLI entry point around `build_server()` below.

Scope note: this builds a server that exposes Custody's own six tools.
Proxying tools from a downstream MCP server (the README's architecture
diagram mentions this as part of the gateway's role) is NOT implemented
in v0.1, every tool call in this release goes through one of the six
built-ins. Treat "proxied downstream MCP server" in README.md as the
target architecture, not current behavior, until ROADMAP.md says
otherwise.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from mcp.server import MCPServer

from custody.approvals import ApprovalBroker, WebhookNotifier
from custody.audit import AuditLog, LocalFileSink
from custody.audit import keys as audit_keys
from custody.catalog import Catalog
from custody.gateway import Gateway
from custody.guard import OutputGuard
from custody.policy import PolicyEngine
from custody.sandbox import SandboxConfig, SandboxExecutor
from custody.tools import (
    ToolContext,
    approvals_status,
    catalog_list,
    files_export,
    files_write,
    shell_run,
    sql_query,
)


@dataclass
class ServerPaths:
    """Every file and directory a Custody deployment needs. `custody
    init` creates a starter layout that matches these defaults."""

    policy: Path
    catalog: Path
    principals: Path
    audit_dir: Path
    signing_key: Path
    approvals_db: Path
    workspace_dir: Path

    @classmethod
    def under(cls, root: Path) -> ServerPaths:
        """The conventional layout: visible config at `root` (policy.yaml,
        catalog.yaml, principals.yaml, meant to be read and edited by a
        compliance reviewer), runtime state under `root/.custody/` (the
        signing key, the audit log, the approvals database, the session
        workspace -- not meant to be hand-edited)."""
        state = root / ".custody"
        return cls(
            policy=root / "policy.yaml",
            catalog=root / "catalog.yaml",
            principals=root / "principals.yaml",
            audit_dir=state / "audit",
            signing_key=state / "signing_key.pem",
            approvals_db=state / "approvals.db",
            workspace_dir=state / "workspace",
        )


def _open_audit_log(paths: ServerPaths, session_id: str, principal: str) -> AuditLog:
    if paths.signing_key.exists():
        signing_key = audit_keys.load(paths.signing_key)
    else:
        signing_key = audit_keys.generate_and_save(paths.signing_key)
    return AuditLog(
        LocalFileSink(paths.audit_dir),
        signing_key,
        session_id=session_id,
        principal=principal,
    )


def build_gateway(
    paths: ServerPaths,
    *,
    session_id: str,
    principal: str,
    webhook_url: str | None = None,
) -> Gateway:
    """`webhook_url`, when given, wires a WebhookNotifier so a new
    pending approval posts a Slack-compatible notification. Also read
    from the CUSTODY_WEBHOOK_URL environment variable by the CLI (see
    custody/cli/main.py); passing it explicitly here always wins.
    """
    catalog = Catalog.load(paths.catalog)
    policy = PolicyEngine.load(paths.policy)
    audit = _open_audit_log(paths, session_id, principal)
    approvals = ApprovalBroker.open(paths.approvals_db, paths.principals)
    notifier = WebhookNotifier(webhook_url) if webhook_url else None
    return Gateway(
        policy=policy,
        catalog=catalog,
        audit=audit,
        approvals=approvals,
        session_id=session_id,
        notifier=notifier,
        principal=principal,
    )


def build_server(
    paths: ServerPaths,
    *,
    session_id: str,
    principal: str,
    sandbox_config: SandboxConfig | None = None,
    webhook_url: str | None = None,
) -> MCPServer:
    """Construct a ready-to-run MCPServer exposing Custody's six tools.
    Call `.run()` (stdio) or `.run_streamable_http_async(...)` on the
    result; see docs/integrations/claude-code.md for the config snippet
    that points a Claude Code session at this.
    """
    gateway = build_gateway(
        paths, session_id=session_id, principal=principal, webhook_url=webhook_url
    )
    sandbox = SandboxExecutor(sandbox_config or SandboxConfig())
    ctx = ToolContext(
        gateway=gateway,
        sandbox=sandbox,
        catalog=gateway.catalog,
        guard=OutputGuard(),
        workspace_dir=paths.workspace_dir,
    )

    mcp = MCPServer(
        "Custody",
        instructions=(
            "A governed, auditable gateway for oncology data workflows. Every "
            "tool call here is policy-checked; an identified-data request may "
            "be held for human approval before it returns."
        ),
    )

    @mcp.tool(name="catalog.list", description="List datasets and their data classes.")
    def _catalog_list() -> dict[str, object]:
        return catalog_list(ctx).model_dump()

    @mcp.tool(
        name="sql.query",
        description=(
            "Run a read-only SQL query (SELECT/WITH only) over one catalog "
            "dataset, inside the sandbox."
        ),
    )
    def _sql_query(dataset_id: str, query: str) -> dict[str, object]:
        return sql_query(ctx, dataset_id, query).model_dump()

    @mcp.tool(name="shell.run", description="Run a command in the sandbox.")
    def _shell_run(
        command: list[str], datasets: list[str] | None = None, egress: bool = False
    ) -> dict[str, object]:
        return shell_run(ctx, command, datasets, egress=egress).model_dump()

    @mcp.tool(name="files.write", description="Write a file to the session workspace.")
    def _files_write(path: str, content: str) -> dict[str, object]:
        return files_write(ctx, path, content).model_dump()

    @mcp.tool(
        name="files.export",
        description="Copy a workspace artifact out to a destination path (policy-gated).",
    )
    def _files_export(path: str, destination: str) -> dict[str, object]:
        return files_export(ctx, path, Path(destination)).model_dump()

    @mcp.tool(
        name="approvals.status",
        description=(
            "Check whether a previously-requested approval is pending, approved, or denied."
        ),
    )
    def _approvals_status(approval_id: str) -> dict[str, object]:
        return approvals_status(ctx, approval_id).model_dump()

    return mcp
