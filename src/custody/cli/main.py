"""`custody` CLI entry point. Registered in pyproject.toml as
`custody = "custody.cli.main:app"`.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import typer

from custody.approvals import ApprovalBroker
from custody.audit import LocalFileSink
from custody.audit import keys as audit_keys
from custody.audit.log import verify_sink
from custody.catalog import Catalog
from custody.mcp_server import ServerPaths, build_server
from custody.policy import PolicyEngine, ToolRequest
from custody.policy import check as policy_check_fn
from custody.policy import explain as policy_explain_fn

app = typer.Typer(
    name="custody",
    help="A governed, auditable agent gateway for oncology data workflows.",
    no_args_is_help=True,
)
policy_app = typer.Typer(help="Policy file operations.", no_args_is_help=True)
approvals_app = typer.Typer(help="Approval broker operations.", no_args_is_help=True)
audit_app = typer.Typer(help="Audit log operations.", no_args_is_help=True)
app.add_typer(policy_app, name="policy")
app.add_typer(approvals_app, name="approvals")
app.add_typer(audit_app, name="audit")

DirOpt = typer.Option(Path("."), "--dir", help="Deployment root (holds .custody/ state).")


_STARTER_CATALOG = """\
# Datasets Custody knows about. An id not listed here classifies as
# "identified", the most restrictive class, when referenced by a tool
# call. See docs/policy-reference.md.
datasets: []
"""

_STARTER_POLICY = """\
# See docs/policy-reference.md. "default: deny" is enforced by Custody
# itself, not just a convention; a non-deny default fails to load.
rules:
  - id: catalog-list-ok
    when: { tool: catalog.list }
    decision: allow
default: deny
model_allowlist: {}
"""

_STARTER_PRINCIPALS = """\
# Approver identities and the roles they hold. An id not listed here
# cannot approve anything (UnauthorizedApproverError), no SSO in v0.1,
# see ROADMAP.md.
principals: []
"""


@app.command()
def init(dir: Path = DirOpt) -> None:
    """Generate the Ed25519 audit-signing key and a starter config."""
    paths = ServerPaths.under(dir)
    starters = {
        paths.catalog: _STARTER_CATALOG,
        paths.policy: _STARTER_POLICY,
        paths.principals: _STARTER_PRINCIPALS,
    }
    for path, content in starters.items():
        if path.exists():
            typer.echo(f"skip  {path} (already exists)")
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        typer.echo(f"wrote {path}")

    if paths.signing_key.exists():
        typer.echo(f"skip  {paths.signing_key} (already exists)")
    else:
        audit_keys.generate_and_save(paths.signing_key)
        typer.echo(f"wrote {paths.signing_key}")

    paths.workspace_dir.mkdir(parents=True, exist_ok=True)
    typer.echo(f"\ncustody is initialized under {dir.resolve()}")
    typer.echo("edit policy.yaml and catalog.yaml, then run: custody demo")


@app.command()
def serve(
    dir: Path = DirOpt,
    session_id: str = typer.Option("default", help="Audit log session id."),
    principal: str = typer.Option(..., help="Identity of the agent/session using this gateway."),
) -> None:
    """Run the MCP gateway (stdio)."""
    paths = ServerPaths.under(dir)
    mcp = build_server(paths, session_id=session_id, principal=principal)
    mcp.run()


@policy_app.command("check")
def policy_check(file: Path) -> None:
    """Lint a policy file. Exits non-zero if it's invalid."""
    errors = policy_check_fn(file)
    if not errors:
        typer.echo(f"{file}: OK")
        return
    for err in errors:
        typer.echo(err, err=True)
    raise typer.Exit(1)


@policy_app.command("explain")
def policy_explain(
    policy_file: Path,
    catalog_file: Path,
    tool: str,
    dataset: list[str] = typer.Option([], help="Repeatable: --dataset a --dataset b"),  # noqa: B008
    egress: bool = False,
    model: str | None = None,
) -> None:
    """Print which rule a hypothetical request would match, and why."""
    engine = PolicyEngine.load(policy_file)
    catalog = Catalog.load(catalog_file)
    request = ToolRequest(tool=tool, datasets=dataset, egress=egress, model=model)
    typer.echo(policy_explain_fn(engine, request, catalog))


@approvals_app.command("list")
def approvals_list(dir: Path = DirOpt) -> None:
    """List pending approvals."""
    paths = ServerPaths.under(dir)
    broker = ApprovalBroker.open(paths.approvals_db, paths.principals)
    try:
        pending = broker.list_pending()
        if not pending:
            typer.echo("no pending approvals")
            return
        for a in pending:
            typer.echo(
                f"{a.id}  tool={a.summary.tool}  data_class={a.summary.data_class}  "
                f"needs={a.required_count} of {a.required_roles}  "
                f"expires={a.expires_at.isoformat()}"
            )
    finally:
        broker.close()


@approvals_app.command("approve")
def approvals_approve(
    approval_id: str,
    as_: str = typer.Option(..., "--as", help="Approver identity."),
    reason: str = typer.Option(...),
    dir: Path = DirOpt,
) -> None:
    """Approve one pending approval."""
    _decide(dir, approval_id, as_, True, reason)


@approvals_app.command("deny")
def approvals_deny(
    approval_id: str,
    as_: str = typer.Option(..., "--as", help="Approver identity."),
    reason: str = typer.Option(...),
    dir: Path = DirOpt,
) -> None:
    """Deny one pending approval."""
    _decide(dir, approval_id, as_, False, reason)


def _decide(dir: Path, approval_id: str, approver: str, approve: bool, reason: str) -> None:
    paths = ServerPaths.under(dir)
    broker = ApprovalBroker.open(paths.approvals_db, paths.principals)
    try:
        result = broker.decide(approval_id, approver, approve, reason)
        typer.echo(f"{approval_id}: {result.status.value}")
    finally:
        broker.close()


@audit_app.command("verify")
def audit_verify(dir: Path = DirOpt) -> None:
    """Recompute the audit chain and check every checkpoint signature."""
    paths = ServerPaths.under(dir)
    sink = LocalFileSink(paths.audit_dir)
    result = verify_sink(sink)
    if result.ok:
        typer.echo(
            f"OK: {result.entries_checked} entries, {result.checkpoints_checked} "
            "checkpoints verified"
        )
        return
    typer.echo(f"BROKEN at seq {result.first_broken_seq}: {result.reason}", err=True)
    raise typer.Exit(1)


@audit_app.command("export")
def audit_export(
    dest: Path,
    fmt: str = typer.Option("jsonl", help="jsonl or csv"),
    since: str | None = typer.Option(None, help="ISO 8601 timestamp."),
    dir: Path = DirOpt,
) -> None:
    """Export audit entries for compliance review or SIEM ingestion."""
    paths = ServerPaths.under(dir)
    sink = LocalFileSink(paths.audit_dir)
    since_dt = datetime.fromisoformat(since) if since else None
    entries = [e for e in sink.read_entries() if since_dt is None or e.timestamp >= since_dt]

    if fmt == "jsonl":
        with dest.open("w", encoding="utf-8") as f:
            for e in entries:
                f.write(e.model_dump_json())
                f.write("\n")
    elif fmt == "csv":
        import csv

        with dest.open("w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(
                ["seq", "timestamp", "session_id", "principal", "event_type", "payload"]
            )
            for e in entries:
                writer.writerow(
                    [
                        e.seq,
                        e.timestamp.isoformat(),
                        e.session_id,
                        e.principal,
                        e.event_type.value,
                        json.dumps(e.payload, sort_keys=True),
                    ]
                )
    else:
        typer.echo(f"unsupported format: {fmt!r} (use jsonl or csv)", err=True)
        raise typer.Exit(1)

    typer.echo(f"wrote {len(entries)} entries to {dest}")


@audit_app.command("tail")
def audit_tail(n: int = 20, dir: Path = DirOpt) -> None:
    """Print the last N audit entries."""
    paths = ServerPaths.under(dir)
    sink = LocalFileSink(paths.audit_dir)
    entries = list(sink.read_entries())
    for e in entries[-n:]:
        typer.echo(
            f"[{e.seq}] {e.timestamp.isoformat()} {e.event_type.value:<10} "
            f"{e.principal}: {json.dumps(e.payload, sort_keys=True)}"
        )


@app.command()
def demo(dir: Path = typer.Option(Path("./demo"), "--dir")) -> None:  # noqa: B008
    """Generate the synthetic dataset and run the scripted end-to-end
    scenario. See docs/demo.md."""
    from custody.demo import run_demo

    run_demo(dir)


@app.command()
def ui(
    dir: Path = DirOpt,
    port: int = 8765,
) -> None:
    """Run the local approvals web UI (127.0.0.1 only)."""
    import uvicorn

    from custody.approvals_ui import build_app

    paths = ServerPaths.under(dir)
    fastapi_app, token = build_app(paths)
    typer.echo(f"approvals UI: http://127.0.0.1:{port}/?token={token}")
    uvicorn.run(fastapi_app, host="127.0.0.1", port=port, log_level="warning")


if __name__ == "__main__":
    app()
