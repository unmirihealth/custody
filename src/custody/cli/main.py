"""`custody` CLI entry point. Registered in pyproject.toml as
`custody = "custody.cli.main:app"`.
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path

import typer

from custody.approvals import ApprovalBroker
from custody.audit import LocalFileSink
from custody.audit import keys as audit_keys
from custody.audit.log import verify_sink
from custody.catalog import Catalog
from custody.evidence import write_evidence_pack
from custody.mcp_server import ServerPaths, build_server
from custody.policy import PolicyBundleError, PolicyEngine, SignedPolicyBundle, ToolRequest
from custody.policy import bundle_path_for as policy_bundle_path_for
from custody.policy import check as policy_check_fn
from custody.policy import explain as policy_explain_fn
from custody.policy import sign_policy as policy_sign_fn
from custody.policy import verify_policy_bundle as policy_verify_bundle_fn

app = typer.Typer(
    name="custody",
    help="A governed, auditable agent gateway for oncology data workflows.",
    no_args_is_help=True,
)
policy_app = typer.Typer(help="Policy file operations.", no_args_is_help=True)
approvals_app = typer.Typer(help="Approval broker operations.", no_args_is_help=True)
audit_app = typer.Typer(help="Audit log operations.", no_args_is_help=True)
evidence_app = typer.Typer(help="Evidence-pack export.", no_args_is_help=True)
app.add_typer(policy_app, name="policy")
app.add_typer(approvals_app, name="approvals")
app.add_typer(audit_app, name="audit")
app.add_typer(evidence_app, name="evidence")

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
# cannot approve anything (UnauthorizedApproverError). `custody
# approvals approve/deny --as-token <jwt>` can verify an approver's
# identity against a real OIDC provider instead of trusting a bare
# --as string (see docs/sso-oidc.md); this file is still the one
# source of truth for which roles any given principal id holds either
# way.
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
    transport: str = typer.Option(
        "stdio", help="stdio (default, for a local agent) or streamable-http (for a server)."
    ),
    host: str = typer.Option("127.0.0.1", help="Bind host, streamable-http only."),
    port: int = typer.Option(8080, help="Bind port, streamable-http only."),
) -> None:
    """Run the MCP gateway. Reads CUSTODY_WEBHOOK_URL from the
    environment, if set, to notify a Slack-compatible webhook on every
    new pending approval.

    `--transport streamable-http --host 0.0.0.0` is the mode a
    Kubernetes Deployment uses (see k8s/ and docs/kubernetes.md): a
    long-running HTTP server a Service/Ingress can route to, as
    opposed to the default stdio mode, which only makes sense for a
    locally-spawned agent session.
    """
    paths = ServerPaths.under(dir)
    webhook_url = os.environ.get("CUSTODY_WEBHOOK_URL")
    mcp = build_server(paths, session_id=session_id, principal=principal, webhook_url=webhook_url)
    if transport == "stdio":
        mcp.run()
    elif transport == "streamable-http":
        mcp.run(transport="streamable-http", host=host, port=port)
    else:
        typer.echo(f"unsupported transport: {transport!r} (use stdio or streamable-http)", err=True)
        raise typer.Exit(1)


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


@policy_app.command("sign")
def policy_sign(
    file: Path,
    key: Path = typer.Option(  # noqa: B008
        ..., help="Ed25519 private key PEM (e.g. .custody/signing_key.pem)."
    ),
    out: Path | None = typer.Option(  # noqa: B008
        None, help="Bundle output path. Defaults to <file>.sig.json."
    ),
) -> None:
    """Sign a policy file, producing a bundle a reviewer can later check
    with `custody policy verify`. Does not validate the policy's own
    contents, run `custody policy check` first."""
    signing_key = audit_keys.load(key)
    bundle = policy_sign_fn(file, signing_key)
    dest = out or policy_bundle_path_for(file)
    dest.write_text(bundle.model_dump_json(indent=2) + "\n")
    typer.echo(f"wrote {dest}")
    typer.echo(f"policy sha256: {bundle.policy_sha256}")
    typer.echo(f"signed by public key: {bundle.public_key}")


@policy_app.command("verify")
def policy_verify(
    file: Path,
    bundle: Path | None = typer.Option(  # noqa: B008
        None, help="Bundle path. Defaults to <file>.sig.json."
    ),
) -> None:
    """Check that a policy file matches a previously signed bundle and
    the signature verifies. Exits non-zero (and prints why) if not."""
    bundle_path = bundle or policy_bundle_path_for(file)
    if not bundle_path.exists():
        typer.echo(f"no signed bundle at {bundle_path}", err=True)
        raise typer.Exit(1)
    loaded = SignedPolicyBundle.model_validate_json(bundle_path.read_text())
    try:
        policy_verify_bundle_fn(file, loaded)
    except PolicyBundleError as exc:
        typer.echo(f"INVALID: {exc.reason}", err=True)
        raise typer.Exit(1) from exc
    typer.echo(
        f"OK: {file} matches the bundle signed {loaded.signed_at.isoformat()} "
        f"by public key {loaded.public_key}"
    )


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


_AS_IDENTITY_JWT_HELP = (
    "Approver identity as a signed OIDC ID token instead of a bare string "
    "(docs/sso-oidc.md); requires CUSTODY_OIDC_ISSUER and CUSTODY_OIDC_JWKS_URL "
    "in the environment. Mutually exclusive with --as."
)


@approvals_app.command("approve")
def approvals_approve(
    approval_id: str,
    as_: str | None = typer.Option(None, "--as", help="Approver identity."),
    as_token: str | None = typer.Option(None, "--as-token", help=_AS_IDENTITY_JWT_HELP),
    reason: str = typer.Option(...),
    dir: Path = DirOpt,
) -> None:
    """Approve one pending approval."""
    _decide(dir, approval_id, _resolve_approver(as_, as_token), True, reason)


@approvals_app.command("deny")
def approvals_deny(
    approval_id: str,
    as_: str | None = typer.Option(None, "--as", help="Approver identity."),
    as_token: str | None = typer.Option(None, "--as-token", help=_AS_IDENTITY_JWT_HELP),
    reason: str = typer.Option(...),
    dir: Path = DirOpt,
) -> None:
    """Deny one pending approval."""
    _decide(dir, approval_id, _resolve_approver(as_, as_token), False, reason)


def _resolve_approver(as_: str | None, as_token: str | None) -> str:
    """Exactly one of --as / --as-token must be given. --as-token is
    verified against an OIDC provider configured via CUSTODY_OIDC_ISSUER
    / CUSTODY_OIDC_JWKS_URL (optionally CUSTODY_OIDC_AUDIENCE,
    CUSTODY_OIDC_SUBJECT_CLAIM, default "sub"); see docs/sso-oidc.md for
    exactly what this does and does not verify."""
    if (as_ is None) == (as_token is None):
        typer.echo("exactly one of --as or --as-token is required", err=True)
        raise typer.Exit(1)
    if as_ is not None:
        return as_

    from custody.approvals.oidc import OidcVerificationError, OidcVerifier

    issuer = os.environ.get("CUSTODY_OIDC_ISSUER")
    jwks_url = os.environ.get("CUSTODY_OIDC_JWKS_URL")
    if not issuer or not jwks_url:
        typer.echo(
            "--as-token requires CUSTODY_OIDC_ISSUER and CUSTODY_OIDC_JWKS_URL "
            "in the environment",
            err=True,
        )
        raise typer.Exit(1)
    verifier = OidcVerifier(
        issuer=issuer,
        jwks_url=jwks_url,
        audience=os.environ.get("CUSTODY_OIDC_AUDIENCE"),
        subject_claim=os.environ.get("CUSTODY_OIDC_SUBJECT_CLAIM", "sub"),
    )
    if as_token is None:
        # Unreachable given the exactly-one check above; narrows the
        # type for the call below without an `assert` in library code.
        raise typer.Exit(1)
    try:
        return verifier.verify(as_token)
    except OidcVerificationError as exc:
        typer.echo(f"token verification failed: {exc.reason}", err=True)
        raise typer.Exit(1) from exc


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


@evidence_app.command("export")
def evidence_export(
    dest: Path,
    dir: Path = DirOpt,
    since: str | None = typer.Option(None, help="ISO 8601 timestamp."),
    until: str | None = typer.Option(None, help="ISO 8601 timestamp."),
) -> None:
    """Export an evidence pack (manifest, README, audit export, policy +
    bundle if present) to DEST, a new or empty directory. See
    docs/evidence-pack.md -- this is a mechanical export, not a
    certification."""
    paths = ServerPaths.under(dir)
    sink = LocalFileSink(paths.audit_dir)
    since_dt = datetime.fromisoformat(since) if since else None
    until_dt = datetime.fromisoformat(until) if until else None
    try:
        manifest = write_evidence_pack(
            dest,
            sink,
            policy_path=paths.policy if paths.policy.exists() else None,
            since=since_dt,
            until=until_dt,
        )
    except FileExistsError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(1) from exc
    typer.echo(f"wrote evidence pack to {dest}")
    typer.echo(
        f"{manifest.entries_in_window} entries, audit integrity: "
        f"{'OK' if manifest.audit_integrity.ok else 'BROKEN'}"
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
