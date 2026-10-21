"""The local approvals web UI: a minimal server-rendered HTML page (no
JS framework, per the project brief), bound to 127.0.0.1 only, gated by
a startup token generated fresh each run. `custody ui` is the CLI entry
point.
"""

from __future__ import annotations

import html
import secrets

from fastapi import FastAPI, Form, HTTPException, Query
from fastapi.responses import HTMLResponse, RedirectResponse

from custody.approvals import (
    ApprovalAlreadyResolvedError,
    ApprovalBroker,
    ApprovalExpiredError,
    ApprovalNotFoundError,
    DuplicateApproverError,
    PendingApproval,
    SelfApprovalError,
    UnauthorizedApproverError,
)
from custody.mcp_server import ServerPaths

_DECIDE_ERRORS = (
    ApprovalNotFoundError,
    ApprovalAlreadyResolvedError,
    ApprovalExpiredError,
    SelfApprovalError,
    UnauthorizedApproverError,
    DuplicateApproverError,
)


def _row_html(a: PendingApproval, token: str) -> str:
    datasets = ", ".join(html.escape(d) for d in a.summary.datasets) or "(none)"
    return f"""
    <tr>
      <td><code>{html.escape(a.id)}</code></td>
      <td>{html.escape(a.summary.tool)}</td>
      <td>{datasets}</td>
      <td>{html.escape(a.summary.data_class)}</td>
      <td>{html.escape(a.rule_id)}</td>
      <td>{a.required_count} of {html.escape(str(a.required_roles))}</td>
      <td>{html.escape(a.expires_at.isoformat())}</td>
      <td>
        <form method="post" action="/approvals/{html.escape(a.id)}/decide" style="display:inline">
          <input type="hidden" name="token" value="{html.escape(token)}">
          <input type="text" name="approver" placeholder="your id" required size="12">
          <input type="text" name="reason" placeholder="reason" required size="20">
          <button name="decision" value="approve">Approve</button>
          <button name="decision" value="deny">Deny</button>
        </form>
      </td>
    </tr>"""


def _page(rows_html: str) -> str:
    body = rows_html or '<tr><td colspan="8">no pending approvals</td></tr>'
    return f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Custody Approvals</title>
  <style>
    body {{ font-family: -apple-system, sans-serif; margin: 2rem; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #ccc; padding: 0.4rem 0.6rem; text-align: left; }}
    th, td {{ font-size: 0.9rem; }}
    th {{ background: #f0f0f0; }}
    button {{ cursor: pointer; }}
  </style>
</head>
<body>
  <h1>Pending approvals</h1>
  <table>
    <tr>
      <th>id</th><th>tool</th><th>datasets</th><th>data class</th><th>rule</th>
      <th>needs</th><th>expires</th><th>decide</th>
    </tr>
    {body}
  </table>
</body>
</html>"""


def build_app(paths: ServerPaths) -> tuple[FastAPI, str]:
    """Returns (app, token). The token is generated fresh for this
    process and must be passed as `?token=...` on every request; there
    is no other authentication in v0.1 (no SSO, see ROADMAP.md), which
    is exactly why this only binds to 127.0.0.1."""
    token = secrets.token_urlsafe(24)
    broker = ApprovalBroker.open(paths.approvals_db, paths.principals)
    app = FastAPI(title="Custody Approvals")

    def _check_token(t: str | None) -> None:
        if t is None or not secrets.compare_digest(t, token):
            raise HTTPException(403, "invalid or missing token")

    @app.get("/", response_class=HTMLResponse)
    def index(token_q: str | None = Query(default=None, alias="token")) -> str:
        _check_token(token_q)
        rows = "".join(_row_html(a, token) for a in broker.list_pending())
        return _page(rows)

    @app.post("/approvals/{approval_id}/decide", response_model=None)
    def decide(
        approval_id: str,
        token_f: str = Form(alias="token"),
        approver: str = Form(),
        reason: str = Form(),
        decision: str = Form(),
    ) -> HTMLResponse | RedirectResponse:
        _check_token(token_f)
        try:
            broker.decide(approval_id, approver, decision == "approve", reason)
        except _DECIDE_ERRORS as exc:
            back = f"/?token={token_f}"
            return HTMLResponse(
                f"<p>Error: {html.escape(str(exc))}</p><a href='{back}'>back</a>",
                status_code=400,
            )
        return RedirectResponse(f"/?token={token_f}", status_code=303)

    return app, token
