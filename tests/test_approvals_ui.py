from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from custody.approvals import ApprovalBroker, ApprovalSummary
from custody.approvals_ui import build_app
from custody.mcp_server import ServerPaths


@pytest.fixture
def paths(tmp_path: Path, fixtures_dir: Path) -> ServerPaths:
    state = ServerPaths.under(tmp_path)
    return ServerPaths(
        policy=fixtures_dir / "policy.yaml",
        catalog=fixtures_dir / "catalog.yaml",
        principals=fixtures_dir / "principals.yaml",
        audit_dir=state.audit_dir,
        signing_key=state.signing_key,
        approvals_db=state.approvals_db,
        workspace_dir=state.workspace_dir,
    )


@pytest.fixture
def client_and_token(paths: ServerPaths) -> tuple[TestClient, str]:
    app, token = build_app(paths)
    return TestClient(app), token


class TestAuth:
    def test_no_token_rejected(self, client_and_token: tuple[TestClient, str]) -> None:
        client, _ = client_and_token
        resp = client.get("/")
        assert resp.status_code == 403

    def test_wrong_token_rejected(self, client_and_token: tuple[TestClient, str]) -> None:
        client, _ = client_and_token
        resp = client.get("/?token=wrong")
        assert resp.status_code == 403

    def test_correct_token_accepted(self, client_and_token: tuple[TestClient, str]) -> None:
        client, token = client_and_token
        resp = client.get(f"/?token={token}")
        assert resp.status_code == 200
        assert "Pending approvals" in resp.text


class TestDecide:
    def test_empty_queue_shows_no_pending(self, client_and_token: tuple[TestClient, str]) -> None:
        client, token = client_and_token
        resp = client.get(f"/?token={token}")
        assert "no pending approvals" in resp.text

    def test_pending_approval_shows_in_list(self, paths: ServerPaths) -> None:
        broker = ApprovalBroker.open(paths.approvals_db, paths.principals)
        approval = broker.request(
            requester="agent_session",
            rule_id="identified-needs-approval",
            summary=ApprovalSummary(tool="sql.query", data_class="identified"),
            required_count=1,
            required_roles=["data_steward"],
        )
        broker.close()

        app, token = build_app(paths)
        client = TestClient(app)
        resp = client.get(f"/?token={token}")
        assert approval.id in resp.text
        assert "sql.query" in resp.text

    def test_approve_via_form_post(self, paths: ServerPaths) -> None:
        broker = ApprovalBroker.open(paths.approvals_db, paths.principals)
        approval = broker.request(
            requester="agent_session",
            rule_id="identified-needs-approval",
            summary=ApprovalSummary(tool="sql.query", data_class="identified"),
            required_count=1,
            required_roles=["data_steward"],
        )

        app, token = build_app(paths)
        client = TestClient(app)
        resp = client.post(
            f"/approvals/{approval.id}/decide",
            data={
                "token": token,
                "approver": "jane_steward",
                "reason": "looks fine",
                "decision": "approve",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 303

        refreshed = broker.get(approval.id)
        assert refreshed.status.value == "approved"
        broker.close()

    def test_decide_without_token_rejected(self, paths: ServerPaths) -> None:
        broker = ApprovalBroker.open(paths.approvals_db, paths.principals)
        approval = broker.request(
            requester="agent_session",
            rule_id="r1",
            summary=ApprovalSummary(tool="sql.query", data_class="identified"),
            required_count=1,
            required_roles=["data_steward"],
        )
        broker.close()

        app, _token = build_app(paths)
        client = TestClient(app)
        resp = client.post(
            f"/approvals/{approval.id}/decide",
            data={
                "token": "wrong",
                "approver": "jane_steward",
                "reason": "x",
                "decision": "approve",
            },
        )
        assert resp.status_code == 403

    def test_self_approval_shows_error_page(self, paths: ServerPaths) -> None:
        broker = ApprovalBroker.open(paths.approvals_db, paths.principals)
        approval = broker.request(
            requester="jane_steward",
            rule_id="r1",
            summary=ApprovalSummary(tool="sql.query", data_class="identified"),
            required_count=1,
            required_roles=["data_steward"],
        )
        broker.close()

        app, token = build_app(paths)
        client = TestClient(app)
        resp = client.post(
            f"/approvals/{approval.id}/decide",
            data={
                "token": token,
                "approver": "jane_steward",
                "reason": "self-approving",
                "decision": "approve",
            },
        )
        assert resp.status_code == 400
        assert "Error" in resp.text
