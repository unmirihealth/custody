from __future__ import annotations

import io
import json
from collections.abc import Iterator
from pathlib import Path

import pytest

from custody.gateway import Gateway
from custody.hooks.claude_code import handle_event, main
from custody.mcp_server import ServerPaths, build_gateway


@pytest.fixture
def gateway(tmp_path: Path, fixtures_dir: Path) -> Iterator[Gateway]:
    paths = ServerPaths(
        policy=fixtures_dir / "policy.yaml",
        catalog=fixtures_dir / "catalog.yaml",
        principals=fixtures_dir / "principals.yaml",
        audit_dir=tmp_path / "audit",
        signing_key=tmp_path / "key.pem",
        approvals_db=tmp_path / "approvals.db",
        workspace_dir=tmp_path / "workspace",
    )
    gw = build_gateway(paths, session_id="hook-test", principal="claude-code")
    yield gw
    gw.close()


class TestHandleEvent:
    def test_ungoverned_tool_defers(self, gateway: Gateway) -> None:
        output = handle_event({"tool_name": "Read", "tool_input": {}}, gateway)
        assert output["hookSpecificOutput"]["permissionDecision"] == "defer"

    def test_missing_tool_name_defers(self, gateway: Gateway) -> None:
        output = handle_event({}, gateway)
        assert output["hookSpecificOutput"]["permissionDecision"] == "defer"

    def test_bash_with_no_matching_rule_denies(self, gateway: Gateway) -> None:
        # The shared test fixture policy has no rule for
        # claude_code.bash, so it falls through to the policy default.
        output = handle_event({"tool_name": "Bash", "tool_input": {"command": "ls"}}, gateway)
        assert output["hookSpecificOutput"]["permissionDecision"] == "deny"

    def test_webfetch_sets_egress_and_hits_no_egress_rule(self, gateway: Gateway) -> None:
        output = handle_event(
            {"tool_name": "WebFetch", "tool_input": {"url": "https://example.com"}}, gateway
        )
        assert output["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert "no-egress" in output["hookSpecificOutput"]["permissionDecisionReason"]

    def test_decision_recorded_in_audit_log(self, gateway: Gateway) -> None:
        handle_event({"tool_name": "Bash", "tool_input": {"command": "ls"}}, gateway)
        entries = list(gateway.audit._sink.read_entries())
        assert any(e.payload.get("source") == "claude_code_hook" for e in entries)


class TestHandleEventWithApprovalRule:
    """Uses a policy that actually has a require_approval rule for one
    of the governed tools, to exercise the 'ask' + recorded-approval
    path (the fixture policy used above has no such rule for
    claude_code.*, deliberately, to keep the deny/defer tests simple)."""

    @pytest.fixture
    def approval_gateway(self, tmp_path: Path, fixtures_dir: Path) -> Iterator[Gateway]:
        policy_path = tmp_path / "policy.yaml"
        policy_path.write_text(
            "rules:\n"
            "  - id: bash-needs-approval\n"
            "    when: { tool: claude_code.bash }\n"
            "    decision: require_approval\n"
            "    approvals: { count: 1, roles: [data_steward] }\n"
            "default: deny\n"
        )
        paths = ServerPaths(
            policy=policy_path,
            catalog=fixtures_dir / "catalog.yaml",
            principals=fixtures_dir / "principals.yaml",
            audit_dir=tmp_path / "audit",
            signing_key=tmp_path / "key.pem",
            approvals_db=tmp_path / "approvals.db",
            workspace_dir=tmp_path / "workspace",
        )
        gw = build_gateway(paths, session_id="hook-test", principal="claude-code")
        yield gw
        gw.close()

    def test_require_approval_returns_ask_and_records_a_pending_approval(
        self, approval_gateway: Gateway
    ) -> None:
        output = handle_event(
            {"tool_name": "Bash", "tool_input": {"command": "rm -rf something"}},
            approval_gateway,
        )
        assert output["hookSpecificOutput"]["permissionDecision"] == "ask"
        pending = approval_gateway.approvals.list_pending()
        assert len(pending) == 1
        assert pending[0].requester == "claude_code:Bash"
        assert pending[0].summary.tool == "claude_code.bash"

    def test_recorded_approval_can_be_approved_through_the_normal_broker(
        self, approval_gateway: Gateway
    ) -> None:
        handle_event({"tool_name": "Bash", "tool_input": {"command": "x"}}, approval_gateway)
        pending = approval_gateway.approvals.list_pending()
        result = approval_gateway.approvals.decide(
            pending[0].id, "jane_steward", True, "fine, reviewed"
        )
        assert result.status.value == "approved"


class TestMain:
    def test_main_reads_stdin_writes_stdout(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        tmp_path: Path,
        fixtures_dir: Path,
    ) -> None:
        import shutil

        shutil.copy(fixtures_dir / "policy.yaml", tmp_path / "policy.yaml")
        shutil.copy(fixtures_dir / "catalog.yaml", tmp_path / "catalog.yaml")
        shutil.copy(fixtures_dir / "principals.yaml", tmp_path / "principals.yaml")

        event = {
            "session_id": "s1",
            "cwd": str(tmp_path),
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {},
        }
        monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(event)))
        exit_code = main()
        assert exit_code == 0

        output = json.loads(capsys.readouterr().out)
        assert output["hookSpecificOutput"]["permissionDecision"] == "defer"

    def test_main_handles_malformed_json_gracefully(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setattr("sys.stdin", io.StringIO("not json"))
        exit_code = main()
        assert exit_code == 0
        assert capsys.readouterr().out == ""
