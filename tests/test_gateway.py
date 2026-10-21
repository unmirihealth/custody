from __future__ import annotations

from collections.abc import Callable, Iterator
from datetime import timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from custody.approvals import ApprovalBroker, ApprovalStore, PrincipalDirectory
from custody.audit import AuditLog, EventType, LocalFileSink
from custody.catalog import Catalog, DataClass
from custody.gateway import Gateway
from custody.policy import PolicyEngine


def _make_gateway(
    tmp_path: Path, fixtures_dir: Path, *, approval_sleep: Callable[[float], None]
) -> Gateway:
    catalog = Catalog.load(fixtures_dir / "catalog.yaml")
    policy = PolicyEngine.load(fixtures_dir / "policy.yaml")
    audit = AuditLog(
        LocalFileSink(tmp_path / "audit"),
        Ed25519PrivateKey.generate(),
        session_id="test-session",
        principal="agent_session",
    )
    broker = ApprovalBroker(
        ApprovalStore(tmp_path / "approvals.db"),
        PrincipalDirectory.load(fixtures_dir / "principals.yaml"),
    )
    return Gateway(
        policy=policy,
        catalog=catalog,
        audit=audit,
        approvals=broker,
        session_id="test-session",
        principal="agent_session",
        approval_poll_interval=timedelta(milliseconds=1),
        approval_sleep=approval_sleep,
    )


@pytest.fixture
def gateway(tmp_path: Path, fixtures_dir: Path) -> Iterator[Gateway]:
    # Default fixture: no approval flow exercised, so a real (tiny) sleep
    # is fine, nothing ever actually waits on it.
    gw = _make_gateway(tmp_path, fixtures_dir, approval_sleep=lambda _s: None)
    try:
        yield gw
    finally:
        gw.close()


class TestAllow:
    def test_catalog_list_is_allowed(self, gateway: Gateway) -> None:
        result = gateway.authorize("catalog.list")
        assert result.allowed is True
        assert result.policy_result.matched_rule_id == "catalog-list-ok"

    def test_deidentified_query_is_allowed(self, gateway: Gateway) -> None:
        result = gateway.authorize("sql.query", datasets=["tumor_registry_deid"])
        assert result.allowed is True
        assert result.data_class == DataClass.deidentified

    def test_allow_writes_request_and_decision_audit_entries(self, gateway: Gateway) -> None:
        gateway.authorize("catalog.list")
        entries = list(gateway.audit._sink.read_entries())  # test-only introspection
        event_types = [e.event_type for e in entries]
        assert EventType.request in event_types
        assert EventType.decision in event_types

    def test_audit_payload_never_carries_dataset_content(self, gateway: Gateway) -> None:
        """Only ids, classes, and reasons belong in an audit payload
        (docs/threat-model.md T6); this test exists so a future change
        that starts logging something richer gets caught. Uses the
        de-identified dataset deliberately: it resolves through the
        allow path with no approval wait, which is all this particular
        assertion needs; approval-flow audit entries get their own
        dedicated tests below."""
        gateway.authorize("sql.query", datasets=["tumor_registry_deid"])
        entries = list(gateway.audit._sink.read_entries())
        for e in entries:
            payload_text = str(e.payload)
            assert "EGFR" not in payload_text  # a value that would appear in real row content


class TestDeny:
    def test_unknown_tool_denied(self, gateway: Gateway) -> None:
        result = gateway.authorize("nobody.registered.this")
        assert result.allowed is False

    def test_egress_denied(self, gateway: Gateway) -> None:
        result = gateway.authorize("shell.run", egress=True)
        assert result.allowed is False


class TestModelRouting:
    def test_disallowed_model_denies_before_any_approval_wait(self, gateway: Gateway) -> None:
        """tumor_registry_identified would normally need an approval
        (identified-needs-approval); gpt-4o isn't on the identified
        model_allowlist (only ollama/* and bedrock-baa/* are), so the
        model-routing check must short-circuit to deny before the
        approval flow ever starts, not get stuck waiting on one."""
        result = gateway.authorize(
            "sql.query", datasets=["tumor_registry_identified"], model="gpt-4o"
        )
        assert result.allowed is False
        assert "model routing" in result.reason

    def test_allowed_model_does_not_block_an_otherwise_allowed_tool(
        self, gateway: Gateway
    ) -> None:
        result = gateway.authorize(
            "sql.query", datasets=["tumor_registry_deid"], model="ollama/llama3"
        )
        assert result.allowed is True


class TestApprovalFlow:
    """`approval_sleep` is injected as the broker's poll-wait callback:
    the very first time wait() is about to poll (approval still
    pending), it decides the approval synchronously instead of actually
    sleeping. The loop's next iteration then sees it resolved. No
    threads, no real waiting, see test_approvals.py for the same
    pattern against the broker directly.
    """

    def test_approved_resolves_allowed(self, tmp_path: Path, fixtures_dir: Path) -> None:
        gw_holder: dict[str, Gateway] = {}

        def approve_on_first_poll(_seconds: float) -> None:
            pending = gw_holder["gw"].approvals.list_pending()
            assert pending, "approval should already be pending by the first poll"
            gw_holder["gw"].approvals.decide(pending[0].id, "jane_steward", True, "fine")

        gw = _make_gateway(tmp_path, fixtures_dir, approval_sleep=approve_on_first_poll)
        gw_holder["gw"] = gw

        result = gw.authorize("sql.query", datasets=["tumor_registry_identified"])
        assert result.allowed is True
        assert result.approval_id is not None
        gw.close()

    def test_denied_resolves_not_allowed(self, tmp_path: Path, fixtures_dir: Path) -> None:
        gw_holder: dict[str, Gateway] = {}

        def deny_on_first_poll(_seconds: float) -> None:
            pending = gw_holder["gw"].approvals.list_pending()
            gw_holder["gw"].approvals.decide(pending[0].id, "jane_steward", False, "no")

        gw = _make_gateway(tmp_path, fixtures_dir, approval_sleep=deny_on_first_poll)
        gw_holder["gw"] = gw

        result = gw.authorize("sql.query", datasets=["tumor_registry_identified"])
        assert result.allowed is False
        assert "denied" in result.reason
        gw.close()

    def test_approval_flow_writes_approval_audit_entries(
        self, tmp_path: Path, fixtures_dir: Path
    ) -> None:
        gw_holder: dict[str, Gateway] = {}

        def approve_on_first_poll(_seconds: float) -> None:
            pending = gw_holder["gw"].approvals.list_pending()
            gw_holder["gw"].approvals.decide(pending[0].id, "jane_steward", True, "fine")

        gw = _make_gateway(tmp_path, fixtures_dir, approval_sleep=approve_on_first_poll)
        gw_holder["gw"] = gw

        gw.authorize("sql.query", datasets=["tumor_registry_identified"])

        entries = list(gw.audit._sink.read_entries())
        approval_entries = [e for e in entries if e.event_type == EventType.approval]
        assert len(approval_entries) == 2  # requested, then resolved
        assert approval_entries[0].payload["status"] == "requested"
        assert approval_entries[1].payload["status"] == "approved"
        gw.close()

    def test_two_person_approval_polls_across_two_deciders(
        self, tmp_path: Path, fixtures_dir: Path
    ) -> None:
        gw_holder: dict[str, Gateway] = {}
        calls = {"n": 0}

        def decide_both(_seconds: float) -> None:
            calls["n"] += 1
            pending = gw_holder["gw"].approvals.list_pending()
            if not pending:
                return  # already resolved; loop will exit on its own next check
            approval = pending[0]
            if calls["n"] == 1:
                gw_holder["gw"].approvals.decide(approval.id, "jane_steward", True, "ok")
            else:
                gw_holder["gw"].approvals.decide(approval.id, "priya_privacy", True, "ok")

        gw = _make_gateway(tmp_path, fixtures_dir, approval_sleep=decide_both)
        gw_holder["gw"] = gw

        result = gw.authorize("files.export", datasets=["tumor_registry_identified"])
        assert result.allowed is True
        assert calls["n"] == 2
        gw.close()
