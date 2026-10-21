from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from custody.approvals import ApprovalBroker, ApprovalStore, PrincipalDirectory
from custody.audit import AuditLog, LocalFileSink
from custody.catalog import Catalog, CatalogEntry, DataClass, DatasetFormat
from custody.gateway import Gateway
from custody.guard import OutputGuard
from custody.policy import Decision, Policy, PolicyEngine, Rule, WhenClause
from custody.sandbox import SandboxConfig, SandboxExecutor
from custody.tools import (
    ToolContext,
    UnsafeQueryError,
    approvals_status,
    catalog_list,
    files_export,
    files_write,
    shell_run,
    sql_query,
)
from tests.conftest import requires_docker


def _permissive_policy() -> Policy:
    return Policy(
        rules=[
            Rule(id="catalog-ok", when=WhenClause(tool="catalog.list"), decision=Decision.allow),
            Rule(
                id="sql-ok",
                when=WhenClause(tool="sql.query", max_data_class=DataClass.deidentified),
                decision=Decision.allow,
            ),
            # Deliberately permissive for this fixture (isolate guard
            # behavior from the approval flow, which has its own tests
            # in test_gateway.py and test_approvals.py): identified
            # sql.query is just allowed, not held for approval.
            Rule(
                id="sql-ok-identified",
                when=WhenClause(tool="sql.query", min_data_class=DataClass.identified),
                decision=Decision.allow,
            ),
            Rule(id="no-egress", when=WhenClause(egress=True), decision=Decision.deny),
            Rule(id="shell-ok", when=WhenClause(tool="shell.run"), decision=Decision.allow),
            Rule(id="write-ok", when=WhenClause(tool="files.write"), decision=Decision.allow),
            Rule(id="export-ok", when=WhenClause(tool="files.export"), decision=Decision.allow),
        ],
        default=Decision.deny,
        model_allowlist={},
    )


@pytest.fixture
def ctx(tmp_path: Path, fixtures_dir: Path) -> Iterator[ToolContext]:
    catalog = Catalog(
        {
            "demo": CatalogEntry(
                id="demo",
                path=fixtures_dir / "data" / "mounted_dataset.csv",
                format=DatasetFormat.csv,
                data_class=DataClass.deidentified,
            ),
            "demo_identified": CatalogEntry(
                id="demo_identified",
                path=fixtures_dir / "data" / "mounted_dataset.csv",
                format=DatasetFormat.csv,
                data_class=DataClass.identified,
            ),
        }
    )
    policy = PolicyEngine(_permissive_policy())
    audit = AuditLog(
        LocalFileSink(tmp_path / "audit"),
        Ed25519PrivateKey.generate(),
        session_id="test-session",
        principal="agent_session",
    )
    broker = ApprovalBroker(
        ApprovalStore(tmp_path / "approvals.db"), PrincipalDirectory.empty()
    )
    gateway = Gateway(
        policy=policy,
        catalog=catalog,
        audit=audit,
        approvals=broker,
        session_id="test-session",
        principal="agent_session",
    )
    sandbox = SandboxExecutor(SandboxConfig(image="alpine:3.20", timeout_seconds=20))
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    try:
        yield ToolContext(
            gateway=gateway,
            sandbox=sandbox,
            catalog=catalog,
            guard=OutputGuard(small_cell_minimum=11),
            workspace_dir=workspace,
        )
    finally:
        gateway.close()


class TestCatalogList:
    def test_lists_both_datasets(self, ctx: ToolContext) -> None:
        result = catalog_list(ctx)
        assert result.denied is False
        ids = {row["id"] for row in result.data}
        assert ids == {"demo", "demo_identified"}


@requires_docker
class TestSqlQuery:
    def test_row_level_query(self, ctx: ToolContext) -> None:
        result = sql_query(ctx, "demo", "SELECT gene, variant FROM data")
        assert result.denied is False
        assert result.data == [{"gene": "EGFR", "variant": "L858R"}]

    def test_aggregate_query_on_deidentified_data_is_not_suppressed(
        self, ctx: ToolContext
    ) -> None:
        """guard.py's own rule: suppression applies at limited_data_set
        and above, not below it."""
        result = sql_query(
            ctx, "demo", "SELECT gene AS gene, count(*) AS count FROM data GROUP BY gene"
        )
        assert result.denied is False
        assert result.data[0]["suppressed"] is False
        assert result.data[0]["count"] == 1

    def test_aggregate_query_on_identified_data_is_suppressed(self, ctx: ToolContext) -> None:
        result = sql_query(
            ctx,
            "demo_identified",
            "SELECT gene AS gene, count(*) AS count FROM data GROUP BY gene",
        )
        assert result.denied is False
        # Only one EGFR row in the fixture: 1 < the default minimum (11).
        assert result.data[0]["suppressed"] is True
        assert result.data[0]["count"] is None

    def test_nonexistent_dataset_denied(self, ctx: ToolContext) -> None:
        result = sql_query(ctx, "nope", "SELECT 1")
        assert result.denied is True

    def test_write_query_rejected_before_sandbox(self, ctx: ToolContext) -> None:
        result = sql_query(ctx, "demo", "DELETE FROM data")
        assert result.denied is True
        assert "SELECT" in result.reason or "keyword" in result.reason

    def test_statement_chaining_rejected(self, ctx: ToolContext) -> None:
        result = sql_query(ctx, "demo", "SELECT 1; SELECT 2")
        assert result.denied is True


class TestSqlValidation:
    """Pure validation, no Docker needed."""

    def test_non_select_rejected(self) -> None:
        from custody.tools.sql import _validate_readonly

        with pytest.raises(UnsafeQueryError):
            _validate_readonly("DROP TABLE data")

    def test_select_accepted(self) -> None:
        from custody.tools.sql import _validate_readonly

        _validate_readonly("SELECT * FROM data")  # does not raise

    def test_with_cte_accepted(self) -> None:
        from custody.tools.sql import _validate_readonly

        _validate_readonly("WITH x AS (SELECT 1) SELECT * FROM x")

    def test_banned_keyword_inside_select_rejected(self) -> None:
        from custody.tools.sql import _validate_readonly

        with pytest.raises(UnsafeQueryError):
            _validate_readonly("SELECT * FROM data; ATTACH 'x.db'")


@requires_docker
class TestShellRun:
    def test_simple_command(self, ctx: ToolContext) -> None:
        result = shell_run(ctx, ["echo", "hello"])
        assert result.denied is False
        assert "hello" in result.data["stdout"]

    def test_with_mounted_dataset(self, ctx: ToolContext) -> None:
        result = shell_run(ctx, ["cat", "/data/demo.csv"], datasets=["demo"])
        assert result.denied is False
        assert "EGFR" in result.data["stdout"]

    def test_unknown_dataset_denied(self, ctx: ToolContext) -> None:
        result = shell_run(ctx, ["echo", "hi"], datasets=["nope"])
        assert result.denied is True

    def test_egress_true_is_denied_by_policy_before_the_sandbox(
        self, ctx: ToolContext
    ) -> None:
        """egress=True is a request, not a grant: the policy's no-egress
        rule still blocks it, same as a real agent asking for network
        access it isn't allowed to have."""
        result = shell_run(ctx, ["echo", "hi"], egress=True)
        assert result.denied is True

    def test_egress_false_is_unaffected_by_the_no_egress_rule(
        self, ctx: ToolContext
    ) -> None:
        result = shell_run(ctx, ["echo", "hi"], egress=False)
        assert result.denied is False


class TestFilesWriteAndExport:
    def test_write_then_read_back(self, ctx: ToolContext) -> None:
        result = files_write(ctx, "notes.txt", "hello world")
        assert result.denied is False
        assert (ctx.workspace_dir / "notes.txt").read_text() == "hello world"

    def test_write_path_escape_rejected(self, ctx: ToolContext) -> None:
        result = files_write(ctx, "../../etc/passwd", "pwned")
        assert result.denied is True
        assert "escapes" in result.reason

    def test_export_copies_file_out(self, ctx: ToolContext, tmp_path: Path) -> None:
        files_write(ctx, "report.txt", "cohort report content")
        dest = tmp_path / "exported" / "report.txt"
        result = files_export(ctx, "report.txt", dest)
        assert result.denied is False
        assert dest.read_text() == "cohort report content"

    def test_export_of_missing_file_denied(self, ctx: ToolContext, tmp_path: Path) -> None:
        result = files_export(ctx, "does_not_exist.txt", tmp_path / "out.txt")
        assert result.denied is True

    def test_export_path_escape_rejected(self, ctx: ToolContext, tmp_path: Path) -> None:
        result = files_export(ctx, "../../../etc/passwd", tmp_path / "out.txt")
        assert result.denied is True


class TestApprovalsStatus:
    def test_unknown_approval_id(self, ctx: ToolContext) -> None:
        result = approvals_status(ctx, "not-a-real-id")
        assert result.denied is True

    def test_known_pending_approval(self, ctx: ToolContext) -> None:
        from custody.approvals import ApprovalSummary

        approval = ctx.gateway.approvals.request(
            requester="agent_session",
            rule_id="r1",
            summary=ApprovalSummary(tool="sql.query", data_class="identified"),
            required_count=1,
            required_roles=["data_steward"],
        )
        result = approvals_status(ctx, approval.id)
        assert result.denied is False
        assert result.data["status"] == "pending"
