from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from custody.cli.main import app

runner = CliRunner()


class TestInit:
    def test_creates_starter_files(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["init", "--dir", str(tmp_path)])
        assert result.exit_code == 0, result.output
        assert (tmp_path / "policy.yaml").exists()
        assert (tmp_path / "catalog.yaml").exists()
        assert (tmp_path / "principals.yaml").exists()
        assert (tmp_path / ".custody" / "signing_key.pem").exists()
        assert (tmp_path / ".custody" / "workspace").is_dir()

    def test_running_twice_does_not_overwrite(self, tmp_path: Path) -> None:
        runner.invoke(app, ["init", "--dir", str(tmp_path)])
        key_bytes_before = (tmp_path / ".custody" / "signing_key.pem").read_bytes()
        result = runner.invoke(app, ["init", "--dir", str(tmp_path)])
        assert result.exit_code == 0
        assert "already exists" in result.output
        assert (tmp_path / ".custody" / "signing_key.pem").read_bytes() == key_bytes_before


class TestServeTransportValidation:
    """custody serve actually running (stdio or streamable-http) blocks
    forever, not something a CliRunner invocation can exercise
    directly; k8s/smoke-test.sh (docs/kubernetes.md) is where
    streamable-http gets a real end-to-end run, against a real kind
    cluster. This only covers the one path that returns instead of
    blocking: an unsupported --transport value."""

    def test_unsupported_transport_exits_with_a_clear_error(self, tmp_path: Path) -> None:
        runner.invoke(app, ["init", "--dir", str(tmp_path)])
        result = runner.invoke(
            app,
            [
                "serve",
                "--dir",
                str(tmp_path),
                "--principal",
                "test-agent",
                "--transport",
                "carrier-pigeon",
            ],
        )
        assert result.exit_code == 1
        assert "unsupported transport" in result.output


class TestPolicyCommands:
    def test_check_valid_policy(self, fixtures_dir: Path) -> None:
        result = runner.invoke(app, ["policy", "check", str(fixtures_dir / "policy.yaml")])
        assert result.exit_code == 0
        assert "OK" in result.output

    def test_check_invalid_policy(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yaml"
        bad.write_text("rules: []\ndefault: allow\n")
        result = runner.invoke(app, ["policy", "check", str(bad)])
        assert result.exit_code == 1

    def test_explain_shows_matched_rule(self, fixtures_dir: Path) -> None:
        result = runner.invoke(
            app,
            [
                "policy",
                "explain",
                str(fixtures_dir / "policy.yaml"),
                str(fixtures_dir / "catalog.yaml"),
                "catalog.list",
            ],
        )
        assert result.exit_code == 0
        assert "catalog-list-ok" in result.output

    def test_explain_with_dataset(self, fixtures_dir: Path) -> None:
        result = runner.invoke(
            app,
            [
                "policy",
                "explain",
                str(fixtures_dir / "policy.yaml"),
                str(fixtures_dir / "catalog.yaml"),
                "sql.query",
                "--dataset",
                "tumor_registry_identified",
            ],
        )
        assert result.exit_code == 0
        assert "require_approval" in result.output


class TestPolicySignAndVerify:
    def test_sign_then_verify_round_trip(self, tmp_path: Path, fixtures_dir: Path) -> None:
        import shutil

        policy = tmp_path / "policy.yaml"
        shutil.copy(fixtures_dir / "policy.yaml", policy)
        key = tmp_path / "signing_key.pem"
        init_result = runner.invoke(app, ["init", "--dir", str(tmp_path / "deploy")])
        assert init_result.exit_code == 0
        key = tmp_path / "deploy" / ".custody" / "signing_key.pem"

        sign_result = runner.invoke(app, ["policy", "sign", str(policy), "--key", str(key)])
        assert sign_result.exit_code == 0, sign_result.output
        assert (tmp_path / "policy.yaml.sig.json").exists()

        verify_result = runner.invoke(app, ["policy", "verify", str(policy)])
        assert verify_result.exit_code == 0, verify_result.output
        assert "OK" in verify_result.output

    def test_verify_fails_without_a_bundle(self, fixtures_dir: Path) -> None:
        result = runner.invoke(app, ["policy", "verify", str(fixtures_dir / "policy.yaml")])
        assert result.exit_code == 1
        assert "no signed bundle" in result.output

    def test_verify_fails_after_the_file_changes(self, tmp_path: Path, fixtures_dir: Path) -> None:
        import shutil

        policy = tmp_path / "policy.yaml"
        shutil.copy(fixtures_dir / "policy.yaml", policy)
        runner.invoke(app, ["init", "--dir", str(tmp_path / "deploy")])
        key = tmp_path / "deploy" / ".custody" / "signing_key.pem"
        runner.invoke(app, ["policy", "sign", str(policy), "--key", str(key)])

        policy.write_text(policy.read_text() + "\n# tampered\n")
        result = runner.invoke(app, ["policy", "verify", str(policy)])
        assert result.exit_code == 1
        assert "INVALID" in result.output


class TestApprovalsCommands:
    def test_list_and_decide_roundtrip(self, tmp_path: Path, fixtures_dir: Path) -> None:
        import shutil

        from custody.approvals import ApprovalBroker, ApprovalSummary
        from custody.mcp_server import ServerPaths

        # The CLI commands build their own ServerPaths.under(tmp_path),
        # which looks for principals.yaml at the deployment root, so the
        # fixture needs to actually live there, not just be referenced.
        shutil.copy(fixtures_dir / "principals.yaml", tmp_path / "principals.yaml")
        paths = ServerPaths.under(tmp_path)
        broker = ApprovalBroker.open(paths.approvals_db, paths.principals)
        approval = broker.request(
            requester="agent_session",
            rule_id="r1",
            summary=ApprovalSummary(tool="sql.query", data_class="identified"),
            required_count=1,
            required_roles=["data_steward"],
        )
        broker.close()

        list_result = runner.invoke(app, ["approvals", "list", "--dir", str(tmp_path)])
        assert approval.id in list_result.output

        approve_result = runner.invoke(
            app,
            [
                "approvals",
                "approve",
                approval.id,
                "--as",
                "jane_steward",
                "--reason",
                "fine",
                "--dir",
                str(tmp_path),
            ],
        )
        assert approve_result.exit_code == 0
        assert "approved" in approve_result.output

        empty_list = runner.invoke(app, ["approvals", "list", "--dir", str(tmp_path)])
        assert "no pending approvals" in empty_list.output

    def test_approve_requires_exactly_one_of_as_or_as_token(
        self, tmp_path: Path, fixtures_dir: Path
    ) -> None:
        import shutil

        shutil.copy(fixtures_dir / "principals.yaml", tmp_path / "principals.yaml")

        neither = runner.invoke(
            app, ["approvals", "approve", "x", "--reason", "r", "--dir", str(tmp_path)]
        )
        assert neither.exit_code == 1
        assert "exactly one of --as or --as-token" in neither.output

        both = runner.invoke(
            app,
            [
                "approvals",
                "approve",
                "x",
                "--as",
                "jane_steward",
                "--as-token",
                "sometoken",
                "--reason",
                "r",
                "--dir",
                str(tmp_path),
            ],
        )
        assert both.exit_code == 1
        assert "exactly one of --as or --as-token" in both.output

    def test_as_token_without_oidc_env_vars_fails_clearly(
        self, tmp_path: Path, fixtures_dir: Path
    ) -> None:
        import shutil

        shutil.copy(fixtures_dir / "principals.yaml", tmp_path / "principals.yaml")
        result = runner.invoke(
            app,
            [
                "approvals",
                "approve",
                "x",
                "--as-token",
                "sometoken",
                "--reason",
                "r",
                "--dir",
                str(tmp_path),
            ],
            env={"CUSTODY_OIDC_ISSUER": "", "CUSTODY_OIDC_JWKS_URL": ""},
        )
        assert result.exit_code == 1
        assert "CUSTODY_OIDC_ISSUER" in result.output


class TestApprovalsOidcToken:
    """--as-token end to end, against a real mock OIDC provider, not a
    mock HTTP layer: see tests/test_oidc.py for OidcVerifier's own
    dedicated test suite; this confirms the CLI actually wires it up,
    including resolving the verified identity into a real approval
    decision."""

    @pytest.fixture(scope="class")
    def issuer_url(self):  # type: ignore[no-untyped-def]
        from tests.test_oidc import MOCK_OIDC_IMAGE, _mock_oidc_available, _wait_for_ready

        if not _mock_oidc_available():
            pytest.skip("Docker daemon not reachable")

        import docker

        client = docker.from_env()
        name = "custody-test-oidc-cli"
        try:
            client.containers.get(name).remove(force=True)
        except docker.errors.NotFound:
            pass
        container = client.containers.run(
            MOCK_OIDC_IMAGE, detach=True, name=name, ports={"8080/tcp": 18445}
        )
        url = "http://localhost:18445/default"
        try:
            _wait_for_ready(url)
            yield url
        finally:
            container.remove(force=True)

    def test_decide_with_a_verified_token(
        self, tmp_path: Path, fixtures_dir: Path, issuer_url: str
    ) -> None:
        import shutil

        from custody.approvals import ApprovalBroker, ApprovalSummary
        from custody.mcp_server import ServerPaths
        from tests.test_oidc import _mint_token

        shutil.copy(fixtures_dir / "principals.yaml", tmp_path / "principals.yaml")
        paths = ServerPaths.under(tmp_path)
        broker = ApprovalBroker.open(paths.approvals_db, paths.principals)
        approval = broker.request(
            requester="agent_session",
            rule_id="r1",
            summary=ApprovalSummary(tool="sql.query", data_class="identified"),
            required_count=1,
            required_roles=["data_steward"],
        )
        broker.close()

        token = _mint_token(issuer_url, "jane_steward")
        result = runner.invoke(
            app,
            [
                "approvals",
                "approve",
                approval.id,
                "--as-token",
                token,
                "--reason",
                "verified via mock IdP",
                "--dir",
                str(tmp_path),
            ],
            env={"CUSTODY_OIDC_ISSUER": issuer_url, "CUSTODY_OIDC_JWKS_URL": f"{issuer_url}/jwks"},
        )
        assert result.exit_code == 0, result.output
        assert "approved" in result.output

    def test_a_tampered_token_is_rejected(
        self, tmp_path: Path, fixtures_dir: Path, issuer_url: str
    ) -> None:
        import shutil

        from tests.test_oidc import _mint_token

        shutil.copy(fixtures_dir / "principals.yaml", tmp_path / "principals.yaml")
        token = _mint_token(issuer_url, "jane_steward")
        tampered = token[:-5] + ("a" if token[-5] != "a" else "b") + token[-4:]

        result = runner.invoke(
            app,
            [
                "approvals",
                "approve",
                "doesnt-matter",
                "--as-token",
                tampered,
                "--reason",
                "r",
                "--dir",
                str(tmp_path),
            ],
            env={"CUSTODY_OIDC_ISSUER": issuer_url, "CUSTODY_OIDC_JWKS_URL": f"{issuer_url}/jwks"},
        )
        assert result.exit_code == 1
        assert "token verification failed" in result.output


class TestAuditCommands:
    def test_verify_on_init_empty_log(self, tmp_path: Path) -> None:
        runner.invoke(app, ["init", "--dir", str(tmp_path)])
        result = runner.invoke(app, ["audit", "verify", "--dir", str(tmp_path)])
        assert result.exit_code == 0
        assert "OK" in result.output

    def test_tail_and_export_after_some_activity(self, tmp_path: Path, fixtures_dir: Path) -> None:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        from custody.audit import AuditLog, EventType, LocalFileSink
        from custody.mcp_server import ServerPaths

        paths = ServerPaths.under(tmp_path)
        log = AuditLog(
            LocalFileSink(paths.audit_dir),
            Ed25519PrivateKey.generate(),
            session_id="s",
            principal="agent_session",
        )
        log.append(EventType.request, {"tool": "catalog.list"})
        log.append(EventType.decision, {"tool": "catalog.list", "decision": "allow"})

        tail_result = runner.invoke(app, ["audit", "tail", "--dir", str(tmp_path)])
        assert "catalog.list" in tail_result.output

        dest = tmp_path / "export.jsonl"
        export_result = runner.invoke(
            app, ["audit", "export", str(dest), "--dir", str(tmp_path)]
        )
        assert export_result.exit_code == 0
        assert dest.exists()
        assert len(dest.read_text().splitlines()) == 2


class TestEvidenceCommands:
    def test_export_writes_a_pack(self, tmp_path: Path) -> None:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        from custody.audit import AuditLog, EventType, LocalFileSink
        from custody.mcp_server import ServerPaths

        runner.invoke(app, ["init", "--dir", str(tmp_path)])
        paths = ServerPaths.under(tmp_path)
        log = AuditLog(
            LocalFileSink(paths.audit_dir),
            Ed25519PrivateKey.generate(),
            session_id="s",
            principal="agent_session",
        )
        log.append(EventType.request, {"tool": "catalog.list"})
        log.append(EventType.decision, {"tool": "catalog.list", "decision": "allow"})

        dest = tmp_path / "pack"
        result = runner.invoke(app, ["evidence", "export", str(dest), "--dir", str(tmp_path)])
        assert result.exit_code == 0, result.output
        assert "audit integrity: OK" in result.output
        assert (dest / "manifest.json").exists()
        assert (dest / "README.md").exists()
        assert (dest / "policy.yaml").exists()  # custody init wrote a starter policy

    def test_export_refuses_a_non_empty_destination(self, tmp_path: Path) -> None:
        runner.invoke(app, ["init", "--dir", str(tmp_path)])
        dest = tmp_path / "pack"
        dest.mkdir()
        (dest / "x").write_text("already here")
        result = runner.invoke(app, ["evidence", "export", str(dest), "--dir", str(tmp_path)])
        assert result.exit_code == 1
        assert "already exists" in result.output
