from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from custody.mcp_server import ServerPaths, build_server
from tests.conftest import requires_docker


@pytest.fixture
def paths(tmp_path: Path, fixtures_dir: Path) -> ServerPaths:
    return ServerPaths(
        policy=fixtures_dir / "policy.yaml",
        catalog=fixtures_dir / "catalog.yaml",
        principals=fixtures_dir / "principals.yaml",
        audit_dir=tmp_path / "audit",
        signing_key=tmp_path / "signing_key.pem",
        approvals_db=tmp_path / "approvals.db",
        workspace_dir=tmp_path / "workspace",
    )


class TestBuildServer:
    def test_server_has_expected_name(self, paths: ServerPaths) -> None:
        mcp = build_server(paths, session_id="test", principal="agent")
        assert mcp.name == "Custody"

    def test_registers_all_seven_tools(self, paths: ServerPaths) -> None:
        mcp = build_server(paths, session_id="test", principal="agent")
        tools = asyncio.run(mcp.list_tools())
        names = {t.name for t in tools}
        assert names == {
            "catalog.list",
            "sql.query",
            "shell.run",
            "files.write",
            "files.export",
            "approvals.status",
            "fhir.search",
        }

    def test_generates_a_signing_key_on_first_build(self, paths: ServerPaths) -> None:
        assert not paths.signing_key.exists()
        build_server(paths, session_id="test", principal="agent")
        assert paths.signing_key.exists()

    def test_reuses_an_existing_signing_key(self, paths: ServerPaths) -> None:
        build_server(paths, session_id="test", principal="agent")
        first_key_bytes = paths.signing_key.read_bytes()
        build_server(paths, session_id="test-2", principal="agent")
        assert paths.signing_key.read_bytes() == first_key_bytes


@requires_docker
class TestCatalogListToolEndToEnd:
    def test_catalog_list_tool_call_succeeds(self, paths: ServerPaths) -> None:
        mcp = build_server(paths, session_id="test", principal="agent")
        result = asyncio.run(mcp.call_tool("catalog.list", {}))
        # call_tool's return shape varies by SDK version (content blocks,
        # possibly a structured result); this only checks the call
        # didn't raise and produced something, the real behavioral
        # coverage lives in test_tools.py against catalog_list() directly.
        assert result is not None
