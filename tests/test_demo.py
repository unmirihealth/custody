from __future__ import annotations

from pathlib import Path

from custody.audit import LocalFileSink
from custody.audit.log import verify_sink
from custody.demo import run_demo
from custody.mcp_server import ServerPaths
from tests.conftest import requires_docker


@requires_docker
class TestRunDemo:
    """One real, end-to-end run (no mocking) of the full scripted
    scenario, docker required. This is deliberately a single large test
    rather than one per step: the steps share expensive setup (building
    the synthetic data, the gateway, the sandbox) and the point of this
    test is exactly that the whole pipeline holds together end to end,
    unit-level coverage of each step already lives in test_tools.py,
    test_gateway.py, and test_approvals.py.
    """

    def test_full_scenario_runs_and_produces_expected_artifacts(
        self, tmp_path: Path, capsys
    ) -> None:
        demo_dir = tmp_path / "demo"
        run_demo(demo_dir)

        # Synthetic data and config actually landed on disk.
        assert (demo_dir / "data" / "tumor_registry_deidentified.synthetic.csv").exists()
        assert (demo_dir / "data" / "tumor_registry_identified.synthetic.csv").exists()
        assert (demo_dir / "policy.yaml").exists()
        assert (demo_dir / "catalog.yaml").exists()
        assert (demo_dir / "principals.yaml").exists()

        output = capsys.readouterr().out

        # Every scripted step actually ran and reported the outcome the
        # scenario is designed to produce.
        assert "[1/8]" in output and "[8/8]" in output
        assert "allowed" in output  # catalog.list, the deidentified query
        assert "held for approval" in output
        assert "DENIED" in output  # the two-person export denial
        assert "BLOCKED" in output  # the sandboxed network attempt
        assert "before tampering: ok=True" in output
        assert "after flipping one byte: ok=False" in output

    def test_audit_log_is_genuinely_tampered_after_the_run(self, tmp_path: Path) -> None:
        """Confirms the demo's own tamper step left the on-disk log
        actually broken (not just printed a message saying so): a fresh
        verify_sink() call against the same files independently agrees.
        """
        demo_dir = tmp_path / "demo"
        run_demo(demo_dir)

        paths = ServerPaths.under(demo_dir)
        result = verify_sink(LocalFileSink(paths.audit_dir))
        assert result.ok is False
