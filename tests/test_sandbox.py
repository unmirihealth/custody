from __future__ import annotations

from pathlib import Path

import pytest

from custody.sandbox import DatasetMount, SandboxConfig, SandboxExecutor
from tests.conftest import requires_docker


class _UnreachableDockerClient:
    def ping(self) -> bool:
        raise ConnectionError("Cannot connect to the Docker daemon")


class TestDockerUnavailable:
    """These never touch a real daemon: Docker is unavailable by
    construction, so they run everywhere, no `requires_docker` marker."""

    def test_available_is_false(self) -> None:
        executor = SandboxExecutor(docker_client=_UnreachableDockerClient())  # type: ignore[arg-type]
        assert executor.available() is False

    def test_run_returns_denied_not_an_exception(self) -> None:
        executor = SandboxExecutor(docker_client=_UnreachableDockerClient())  # type: ignore[arg-type]
        result = executor.run(["echo", "hi"])
        assert result.denied is True
        assert result.exit_code is None
        assert result.timed_out is False
        assert "Docker is unavailable" in (result.denial_reason or "")


# ── Real Docker integration tests ────────────────────────────────────


@pytest.fixture
def executor() -> SandboxExecutor:
    return SandboxExecutor(SandboxConfig(image="alpine:3.20", timeout_seconds=20))


@requires_docker
class TestRealSandbox:
    def test_available_is_true(self, executor: SandboxExecutor) -> None:
        assert executor.available() is True

    def test_simple_command_succeeds(self, executor: SandboxExecutor) -> None:
        result = executor.run(["echo", "hello from the sandbox"])
        assert result.denied is False
        assert result.exit_code == 0
        assert "hello from the sandbox" in result.stdout

    def test_runs_as_non_root(self, executor: SandboxExecutor) -> None:
        result = executor.run(["id", "-u"])
        assert result.stdout.strip() == "65534"

    def test_root_filesystem_is_read_only(self, executor: SandboxExecutor) -> None:
        result = executor.run(["sh", "-c", "touch /not-allowed 2>&1 || echo READONLY"])
        assert "READONLY" in result.stdout

    def test_tmp_is_writable(self, executor: SandboxExecutor) -> None:
        result = executor.run(["sh", "-c", "touch /tmp/scratch && echo WROTE_OK"])
        assert "WROTE_OK" in result.stdout

    def test_network_disabled_by_default(self, executor: SandboxExecutor) -> None:
        """With no interface but loopback, even DNS resolution fails
        immediately, regardless of whether the host itself has internet
        access -- this is the same observable failure either way, which
        is exactly why it's a reliable thing to assert on."""
        result = executor.run(
            ["sh", "-c", "wget -T 2 -q -O /dev/null http://10.255.255.1/ 2>&1 || echo NO_NETWORK"]
        )
        assert "NO_NETWORK" in result.stdout

    def test_mounted_dataset_is_readable(
        self, executor: SandboxExecutor, fixtures_dir: Path
    ) -> None:
        mount = DatasetMount(
            dataset_id="demo",
            host_path=fixtures_dir / "data" / "mounted_dataset.csv",
            container_path="/data/demo.csv",
        )
        result = executor.run(["cat", "/data/demo.csv"], mounts=[mount])
        assert "EGFR" in result.stdout
        assert "L858R" in result.stdout

    def test_mounted_dataset_is_read_only(
        self, executor: SandboxExecutor, fixtures_dir: Path
    ) -> None:
        mount = DatasetMount(
            dataset_id="demo",
            host_path=fixtures_dir / "data" / "mounted_dataset.csv",
            container_path="/data/demo.csv",
        )
        result = executor.run(
            ["sh", "-c", "echo tampered > /data/demo.csv 2>&1 || echo RO"], mounts=[mount]
        )
        assert "RO" in result.stdout

    def test_unmounted_path_does_not_exist_in_container(
        self, executor: SandboxExecutor
    ) -> None:
        """No mounts at all: /data isn't even a real path inside the
        container, so a dataset the policy never allowed isn't just
        access-denied, it isn't there."""
        result = executor.run(["sh", "-c", "cat /data/anything.csv 2>&1 || echo NOT_FOUND"])
        assert "NOT_FOUND" in result.stdout

    def test_only_the_allowed_dataset_is_visible(
        self, executor: SandboxExecutor, fixtures_dir: Path
    ) -> None:
        """Mounting one dataset doesn't leak a sibling file that happens
        to live next to it on the host."""
        mount = DatasetMount(
            dataset_id="demo",
            host_path=fixtures_dir / "data" / "mounted_dataset.csv",
            container_path="/data/demo.csv",
        )
        result = executor.run(
            ["sh", "-c", "ls /data/ 2>&1"],
            mounts=[mount],
        )
        assert "demo.csv" in result.stdout
        assert "catalog.yaml" not in result.stdout  # a sibling fixture file, never mounted

    def test_nonzero_exit_code_is_reported(self, executor: SandboxExecutor) -> None:
        result = executor.run(["sh", "-c", "exit 7"])
        assert result.exit_code == 7
        assert result.denied is False

    def test_timeout_is_reported(self) -> None:
        executor = SandboxExecutor(SandboxConfig(image="alpine:3.20", timeout_seconds=1))
        result = executor.run(["sleep", "10"])
        assert result.timed_out is True
        assert result.exit_code is None

    def test_image_override_takes_precedence_over_config(self) -> None:
        executor = SandboxExecutor(SandboxConfig(image="alpine:3.20"))
        result = executor.run(["python3", "--version"], image="custody-sandbox:duckdb")
        assert result.denied is False
        assert result.exit_code == 0
        assert "Python" in result.stdout
