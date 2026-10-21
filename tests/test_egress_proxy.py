"""Real-Docker tests for the egress allowlist proxy (docs/threat-model.md
T9). Deliberately avoids depending on real internet access: an
"upstream" test target is just another container on the same internal
network as the proxy, which is enough to prove the allow/deny
mechanism works without the test suite's pass/fail depending on
whatever network the CI runner happens to have.
"""

from __future__ import annotations

import pytest

from custody.sandbox import EgressAllowlistProxy, SandboxConfig, SandboxExecutor
from tests.conftest import requires_docker


@requires_docker
class TestEgressAllowlistProxy:
    def test_requires_a_non_empty_allowlist(self) -> None:
        import docker

        with pytest.raises(ValueError, match="non-empty allowlist"):
            EgressAllowlistProxy(docker.from_env(), [])

    def test_start_returns_a_reachable_proxy_address(self) -> None:
        import docker

        proxy = EgressAllowlistProxy(docker.from_env(), ["example.com"])
        try:
            handle = proxy.start()
            assert handle.network_name.startswith("custody-egress-")
            assert handle.proxy_url.startswith("http://")
        finally:
            proxy.stop()

    def test_stop_removes_the_container_and_network(self) -> None:
        import docker

        client = docker.from_env()
        proxy = EgressAllowlistProxy(client, ["example.com"])
        handle = proxy.start()
        proxy.stop()
        with pytest.raises(docker.errors.NotFound):
            client.networks.get(handle.network_name)


@requires_docker
class TestSandboxExecutorScopedEgress:
    """End to end: a sandboxed container with allow_egress=True and a
    configured allowlist can only reach an allowlisted container name,
    never one left off the list, and never the open internet either --
    the network it joins has no route out beyond the proxy.
    """

    @pytest.fixture
    def allowed_upstream(self):  # type: ignore[no-untyped-def]
        import docker

        client = docker.from_env()
        container = client.containers.run(
            "python:3.12-alpine",
            ["python3", "-m", "http.server", "8000"],
            detach=True,
            name="custody-test-upstream-allowed",
            network="bridge",
        )
        yield container
        container.remove(force=True)

    def test_allowlisted_host_is_reachable_through_the_proxy(self, allowed_upstream) -> None:  # type: ignore[no-untyped-def]
        import docker

        client = docker.from_env()
        allowed_upstream.reload()
        allowed_ip = allowed_upstream.attrs["NetworkSettings"]["Networks"]["bridge"]["IPAddress"]

        config = SandboxConfig(
            image="alpine:3.20", timeout_seconds=20, egress_allowlist=[allowed_ip]
        )
        executor = SandboxExecutor(config, docker_client=client)
        result = executor.run(
            ["sh", "-c", f"wget -T 5 -q -O- http://{allowed_ip}:8000/ || echo FAILED"],
            allow_egress=True,
        )
        assert result.denied is False
        assert "FAILED" not in result.stdout

    def test_non_allowlisted_host_is_refused_by_the_proxy(self, allowed_upstream) -> None:  # type: ignore[no-untyped-def]
        """`allowed_upstream` runs, but its IP is never added to the
        allowlist here -- only a different, made-up address is -- so
        the proxy must refuse to forward to it, confirming the
        allowlist is actually enforced, not just "network reachable or
        not"."""
        import docker

        client = docker.from_env()
        allowed_upstream.reload()
        allowed_ip = allowed_upstream.attrs["NetworkSettings"]["Networks"]["bridge"]["IPAddress"]

        config = SandboxConfig(
            image="alpine:3.20", timeout_seconds=20, egress_allowlist=["203.0.113.1"]
        )
        executor = SandboxExecutor(config, docker_client=client)
        result = executor.run(
            ["sh", "-c", f"wget -T 5 -q -O- http://{allowed_ip}:8000/ 2>&1 || echo BLOCKED"],
            allow_egress=True,
        )
        assert result.denied is False
        assert "BLOCKED" in result.stdout

    def test_no_allowlist_falls_back_to_old_unscoped_behavior(self) -> None:
        """SandboxConfig with an empty egress_allowlist (the default)
        must behave exactly as before this feature existed: a plain
        on/off switch, no proxy involved."""
        executor = SandboxExecutor(SandboxConfig(image="alpine:3.20", timeout_seconds=10))
        result = executor.run(["sh", "-c", "echo ran"], allow_egress=True)
        assert result.denied is False
        assert "ran" in result.stdout
