"""Docker-based egress allowlist proxy (docs/threat-model.md T9).

The problem this solves: `allow_egress=True` on its own is a plain
on/off switch (`network_disabled=False`), the same unscoped access the
threat model documents as a residual risk. This module gives
`SandboxExecutor` a scoped alternative: when a `SandboxConfig` carries
a non-empty `egress_allowlist`, an egress-allowed run attaches the
sandboxed container to a Docker network with `internal=True` (no route
out at all) alongside a small forward proxy (`docker/egress-proxy
.Dockerfile`, `docker/egress_proxy_server.py`) that is the only thing
also attached to a normal, internet-reaching network. The sandboxed
container's one and only path anywhere, allowlisted host or not, is
through that proxy, which refuses anything not on the allowlist.

This is still not gVisor or Firecracker-grade isolation (ROADMAP.md):
a sandboxed process that found a way to bypass its HTTP_PROXY/
HTTPS_PROXY environment variables (rather than merely ignoring them)
and reach another IP directly would still be blocked only because the
network itself has no route out, not because the proxy inspected and
rejected it, the `internal=True` network is what actually makes this a
hard boundary, the proxy adds host-level allowlisting on top of that.
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass

from docker.models.containers import Container
from docker.models.networks import Network

import docker

logger = logging.getLogger("custody.sandbox.egress_proxy")

DEFAULT_EGRESS_PROXY_IMAGE = "custody-egress-proxy:latest"
_PROXY_PORT = 3128


@dataclass
class EgressProxyHandle:
    """Everything a sandboxed container needs to route through a
    running proxy: which network to join, and the proxy's address on
    that network."""

    network_name: str
    proxy_url: str


class EgressAllowlistProxy:
    """One instance per sandboxed run that needs scoped egress. Not
    reused across runs: a fresh internal network and proxy container
    per call keeps one run's allowlist from ever leaking into another's,
    at the cost of a little startup latency (a few hundred ms locally).
    """

    def __init__(
        self,
        docker_client: docker.DockerClient,
        allowlist: list[str],
        *,
        image: str = DEFAULT_EGRESS_PROXY_IMAGE,
    ) -> None:
        if not allowlist:
            raise ValueError("EgressAllowlistProxy requires a non-empty allowlist")
        self._client = docker_client
        self._allowlist = allowlist
        self._image = image
        self._suffix = uuid.uuid4().hex[:12]
        self._network: Network | None = None
        self._container: Container | None = None

    def start(self) -> EgressProxyHandle:
        network_name = f"custody-egress-{self._suffix}"
        self._network = self._client.networks.create(
            network_name, driver="bridge", internal=True
        )
        container = self._client.containers.run(
            self._image,
            detach=True,
            name=f"custody-egress-proxy-{self._suffix}",
            environment={"ALLOWED_HOSTS": ",".join(self._allowlist)},
            network=network_name,
            read_only=True,
            cap_drop=["ALL"],
            security_opt=["no-new-privileges:true"],
        )
        self._container = container
        # The proxy container needs a second leg out to wherever an
        # allowlisted host actually lives; the internal network above
        # has no route out by design. Docker's own default "bridge"
        # network is NAT'd to the host's network, same reachability
        # any container gets without network_disabled set.
        self._client.networks.get("bridge").connect(container)
        container.reload()
        proxy_ip = container.attrs["NetworkSettings"]["Networks"][network_name]["IPAddress"]
        self._wait_until_listening(container)
        return EgressProxyHandle(
            network_name=network_name,
            proxy_url=f"http://{proxy_ip}:{_PROXY_PORT}",
        )

    def _wait_until_listening(self, container: Container, timeout: float = 5.0) -> None:
        """Python's interpreter startup plus a container's own first
        scheduling (a few tens to low hundreds of ms on this machine)
        means the proxy process is not guaranteed to be bound and
        listening the instant `containers.run` returns. Probe from
        inside the container itself via `exec_run` (works over the
        Docker API, not network routing, so it's unaffected by the
        internal network's own reachability) rather than guessing at a
        fixed sleep."""
        deadline = time.monotonic() + timeout
        probe = [
            "python3",
            "-c",
            f"import socket; socket.create_connection(('127.0.0.1', {_PROXY_PORT}), 0.5).close()",
        ]
        while time.monotonic() < deadline:
            result = container.exec_run(probe)
            if result.exit_code == 0:
                return
            time.sleep(0.1)
        logger.debug("egress proxy: readiness probe never succeeded within %.1fs", timeout)

    def stop(self) -> None:
        if self._container is not None:
            try:
                self._container.remove(force=True)
            except Exception as exc:  # noqa: BLE001 - best-effort cleanup
                logger.debug("egress proxy: container removal failed: %s", exc)
            self._container = None
        if self._network is not None:
            try:
                self._network.remove()
            except Exception as exc:  # noqa: BLE001 - best-effort cleanup
                logger.debug("egress proxy: network removal failed: %s", exc)
            self._network = None

    def __enter__(self) -> EgressProxyHandle:
        return self.start()

    def __exit__(self, *_exc_info: object) -> None:
        self.stop()


__all__ = ["DEFAULT_EGRESS_PROXY_IMAGE", "EgressAllowlistProxy", "EgressProxyHandle"]
