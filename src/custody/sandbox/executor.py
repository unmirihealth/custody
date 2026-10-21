"""Runs a command in a locked-down Docker container. See
docs/threat-model.md T2 and T9 for exactly what this does and does not
protect against: standard Docker container isolation, not gVisor or
Firecracker (ROADMAP.md), and no fully isolated egress allowlist in
v0.1, `allow_egress=True` is a plain on/off switch, not a scoped proxy.
"""

from __future__ import annotations

import logging

import docker
import docker.errors

from custody.sandbox.models import DatasetMount, ExecutionResult, SandboxConfig

logger = logging.getLogger("custody.sandbox")


class SandboxExecutor:
    """Construct once per gateway process; reuses one Docker client. If
    the Docker daemon is unreachable at construction time, `available()`
    returns False and every `run()` call returns a `denied` result
    instead of raising, matching "if Docker is unavailable... deny and
    log" rather than crashing the gateway.
    """

    def __init__(
        self,
        config: SandboxConfig | None = None,
        docker_client: docker.DockerClient | None = None,
    ) -> None:
        self._config = config or SandboxConfig()
        self._client: docker.DockerClient | None = None
        self._unavailable_reason: str | None = None
        try:
            client = docker_client or docker.from_env()
            client.ping()
            self._client = client
        except Exception as exc:  # noqa: BLE001 - any Docker failure means "unavailable"
            self._unavailable_reason = str(exc)

    def available(self) -> bool:
        return self._client is not None

    def run(
        self,
        command: list[str],
        mounts: list[DatasetMount] | None = None,
        *,
        allow_egress: bool = False,
    ) -> ExecutionResult:
        if self._client is None:
            return ExecutionResult(
                exit_code=None,
                stdout="",
                stderr="",
                timed_out=False,
                denied=True,
                denial_reason=f"Docker is unavailable: {self._unavailable_reason}",
            )

        volumes = {
            str(m.host_path.resolve()): {"bind": m.container_path, "mode": "ro"}
            for m in (mounts or [])
        }

        try:
            container = self._client.containers.run(
                self._config.image,
                command,
                detach=True,
                user="65534:65534",  # nobody:nobody; non-root unconditionally
                network_disabled=not allow_egress,
                read_only=True,
                # This is the CONTAINER's mount point, not a host path:
                # ruff's S108 flags bare "/tmp" as an insecure host temp
                # dir, which doesn't apply to a tmpfs target inside an
                # isolated container.
                tmpfs={"/tmp": f"rw,size={self._config.tmpfs_size_mb}m"},  # noqa: S108
                cap_drop=["ALL"],
                security_opt=["no-new-privileges:true"],
                mem_limit=f"{self._config.memory_limit_mb}m",
                nano_cpus=int(self._config.cpu_limit * 1_000_000_000),
                pids_limit=self._config.pids_limit,
                volumes=volumes,
                stdout=True,
                stderr=True,
            )
        except (docker.errors.APIError, docker.errors.ImageNotFound) as exc:
            return ExecutionResult(
                exit_code=None,
                stdout="",
                stderr="",
                timed_out=False,
                denied=True,
                denial_reason=f"container failed to start: {exc}",
            )

        timed_out = False
        exit_code: int | None
        try:
            wait_result = container.wait(timeout=self._config.timeout_seconds)
            exit_code = wait_result.get("StatusCode")
        except Exception:  # noqa: BLE001 - docker-py raises a bare requests timeout here
            timed_out = True
            exit_code = None
            try:
                container.kill()
            except Exception as kill_exc:  # noqa: BLE001 - best-effort, container may already be gone
                logger.debug(
                    "sandbox: kill after timeout failed (likely already exited): %s", kill_exc
                )

        stdout = container.logs(stdout=True, stderr=False).decode("utf-8", errors="replace")
        stderr = container.logs(stdout=False, stderr=True).decode("utf-8", errors="replace")

        try:
            container.remove(force=True)
        except Exception as remove_exc:  # noqa: BLE001 - best-effort cleanup
            logger.debug("sandbox: container removal failed: %s", remove_exc)

        return ExecutionResult(
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            timed_out=timed_out,
            denied=False,
        )
