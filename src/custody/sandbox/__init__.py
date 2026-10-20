"""Sandbox executor.

Runs shell commands and Python scripts inside a Docker container: non-root
user, --network none by default, read-only root filesystem with a
writable tmpfs work directory, CPU/memory/pids/time limits, every
capability dropped, no-new-privileges. Only the datasets a policy decision
allowed are bind-mounted, and always read-only.

If Docker is unavailable, or the container fails to start, that resolves
to deny and is logged the same as a policy deny, not as a silent
best-effort skip. See docs/threat-model.md T2 and T9 for what this does
and does not protect against, in particular that this is standard Docker
isolation in v0.1, not gVisor or Firecracker (ROADMAP.md).

Planned surface:
    class SandboxConfig(BaseModel): ...
    class SandboxExecutor:
        def run(self, command: list[str], mounts: list[DatasetMount],
                 allow_egress: EgressAllowlist | None = None) -> ExecutionResult: ...

Not yet implemented.
"""

raise NotImplementedError("custody.sandbox is not yet implemented (v0.1 skeleton)")
