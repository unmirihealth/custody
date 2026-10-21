"""Pydantic models for the sandbox executor. See docs/threat-model.md T2
and T9 for what this layer does and does not protect against.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field


class SandboxConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    image: str = "alpine:3.20"
    cpu_limit: float = Field(default=1.0, gt=0)
    memory_limit_mb: int = Field(default=512, gt=0)
    pids_limit: int = Field(default=64, gt=0)
    timeout_seconds: int = Field(default=30, gt=0)
    tmpfs_size_mb: int = Field(default=64, gt=0)
    # Hostnames (exact or fnmatch-style glob, e.g. "*.example.com") an
    # egress-allowed run may reach. Empty means an `allow_egress=True`
    # call falls back to the old unscoped behavior (full network
    # access, the residual risk docs/threat-model.md T9 documents);
    # non-empty switches to the scoped proxy in
    # custody.sandbox.egress_proxy.
    egress_allowlist: list[str] = Field(default_factory=list)
    egress_proxy_image: str = "custody-egress-proxy:latest"


class DatasetMount(BaseModel):
    """One dataset, bind-mounted read-only into the container. Only
    datasets the policy decision actually allowed should ever appear in
    this list, the sandbox itself does not re-check policy, it trusts
    its caller the same way a kernel trusts a syscall's arguments."""

    model_config = ConfigDict(extra="forbid")

    dataset_id: str
    host_path: Path
    container_path: str = Field(pattern=r"^/\S+$")


class ExecutionResult(BaseModel):
    """`denied=True` covers both "Docker is unavailable" and "the
    container failed to start": both are the same outcome from the
    caller's point of view (docs/threat-model.md: "If Docker is
    unavailable, or the container fails to start, deny and log")."""

    model_config = ConfigDict(extra="forbid")

    exit_code: int | None
    stdout: str
    stderr: str
    timed_out: bool
    denied: bool
    denial_reason: str | None = None
