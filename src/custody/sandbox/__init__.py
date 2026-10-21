"""Sandbox executor. Runs shell commands and Python scripts in a
locked-down Docker container: non-root, no network by default,
read-only root filesystem, every capability dropped, resource limits,
only explicitly-allowed datasets mounted and always read-only. If Docker
is unavailable or the container fails to start, that resolves to deny,
the same as any other policy denial. See docs/threat-model.md T2 and T9.

When `SandboxConfig.egress_allowlist` is set, an `allow_egress=True`
run is scoped through `custody.sandbox.egress_proxy.EgressAllowlistProxy`
rather than opened broadly; see that module's docstring.
"""

from custody.sandbox.egress_proxy import (
    DEFAULT_EGRESS_PROXY_IMAGE,
    EgressAllowlistProxy,
    EgressProxyHandle,
)
from custody.sandbox.executor import SandboxExecutor
from custody.sandbox.models import DatasetMount, ExecutionResult, SandboxConfig

__all__ = [
    "DEFAULT_EGRESS_PROXY_IMAGE",
    "DatasetMount",
    "EgressAllowlistProxy",
    "EgressProxyHandle",
    "ExecutionResult",
    "SandboxConfig",
    "SandboxExecutor",
]
