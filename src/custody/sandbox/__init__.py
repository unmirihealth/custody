"""Sandbox executor. Runs shell commands and Python scripts in a
locked-down Docker container: non-root, no network by default,
read-only root filesystem, every capability dropped, resource limits,
only explicitly-allowed datasets mounted and always read-only. If Docker
is unavailable or the container fails to start, that resolves to deny,
the same as any other policy denial. See docs/threat-model.md T2 and T9.
"""

from custody.sandbox.executor import SandboxExecutor
from custody.sandbox.models import DatasetMount, ExecutionResult, SandboxConfig

__all__ = ["DatasetMount", "ExecutionResult", "SandboxConfig", "SandboxExecutor"]
