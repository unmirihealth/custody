"""Everything a built-in tool needs: the gateway to authorize through,
the sandbox to execute in, the catalog to resolve dataset paths from,
the output guard, and the session's scratch workspace. A plain dataclass,
not a pydantic model: this holds live connections (a Docker client, a
SQLite connection, an open audit log), not serializable data.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from custody.catalog import Catalog
from custody.gateway import Gateway
from custody.guard import OutputGuard
from custody.sandbox import SandboxExecutor


@dataclass
class ToolContext:
    gateway: Gateway
    sandbox: SandboxExecutor
    catalog: Catalog
    guard: OutputGuard
    workspace_dir: Path
    sql_image: str = "custody-sandbox:duckdb"
