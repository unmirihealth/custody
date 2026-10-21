"""The shape every built-in tool returns. Deliberately one shared shape
(MCP tool functions return this, serialized), rather than six different
ad hoc result types.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict


class ToolResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    denied: bool
    reason: str
    data: Any = None
