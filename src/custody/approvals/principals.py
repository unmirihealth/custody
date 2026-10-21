"""Approver identity and roles, loaded from a local principals.yaml.

v0.1 has no SSO/OIDC integration (ROADMAP.md): an approver's identity is
whatever string they identify themselves with (the CLI, the web UI's
startup-token-gated session), and their roles are whatever this file
says. The strength of every approval-gate guarantee in this project is
only as strong as how this file is managed and who can write to it, that
caveat belongs here, not buried in the broker.
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field


class Principal(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    roles: list[str] = Field(min_length=1)


class _PrincipalsFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    principals: list[Principal] = Field(default_factory=list)


class PrincipalDirectory:
    def __init__(self, principals: dict[str, Principal]) -> None:
        self._principals = principals

    @classmethod
    def load(cls, path: Path) -> PrincipalDirectory:
        raw = yaml.safe_load(path.read_text()) or {}
        parsed = _PrincipalsFile.model_validate(raw)
        by_id: dict[str, Principal] = {}
        for p in parsed.principals:
            if p.id in by_id:
                raise ValueError(f"principal {p.id!r} is declared more than once")
            by_id[p.id] = p
        return cls(by_id)

    @classmethod
    def empty(cls) -> PrincipalDirectory:
        return cls({})

    def roles_of(self, principal_id: str) -> list[str]:
        """Roles for `principal_id`, or an empty list if the directory
        has never heard of them. An unknown principal holds no roles,
        not "any role" -- deny by default."""
        p = self._principals.get(principal_id)
        return list(p.roles) if p is not None else []

    def has_any_role(self, principal_id: str, roles: list[str]) -> bool:
        held = set(self.roles_of(principal_id))
        return bool(held.intersection(roles))
