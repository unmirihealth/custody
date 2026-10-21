"""Pydantic models for the approval broker. See broker.py for the state
machine these feed into.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class ApprovalStatus(StrEnum):
    pending = "pending"
    approved = "approved"
    denied = "denied"
    expired = "expired"  # timeout reached with no decision: treated as deny


class ApprovalSummary(BaseModel):
    """What a human approver sees. Deliberately a small, explicit set of
    fields rather than an open dict: this is the one place in the whole
    project where it would be easiest to accidentally pass through raw
    PHI "because it's useful for the approver to see," so the shape is
    closed (docs/threat-model.md T6).
    """

    model_config = ConfigDict(extra="forbid")

    tool: str
    datasets: list[str] = Field(default_factory=list)
    data_class: str
    matched_rule_id: str | None = None


class PendingApproval(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    requester: str
    rule_id: str
    summary: ApprovalSummary
    required_count: int
    required_roles: list[str]
    created_at: datetime
    expires_at: datetime
    status: ApprovalStatus


class ApprovalDecision(BaseModel):
    model_config = ConfigDict(frozen=True)

    approval_id: str
    approver: str
    approve: bool
    reason: str
    decided_at: datetime
