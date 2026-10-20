"""Pydantic models for a loaded policy file. Kept separate from
engine.py so the shapes a compliance reviewer reads about in
docs/policy-reference.md map onto one small, readable module."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, model_validator

from custody.catalog import DataClass


class Decision(StrEnum):
    allow = "allow"
    deny = "deny"
    require_approval = "require_approval"


class WhenClause(BaseModel):
    """Conditions a request must satisfy for a rule to match. Every field
    present is ANDed together; an absent field is not checked at all (it
    does not mean "any value", it means this rule does not care about
    that dimension of the request).
    """

    model_config = ConfigDict(extra="forbid")

    tool: str | None = None
    min_data_class: DataClass | None = None
    max_data_class: DataClass | None = None
    egress: bool | None = None

    @model_validator(mode="after")
    def _at_least_one_condition(self) -> WhenClause:
        if (
            self.tool is None
            and self.min_data_class is None
            and self.max_data_class is None
            and self.egress is None
        ):
            raise ValueError(
                "a rule's `when` clause must constrain at least one field; "
                "an empty `when` would match every request, silently "
                "defeating every rule listed after it"
            )
        return self

    @model_validator(mode="after")
    def _min_le_max(self) -> WhenClause:
        if (
            self.min_data_class is not None
            and self.max_data_class is not None
            and self.min_data_class > self.max_data_class
        ):
            raise ValueError(
                f"min_data_class ({self.min_data_class}) is more restrictive than "
                f"max_data_class ({self.max_data_class}); this range can never match"
            )
        return self


class ApprovalRequirement(BaseModel):
    """How many approvers, of which roles, a `require_approval` decision
    needs before the broker will let the request proceed."""

    model_config = ConfigDict(extra="forbid")

    # min_length=1 is the whole guarantee here: an empty roles list could
    # never be satisfied by any approval. Not a hard requirement that
    # len(roles) >= count, a single role can satisfy a count > 1 if
    # multiple distinct people hold it.
    count: int = Field(ge=1)
    roles: list[str] = Field(min_length=1)


class Rule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    when: WhenClause
    decision: Decision
    approvals: ApprovalRequirement | None = None

    @model_validator(mode="after")
    def _approvals_match_decision(self) -> Rule:
        if self.decision == Decision.require_approval and self.approvals is None:
            raise ValueError(
                f"rule {self.id!r}: decision is require_approval but no "
                "`approvals` block is set"
            )
        if self.decision != Decision.require_approval and self.approvals is not None:
            raise ValueError(
                f"rule {self.id!r}: `approvals` is set but decision is "
                f"{self.decision!r}, not require_approval; this is almost "
                "certainly a mistake"
            )
        return self


class Policy(BaseModel):
    """The validated shape of a policy YAML file."""

    model_config = ConfigDict(extra="forbid")

    rules: list[Rule] = Field(default_factory=list)
    default: Decision
    model_allowlist: dict[DataClass, list[str]] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _default_must_be_deny(self) -> Policy:
        # "Deny by default" is a hard rule of this project, not a
        # convention a policy author can opt out of by setting
        # `default: allow`. Enforcing it here means every policy file
        # that loads at all has this guarantee, rather than depending on
        # every author reading the docs.
        if self.default != Decision.deny:
            raise ValueError(
                f"policy `default` must be \"deny\", got {self.default!r}. "
                "Custody enforces deny-by-default; an explicit allow or "
                "require_approval default is not supported."
            )
        return self

    @model_validator(mode="after")
    def _unique_rule_ids(self) -> Policy:
        seen: set[str] = set()
        for rule in self.rules:
            if rule.id in seen:
                raise ValueError(f"rule id {rule.id!r} is declared more than once")
            seen.add(rule.id)
        return self
