"""Deterministic policy evaluation: first matching rule wins, no match
falls through to the policy's own (always-deny) default. See
docs/policy-reference.md for the YAML shape this reads.
"""

from __future__ import annotations

import fnmatch
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict

from custody.catalog import Catalog, DataClass
from custody.policy.models import ApprovalRequirement, Decision, Policy, Rule


class ToolRequest(BaseModel):
    """What the gateway asks the policy engine to decide on. `datasets`
    is every dataset id a tool call reads or writes; the request's
    effective data class is the MOST restrictive class among them (a
    join across a de-identified table and an identified one is an
    identified request), computed by `PolicyEngine.evaluate`, not here,
    since that computation needs the catalog.
    """

    model_config = ConfigDict(extra="forbid")

    tool: str
    datasets: list[str] = []
    egress: bool = False
    model: str | None = None


class PolicyResult(BaseModel):
    """The decision, which rule produced it (None for the policy's own
    default), and a one-line human-readable reason. This whole object is
    what gets written into the audit log's decision entry."""

    model_config = ConfigDict(extra="forbid")

    decision: Decision
    matched_rule_id: str | None
    data_class: DataClass
    reason: str
    approvals: ApprovalRequirement | None = None


class RoutingDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    allowed: bool
    data_class: DataClass
    model: str
    matched_pattern: str | None
    reason: str


def _when_matches(rule: Rule, request: ToolRequest, data_class: DataClass) -> bool:
    w = rule.when
    if w.tool is not None and w.tool != request.tool:
        return False
    if w.min_data_class is not None and data_class < w.min_data_class:
        return False
    if w.max_data_class is not None and data_class > w.max_data_class:
        return False
    if w.egress is not None and w.egress != request.egress:
        return False
    return True


class PolicyEngine:
    """Load with `PolicyEngine.load(path)`. Evaluate with `.evaluate()`.
    Both are read-only after load; a policy change requires a new load,
    there is no in-place mutation of a loaded engine."""

    def __init__(self, policy: Policy) -> None:
        self._policy = policy

    @classmethod
    def load(cls, path: Path) -> PolicyEngine:
        raw = yaml.safe_load(path.read_text()) or {}
        return cls(Policy.model_validate(raw))

    @property
    def policy(self) -> Policy:
        return self._policy

    def _effective_data_class(self, request: ToolRequest, catalog: Catalog) -> DataClass:
        if not request.datasets:
            # No dataset named at all: deny-by-default treats this the
            # same as touching the most restrictive class, not the
            # least. A rule that should apply regardless of data class
            # (catalog.list, approvals.status) constrains on `tool`
            # alone and never looks at this value.
            return DataClass.identified
        return max(catalog.classify(d) for d in request.datasets)

    def evaluate(self, request: ToolRequest, catalog: Catalog) -> PolicyResult:
        data_class = self._effective_data_class(request, catalog)

        for rule in self._policy.rules:
            if _when_matches(rule, request, data_class):
                return PolicyResult(
                    decision=rule.decision,
                    matched_rule_id=rule.id,
                    data_class=data_class,
                    reason=f"matched rule {rule.id!r}",
                    approvals=rule.approvals,
                )

        return PolicyResult(
            decision=self._policy.default,
            matched_rule_id=None,
            data_class=data_class,
            reason="no rule matched; fell through to the policy default (deny)",
        )

    def check_model(self, data_class: DataClass, model: str) -> RoutingDecision:
        """Is `model` allowed to see a request of this data class.

        A data class with no entry in `model_allowlist` denies every
        model, not just unlisted ones: an allowlist that never mentions
        `identified` is not "no restriction for identified", it is "no
        model is on the identified allowlist yet". This is the same
        deny-by-default posture as everything else in this module.
        """
        patterns = self._policy.model_allowlist.get(data_class, [])
        for pattern in patterns:
            if fnmatch.fnmatchcase(model, pattern):
                return RoutingDecision(
                    allowed=True,
                    data_class=data_class,
                    model=model,
                    matched_pattern=pattern,
                    reason=(
                        f"model {model!r} matched allowlist pattern "
                        f"{pattern!r} for {data_class}"
                    ),
                )
        return RoutingDecision(
            allowed=False,
            data_class=data_class,
            model=model,
            matched_pattern=None,
            reason=(
                f"model {model!r} is not on the model_allowlist for {data_class}"
                if patterns
                else f"no model_allowlist is configured for {data_class}; deny by default"
            ),
        )


def explain(engine: PolicyEngine, request: ToolRequest, catalog: Catalog) -> str:
    """Human-readable form of `evaluate()`'s result, for `custody policy
    explain`."""
    result = engine.evaluate(request, catalog)
    lines = [
        f"tool: {request.tool}",
        f"datasets: {request.datasets or '(none)'}",
        f"effective data class: {result.data_class}",
        f"decision: {result.decision}",
        f"rule: {result.matched_rule_id or '(policy default)'}",
        f"reason: {result.reason}",
    ]
    if result.approvals is not None:
        lines.append(
            f"approvals required: {result.approvals.count} of {result.approvals.roles}"
        )
    return "\n".join(lines)


def check(path: Path) -> list[str]:
    """Validate a policy file without constructing an engine from it.
    Returns a list of human-readable problems; an empty list means the
    file is valid. Used by `custody policy check`.
    """
    try:
        raw = yaml.safe_load(path.read_text()) or {}
    except yaml.YAMLError as exc:
        return [f"invalid YAML: {exc}"]

    try:
        Policy.model_validate(raw)
    except Exception as exc:  # pydantic.ValidationError, deliberately broad for the CLI
        return [str(exc)]
    return []
