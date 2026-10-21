"""OPAPolicyEngine: evaluates the exact same policy.yaml semantics as
`custody.policy.engine.PolicyEngine`, but by querying a real OPA (Open
Policy Agent) server instead of evaluating rules in this process. See
docs/opa-policy-backend.md for the full design rationale; the short
version:

- `policy.yaml` is parsed by the same Pydantic models as the local
  engine (`custody/policy/models.py`) -- nothing about how a
  deployment authors policy changes.
- The parsed `Policy` is converted to plain JSON and pushed into a
  running OPA server's Data API (`PUT /v1/data/policy_input`).
- `docker/opa/policy.rego` is a small, fixed Rego module (not
  generated per deployment) that reproduces the Python engine's exact
  first-match-wins algorithm against that pushed data.
- `evaluate()` computes the request's effective data class the same
  way `PolicyEngine` does (`custody.policy.engine.effective_data_class`,
  catalog-driven, not backend-driven), POSTs it to OPA's query
  endpoint, and translates the JSON result back into the same
  `PolicyResult` shape `PolicyEngine.evaluate()` returns.
- `check_model()` does NOT go through OPA: model routing is a simple,
  fast allowlist lookup (`custody.policy.engine.check_model_allowlist`),
  not a rule-matching decision, and routing it through a network call
  would add latency for no real benefit. Both backends share this one
  implementation.

This makes `OPAPolicyEngine` a structural match for
`custody.policy.engine.PolicyBackend`: `Gateway(policy=OPAPolicyEngine(...))`
works exactly like `Gateway(policy=PolicyEngine.load(...))`.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any

from custody.catalog import Catalog, DataClass
from custody.policy.engine import (
    PolicyResult,
    RoutingDecision,
    ToolRequest,
    check_model_allowlist,
    effective_data_class,
)
from custody.policy.models import ApprovalRequirement, Decision, Policy, Rule, WhenClause

_DEFAULT_TIMEOUT = 5.0


class OPABackendError(Exception):
    """OPA could not be reached, or returned something this module does
    not know how to interpret (an HTTP error, a response missing the
    expected `result` key, or a `decision` value that isn't one of
    Custody's own `Decision` enum members, which would mean the Rego
    module and this Python code have drifted out of sync)."""


def _http_put(url: str, payload: bytes, timeout: float) -> int:
    request = urllib.request.Request(url, data=payload, method="PUT")  # noqa: S310 - opa_url is operator-configured, not user input
    request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            return int(response.status)
    except urllib.error.HTTPError as exc:
        return exc.code
    except (urllib.error.URLError, OSError) as exc:
        # Connection refused, DNS failure, timeout: there is no HTTP
        # status to report, unlike HTTPError above. Translate to the
        # one error type this module raises rather than letting a
        # bare urllib exception escape.
        raise OPABackendError(f"could not reach OPA at {url}: {exc}") from exc


def _http_post(url: str, payload: bytes, timeout: float) -> tuple[int, bytes]:
    request = urllib.request.Request(url, data=payload, method="POST")  # noqa: S310 - see _http_put
    request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            return int(response.status), response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()
    except (urllib.error.URLError, OSError) as exc:
        raise OPABackendError(f"could not reach OPA at {url}: {exc}") from exc


def _when_to_opa(when: WhenClause) -> dict[str, Any]:
    """`min_data_class`/`max_data_class` become plain integer ranks
    (`DataClass.rank`): the Rego module compares ranks, not the
    four-way `DataClass` ordering custody.catalog defines in Python,
    to keep the fixed Rego module free of any Custody-specific enum
    knowledge beyond "it's an ordered integer".
    """
    out: dict[str, Any] = {}
    if when.tool is not None:
        out["tool"] = when.tool
    if when.min_data_class is not None:
        out["min_rank"] = when.min_data_class.rank
    if when.max_data_class is not None:
        out["max_rank"] = when.max_data_class.rank
    if when.egress is not None:
        out["egress"] = when.egress
    return out


def _rule_to_opa(rule: Rule) -> dict[str, Any]:
    out: dict[str, Any] = {
        "id": rule.id,
        "when": _when_to_opa(rule.when),
        "decision": rule.decision.value,
    }
    if rule.approvals is not None:
        out["approvals"] = {"count": rule.approvals.count, "roles": rule.approvals.roles}
    return out


def policy_to_opa_data(policy: Policy) -> dict[str, Any]:
    """The JSON pushed to OPA's `policy_input` data path. Exposed as a
    free function (not just an internal detail) so a deployment can
    inspect exactly what would be uploaded, e.g. for a `custody policy
    explain`-style debugging tool against the OPA backend."""
    return {
        "default": policy.default.value,
        "rules": [_rule_to_opa(r) for r in policy.rules],
    }


class OPAPolicyEngine:
    """Construct from an already-loaded `Policy` (e.g.
    `PolicyEngine.load(path).policy` or `PolicyEngine.load_verified(...)
    .policy`, reusing the exact same YAML parsing and validation, and a
    running OPA server's base URL (e.g. `http://localhost:8181`, see
    `docker/opa.Dockerfile`). Pushes the policy to OPA once, at
    construction time; call `push_policy()` again after loading a
    changed policy.yaml to update the same running server rather than
    restarting it.
    """

    def __init__(
        self,
        policy: Policy,
        opa_url: str,
        *,
        timeout: float = _DEFAULT_TIMEOUT,
        put: Callable[[str, bytes, float], int] = _http_put,
        post: Callable[[str, bytes, float], tuple[int, bytes]] = _http_post,
    ) -> None:
        self._policy = policy
        self._opa_url = opa_url.rstrip("/")
        self._timeout = timeout
        self._put = put
        self._post = post
        self.push_policy()

    @property
    def policy(self) -> Policy:
        return self._policy

    def push_policy(self) -> None:
        """Upload the current `Policy` to OPA's Data API. Called once
        automatically at construction; call again after replacing
        `self._policy` (there is no public setter -- construct a new
        `OPAPolicyEngine` instead, the same "read-only after load"
        posture `PolicyEngine` has)."""
        body = json.dumps(policy_to_opa_data(self._policy)).encode("utf-8")
        status = self._put(f"{self._opa_url}/v1/data/policy_input", body, self._timeout)
        if status not in (200, 204):
            raise OPABackendError(f"failed to push policy to OPA: HTTP {status}")

    def evaluate(self, request: ToolRequest, catalog: Catalog) -> PolicyResult:
        data_class = effective_data_class(request, catalog)
        input_payload = {
            "tool": request.tool,
            "data_class_rank": data_class.rank,
            "egress": request.egress,
        }
        body = json.dumps({"input": input_payload}).encode("utf-8")
        status, response_body = self._post(
            f"{self._opa_url}/v1/data/custody/decision/result", body, self._timeout
        )
        if status != 200:
            raise OPABackendError(f"OPA query failed: HTTP {status}: {response_body!r}")

        try:
            parsed = json.loads(response_body)
            result = parsed["result"]
            decision = Decision(result["decision"])
            matched_rule_id = result.get("matched_rule_id")
            approvals = (
                ApprovalRequirement.model_validate(result["approvals"])
                if result.get("approvals")
                else None
            )
        except (json.JSONDecodeError, KeyError, ValueError) as exc:
            raise OPABackendError(
                f"could not interpret OPA's response: {response_body!r}"
            ) from exc

        reason = (
            f"matched rule {matched_rule_id!r}"
            if matched_rule_id
            else "no rule matched; fell through to the policy default (deny)"
        )
        return PolicyResult(
            decision=decision,
            matched_rule_id=matched_rule_id,
            data_class=data_class,
            reason=reason,
            approvals=approvals,
        )

    def check_model(self, data_class: DataClass, model: str) -> RoutingDecision:
        """Does not call OPA, see this module's docstring for why."""
        return check_model_allowlist(self._policy, data_class, model)


__all__ = ["OPABackendError", "OPAPolicyEngine", "policy_to_opa_data"]
