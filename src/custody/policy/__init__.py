"""Policy engine. Policies are YAML, validated by Pydantic, readable by a
compliance reviewer. Evaluation is deterministic: first matching rule
wins, no match falls through to the policy's own (enforced-deny) default.
See docs/policy-reference.md for the YAML shape.
"""

from custody.policy.bundle import (
    PolicyBundleError,
    SignedPolicyBundle,
    bundle_path_for,
    sign_policy,
    verify_policy_bundle,
)
from custody.policy.engine import (
    PolicyBackend,
    PolicyEngine,
    PolicyResult,
    RoutingDecision,
    ToolRequest,
    check,
    check_model_allowlist,
    effective_data_class,
    explain,
)
from custody.policy.models import ApprovalRequirement, Decision, Policy, Rule, WhenClause

__all__ = [
    "ApprovalRequirement",
    "Decision",
    "Policy",
    "PolicyBackend",
    "PolicyBundleError",
    "PolicyEngine",
    "PolicyResult",
    "Rule",
    "RoutingDecision",
    "SignedPolicyBundle",
    "ToolRequest",
    "WhenClause",
    "bundle_path_for",
    "check",
    "check_model_allowlist",
    "effective_data_class",
    "explain",
    "sign_policy",
    "verify_policy_bundle",
]
