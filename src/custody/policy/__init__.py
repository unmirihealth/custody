"""Policy engine.

Policies are YAML, validated through Pydantic models, readable by a
compliance reviewer without a Python background. Evaluation is
deterministic: rules are checked in order, first match wins, and the
matched rule's id is recorded on every audit entry so a decision is
traceable back to the exact line that produced it. No match falls through
to the policy's own `default`, which custody.policy requires to be `deny`
at load time (a policy file that sets a non-deny default fails validation).

Also owns model routing: a `model_allowlist` keyed by data class, checked
against the model identity a session declares. A request carrying a data
class to a model outside its allowlist is denied the same way any other
policy violation is.

Planned surface:
    class Decision(StrEnum): allow, deny, require_approval
    class Rule(BaseModel): id, when, decision, approvals | None
    class Policy(BaseModel): rules, default
    class PolicyEngine:
        @classmethod
        def load(cls, path: Path) -> "PolicyEngine": ...
        def evaluate(self, request: ToolRequest) -> PolicyResult: ...
    # CLI-facing:
    def check(path: Path) -> list[ValidationError]: ...
    def explain(policy: PolicyEngine, request: ToolRequest) -> str: ...

Not yet implemented.
"""

raise NotImplementedError("custody.policy is not yet implemented (v0.1 skeleton)")
