"""Model routing check.

Agents declare the model they are using via session metadata or a config
entry. This module enforces the per-data-class model_allowlist from the
loaded policy and logs the model identity on every decision it makes.

Read docs/threat-model.md T7 before treating this as stronger than it is:
Custody cannot see inside a model provider and only controls what data it
releases to a session that has declared a given model identity. It cannot
detect a model identity the agent misreports.

Planned surface:
    class ModelRouter:
        def check(
            self, data_class: DataClass, model_id: str, policy: PolicyEngine,
        ) -> RoutingDecision: ...

Not yet implemented.
"""

raise NotImplementedError("custody.routing is not yet implemented (v0.1 skeleton)")
