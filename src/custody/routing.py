"""Model routing check: a thin, stateless wrapper around
`PolicyEngine.check_model`, kept as its own module so the gateway can
depend on "where does model routing happen" as a named thing rather than
reaching into the policy engine directly from the tool-call path.

Read docs/threat-model.md T7 before treating this as stronger than it is:
Custody cannot see inside a model provider and only controls what data it
releases to a session that has declared a given model identity. It
cannot detect a model identity the agent misreports.
"""

from __future__ import annotations

from custody.catalog import DataClass
from custody.policy import PolicyEngine, RoutingDecision


class ModelRouter:
    def check(self, data_class: DataClass, model_id: str, policy: PolicyEngine) -> RoutingDecision:
        return policy.check_model(data_class, model_id)
