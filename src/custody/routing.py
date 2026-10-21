"""Model routing check: a thin, stateless wrapper around whichever
policy backend's `check_model`, kept as its own module so the gateway
can depend on "where does model routing happen" as a named thing
rather than reaching into the policy backend directly from the
tool-call path. `policy` is typed as `PolicyBackend`, not the concrete
`PolicyEngine`, so this works unchanged with
`custody.policy.opa_backend.OPAPolicyEngine` too.

Read docs/threat-model.md T7 before treating this as stronger than it is:
Custody cannot see inside a model provider and only controls what data it
releases to a session that has declared a given model identity. It
cannot detect a model identity the agent misreports.
"""

from __future__ import annotations

from custody.catalog import DataClass
from custody.policy import PolicyBackend, RoutingDecision


class ModelRouter:
    def check(self, data_class: DataClass, model_id: str, policy: PolicyBackend) -> RoutingDecision:
        return policy.check_model(data_class, model_id)
