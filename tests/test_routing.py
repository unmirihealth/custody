from __future__ import annotations

from custody.catalog import DataClass
from custody.policy import Decision, Policy, PolicyEngine
from custody.routing import ModelRouter


def _engine() -> PolicyEngine:
    policy = Policy(
        rules=[],
        default=Decision.deny,
        model_allowlist={
            DataClass.synthetic: ["*"],
            DataClass.identified: ["ollama/*"],
        },
    )
    return PolicyEngine(policy)


class TestModelRouter:
    def test_allowed_model_passes(self) -> None:
        router = ModelRouter()
        decision = router.check(DataClass.identified, "ollama/llama3", _engine())
        assert decision.allowed is True

    def test_disallowed_model_denied(self) -> None:
        router = ModelRouter()
        decision = router.check(DataClass.identified, "gpt-4o", _engine())
        assert decision.allowed is False

    def test_delegates_to_policy_engine_check_model(self) -> None:
        """ModelRouter adds no logic of its own, it's a named seam. This
        test exists so a future refactor that accidentally diverges the
        two gets caught."""
        router = ModelRouter()
        engine = _engine()
        assert router.check(
            DataClass.synthetic, "anything", engine
        ) == engine.check_model(DataClass.synthetic, "anything")
