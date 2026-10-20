from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from custody.catalog import Catalog, DataClass
from custody.policy import (
    ApprovalRequirement,
    Decision,
    Policy,
    PolicyEngine,
    Rule,
    ToolRequest,
    WhenClause,
    check,
    explain,
)


@pytest.fixture
def catalog(fixtures_dir: Path) -> Catalog:
    return Catalog.load(fixtures_dir / "catalog.yaml")


@pytest.fixture
def engine(fixtures_dir: Path) -> PolicyEngine:
    return PolicyEngine.load(fixtures_dir / "policy.yaml")


class TestEvaluateAllowAndApproval:
    def test_catalog_list_always_allowed(self, engine: PolicyEngine, catalog: Catalog) -> None:
        result = engine.evaluate(ToolRequest(tool="catalog.list"), catalog)
        assert result.decision == Decision.allow
        assert result.matched_rule_id == "catalog-list-ok"

    def test_deidentified_query_allowed(self, engine: PolicyEngine, catalog: Catalog) -> None:
        req = ToolRequest(tool="sql.query", datasets=["tumor_registry_deid"])
        result = engine.evaluate(req, catalog)
        assert result.decision == Decision.allow
        assert result.matched_rule_id == "deid-query-ok"
        assert result.data_class == DataClass.deidentified

    def test_identified_query_requires_approval(
        self, engine: PolicyEngine, catalog: Catalog
    ) -> None:
        req = ToolRequest(tool="sql.query", datasets=["tumor_registry_identified"])
        result = engine.evaluate(req, catalog)
        assert result.decision == Decision.require_approval
        assert result.matched_rule_id == "identified-needs-approval"
        assert result.approvals == ApprovalRequirement(count=1, roles=["data_steward"])

    def test_export_of_identified_requires_two_person_approval(
        self, engine: PolicyEngine, catalog: Catalog
    ) -> None:
        req = ToolRequest(tool="files.export", datasets=["tumor_registry_identified"])
        result = engine.evaluate(req, catalog)
        assert result.decision == Decision.require_approval
        assert result.matched_rule_id == "export-two-person"
        assert result.approvals is not None
        assert result.approvals.count == 2

    def test_mixed_sensitivity_datasets_use_the_more_restrictive_class(
        self, engine: PolicyEngine, catalog: Catalog
    ) -> None:
        """A request touching both a de-identified and an identified
        dataset is an identified request, the join is only as safe as
        its most sensitive input."""
        req = ToolRequest(
            tool="sql.query",
            datasets=["tumor_registry_deid", "tumor_registry_identified"],
        )
        result = engine.evaluate(req, catalog)
        assert result.data_class == DataClass.identified
        assert result.decision == Decision.require_approval


class TestDenyByDefaultPaths:
    """Every ambiguous path must resolve to deny. Each test below is one
    such path, named for what makes it ambiguous."""

    def test_unknown_tool_denies(self, engine: PolicyEngine, catalog: Catalog) -> None:
        result = engine.evaluate(ToolRequest(tool="nobody.registered.this"), catalog)
        assert result.decision == Decision.deny
        assert result.matched_rule_id is None
        assert "policy default" in result.reason

    def test_unlabeled_dataset_is_treated_as_identified(
        self, engine: PolicyEngine, catalog: Catalog
    ) -> None:
        """A dataset id not in the catalog classifies as `identified`
        (Catalog's own deny-by-default), which then flows into the
        policy engine as the most restrictive class."""
        req = ToolRequest(tool="sql.query", datasets=["nobody_cataloged_this"])
        result = engine.evaluate(req, catalog)
        assert result.data_class == DataClass.identified
        assert result.decision == Decision.require_approval  # the identified rule catches it

    def test_unlabeled_dataset_with_no_catching_rule_denies(self, catalog: Catalog) -> None:
        """If a policy has no rule at all for `identified`, the request
        denies rather than silently falling through to an allow rule
        meant for a different tool."""
        policy = Policy(
            rules=[
                Rule(
                    id="deid-only",
                    when=WhenClause(tool="sql.query", max_data_class=DataClass.deidentified),
                    decision=Decision.allow,
                )
            ],
            default=Decision.deny,
        )
        engine = PolicyEngine(policy)
        req = ToolRequest(tool="sql.query", datasets=["unlabeled"])
        result = engine.evaluate(req, catalog)
        assert result.decision == Decision.deny

    def test_egress_denied_even_for_an_otherwise_allowed_tool(
        self, engine: PolicyEngine, catalog: Catalog
    ) -> None:
        req = ToolRequest(tool="shell.run", egress=True)
        result = engine.evaluate(req, catalog)
        assert result.decision == Decision.deny
        assert result.matched_rule_id == "no-egress"

    def test_model_not_on_allowlist_denies(self, engine: PolicyEngine) -> None:
        routing = engine.check_model(DataClass.identified, "gpt-4o")
        assert routing.allowed is False
        assert routing.matched_pattern is None

    def test_data_class_with_no_allowlist_entry_denies_every_model(self) -> None:
        policy = Policy(rules=[], default=Decision.deny, model_allowlist={})
        engine = PolicyEngine(policy)
        routing = engine.check_model(DataClass.synthetic, "anything/at-all")
        assert routing.allowed is False
        assert "no model_allowlist is configured" in routing.reason

    def test_model_on_allowlist_is_allowed(self, engine: PolicyEngine) -> None:
        routing = engine.check_model(DataClass.identified, "ollama/llama3")
        assert routing.allowed is True
        assert routing.matched_pattern == "ollama/*"

    def test_policy_parse_error_raises(self, tmp_path: Path) -> None:
        bad = tmp_path / "policy.yaml"
        bad.write_text("not: [valid, policy, {shape")
        with pytest.raises(Exception):  # noqa: B017 - yaml.YAMLError, deliberately broad
            PolicyEngine.load(bad)


class TestPolicyValidation:
    """Policy authoring mistakes fail at load time, not at decision time."""

    def test_non_deny_default_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="deny-by-default"):
            Policy(rules=[], default=Decision.allow)

    def test_empty_when_clause_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="at least one field"):
            WhenClause()

    def test_min_greater_than_max_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="never match"):
            WhenClause(min_data_class=DataClass.identified, max_data_class=DataClass.synthetic)

    def test_require_approval_without_approvals_block_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="require_approval"):
            Rule(
                id="r1",
                when=WhenClause(tool="x"),
                decision=Decision.require_approval,
            )

    def test_approvals_block_on_a_non_approval_decision_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Rule(
                id="r1",
                when=WhenClause(tool="x"),
                decision=Decision.allow,
                approvals=ApprovalRequirement(count=1, roles=["data_steward"]),
            )

    def test_duplicate_rule_ids_rejected(self) -> None:
        rule = Rule(id="dupe", when=WhenClause(tool="x"), decision=Decision.deny)
        with pytest.raises(ValidationError, match="more than once"):
            Policy(rules=[rule, rule], default=Decision.deny)


class TestCliHelpers:
    def test_check_valid_policy_returns_no_errors(self, fixtures_dir: Path) -> None:
        assert check(fixtures_dir / "policy.yaml") == []

    def test_check_invalid_policy_returns_errors(self, tmp_path: Path) -> None:
        bad = tmp_path / "policy.yaml"
        bad.write_text("rules: []\ndefault: allow\n")
        errors = check(bad)
        assert len(errors) == 1
        assert "deny-by-default" in errors[0]

    def test_explain_reports_matched_rule_and_approvals(
        self, engine: PolicyEngine, catalog: Catalog
    ) -> None:
        req = ToolRequest(tool="files.export", datasets=["tumor_registry_identified"])
        text = explain(engine, req, catalog)
        assert "export-two-person" in text
        assert "require_approval" in text
        assert "approvals required: 2" in text


class TestCoverageEdges:
    def test_check_reports_invalid_yaml_syntax(self, tmp_path: Path) -> None:
        bad = tmp_path / "policy.yaml"
        bad.write_text("rules: [this is not: valid: yaml:")
        errors = check(bad)
        assert len(errors) == 1
        assert "invalid YAML" in errors[0]

    def test_policy_property_returns_loaded_policy(self, engine: PolicyEngine) -> None:
        assert engine.policy.default == Decision.deny

    def test_egress_false_does_not_trigger_the_egress_rule(
        self, engine: PolicyEngine, catalog: Catalog
    ) -> None:
        req = ToolRequest(tool="catalog.list", egress=False)
        result = engine.evaluate(req, catalog)
        assert result.matched_rule_id != "no-egress"
