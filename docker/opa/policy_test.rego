
# OPA's own test runner (`opa test docker/opa/`), independent of the
# Python test suite in tests/test_opa_backend.py: this file proves the
# Rego module itself is correct in isolation, the Python tests prove
# OPAPolicyEngine talks to a real running OPA server correctly. CI runs
# both (see .github/workflows/ci.yml).
package custody.decision_test

import data.custody.decision
import rego.v1

mock_rules := {
	"default": "deny",
	"rules": [
		{"id": "catalog-list-ok", "when": {"tool": "catalog.list"}, "decision": "allow"},
		{"id": "deid-ok", "when": {"max_rank": 1}, "decision": "allow"},
		{
			"id": "identified-needs-approval",
			"when": {"min_rank": 3},
			"decision": "require_approval",
			"approvals": {"count": 1, "roles": ["data_steward"]},
		},
		{"id": "no-egress", "when": {"egress": true}, "decision": "deny"},
	],
}

test_tool_match_wins_first if {
	decision.result == {
		"decision": "allow",
		"matched_rule_id": "catalog-list-ok",
		"approvals": null,
	} with data.policy_input as mock_rules
		with input as {"tool": "catalog.list", "data_class_rank": 3, "egress": false}
}

test_max_rank_matches_deidentified_and_below if {
	decision.result == {
		"decision": "allow",
		"matched_rule_id": "deid-ok",
		"approvals": null,
	} with data.policy_input as mock_rules
		with input as {"tool": "sql.query", "data_class_rank": 1, "egress": false}
}

test_min_rank_requires_approval_for_identified if {
	decision.result == {
		"decision": "require_approval",
		"matched_rule_id": "identified-needs-approval",
		"approvals": {"count": 1, "roles": ["data_steward"]},
	} with data.policy_input as mock_rules
		with input as {"tool": "sql.query", "data_class_rank": 3, "egress": false}
}

test_rule_order_beats_a_later_more_specific_rule if {
	# "deid-ok" (index 1) matches before "no-egress" (index 3) is ever
	# considered, even though this request has egress=true -- the same
	# ordering-dependent behavior custody.policy.engine.PolicyEngine has
	# (first match wins, full stop), not a bug in either evaluator.
	decision.result == {
		"decision": "allow",
		"matched_rule_id": "deid-ok",
		"approvals": null,
	} with data.policy_input as mock_rules
		with input as {"tool": "sql.query", "data_class_rank": 1, "egress": true}
}

test_no_match_falls_through_to_default_deny if {
	rules_without_a_catchall := {
		"default": "deny",
		"rules": [{"id": "catalog-list-ok", "when": {"tool": "catalog.list"}, "decision": "allow"}],
	}
	decision.result == {
		"decision": "deny",
		"matched_rule_id": null,
		"approvals": null,
	} with data.policy_input as rules_without_a_catchall
		with input as {"tool": "sql.query", "data_class_rank": 3, "egress": false}
}

test_egress_rule_blocks_when_nothing_earlier_matches if {
	rules_with_only_egress_and_catalog := {
		"default": "deny",
		"rules": [
			{"id": "catalog-list-ok", "when": {"tool": "catalog.list"}, "decision": "allow"},
			{"id": "no-egress", "when": {"egress": true}, "decision": "deny"},
		],
	}
	decision.result == {
		"decision": "deny",
		"matched_rule_id": "no-egress",
		"approvals": null,
	} with data.policy_input as rules_with_only_egress_and_catalog
		with input as {"tool": "shell.run", "data_class_rank": 0, "egress": true}
}
