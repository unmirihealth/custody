
# The OPA-side half of custody.policy.opa_backend.OPAPolicyEngine.
#
# This module does NOT encode any specific deployment's policy.yaml;
# it is a fixed, generic evaluator that reproduces
# custody.policy.engine.PolicyEngine's exact algorithm (first-match-
# wins over an ordered rule list, falling through to a deny-by-default
# default) against whatever rules are pushed into OPA's runtime data at
# `data.policy_input`. A deployment's actual policy.yaml is parsed by
# the same Pydantic models as the local engine (custody/policy/models.py)
# and uploaded as this plain data, not compiled into Rego -- see
# custody/policy/opa_backend.py and docs/opa-policy-backend.md for why.
#
# `data.policy_input` is deliberately NOT nested under this module's
# own package path (`custody.decision`): OPA merges rule-derived
# documents and pushed data into one global `data` tree, and a data
# document living under the same path as the rules that read it
# produces a recursive-rule error, not a clean error at query time.
package custody.decision

import rego.v1

default_decision := object.get(data.policy_input, "default", "deny")

when_matches(when) if {
	tool_ok(when)
	min_ok(when)
	max_ok(when)
	egress_ok(when)
}

tool_ok(when) if {
	not "tool" in object.keys(when)
}

tool_ok(when) if {
	when.tool == input.tool
}

min_ok(when) if {
	not "min_rank" in object.keys(when)
}

min_ok(when) if {
	input.data_class_rank >= when.min_rank
}

max_ok(when) if {
	not "max_rank" in object.keys(when)
}

max_ok(when) if {
	input.data_class_rank <= when.max_rank
}

egress_ok(when) if {
	not "egress" in object.keys(when)
}

egress_ok(when) if {
	when.egress == input.egress
}

matched_indices contains i if {
	some i
	rule := data.policy_input.rules[i]
	when_matches(rule.when)
}

first_matched_index := min(matched_indices) if {
	count(matched_indices) > 0
}

result := {
	"decision": data.policy_input.rules[first_matched_index].decision,
	"matched_rule_id": data.policy_input.rules[first_matched_index].id,
	"approvals": object.get(data.policy_input.rules[first_matched_index], "approvals", null),
} if {
	first_matched_index
} else := {
	"decision": default_decision,
	"matched_rule_id": null,
	"approvals": null,
}
