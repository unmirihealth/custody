# Policy reference

A policy file is YAML, validated by `custody.policy.models.Policy`
(Pydantic) when loaded. `custody policy check <file>` validates one
without building a gateway from it.

## Shape

```yaml
rules:
  - id: deid-query-ok
    when: { tool: sql.query, max_data_class: deidentified }
    decision: allow

  - id: identified-needs-approval
    when: { tool: sql.query, min_data_class: identified }
    decision: require_approval
    approvals: { count: 1, roles: [data_steward] }

  - id: export-two-person
    when: { tool: files.export, min_data_class: limited_data_set }
    decision: require_approval
    approvals: { count: 2, roles: [data_steward, privacy_officer] }

  - id: no-egress
    when: { egress: true }
    decision: deny

default: deny

model_allowlist:
  synthetic: ["*"]
  deidentified: ["*"]
  limited_data_set: ["ollama/*", "bedrock-baa/*"]
  identified: ["ollama/*", "bedrock-baa/*"]
```

## Evaluation

Rules are checked **in order**. The first rule whose `when` matches the
request wins; nothing after it is considered. If no rule matches, the
request resolves to `default`, which the loader requires to be
`"deny"` -- a policy with any other default fails to load, this is not
a convention an author can override.

Every decision records which rule (or "policy default") produced it;
that id is what shows up in the audit log's `decision` entry and in
`custody policy explain`'s output.

## `when` fields

| Field | Type | Matches when... |
|---|---|---|
| `tool` | string | the request's tool name equals this exactly |
| `min_data_class` | one of `synthetic`, `deidentified`, `limited_data_set`, `identified` | the request's effective data class is this class or more restrictive |
| `max_data_class` | same enum | the request's effective data class is this class or less restrictive |
| `egress` | bool | the request's `egress` flag equals this |

A field left out of `when` is not checked at all, it does not mean
"any value". A `when` block must set at least one field; an empty
`when` would match every request and silently defeat every rule listed
after it, so the loader rejects it.

**The request's effective data class** is the most restrictive class
among every dataset the request touches (`datasets: []` on the
request, or a dataset id the catalog has never heard of, both count as
`identified`, the most restrictive class, not the least). A request
touching both a `deidentified` and an `identified` dataset is an
`identified` request.

## `decision`

- `allow` -- the gateway proceeds immediately.
- `deny` -- the gateway returns denied immediately, nothing runs.
- `require_approval` -- the gateway creates a pending approval (see
  below) and, for an MCP tool call, blocks until it resolves or
  expires (timeout = deny). Requires an `approvals` block.

## `approvals` (only on `require_approval` rules)

```yaml
approvals: { count: 2, roles: [data_steward, privacy_officer] }
```

- `count`: how many **distinct** approvers must approve.
- `roles`: which roles (from `principals.yaml`) are eligible. An
  approver needs at least one role in this list, `count` does not mean
  "one approver per listed role", just "this many distinct people
  holding an eligible role."

A single `deny` from any eligible approver resolves the whole approval
to denied immediately (fail-fast), it does not wait for whatever a
second approver might have said. An approver can never be the same
principal as the request's own requester (`SelfApprovalError`), and
the same approver cannot decide twice on one approval
(`DuplicateApproverError`, enforced at the database level).

## `model_allowlist`

```yaml
model_allowlist:
  identified: ["ollama/*", "bedrock-baa/*"]
```

Keyed by data class, each value a list of glob patterns
(`fnmatch`-style) matched against a model identity the session
declares. **A data class with no entry denies every model for that
class**, not just unlisted ones, same deny-by-default posture as
everything else. Model routing runs independently of the tool/data
policy decision: a disallowed model denies the request before an
approval wait would even start, see `custody/gateway.py`.

## `custody policy explain`

```bash
custody policy explain policy.yaml catalog.yaml sql.query \
  --dataset tumor_registry_identified
```

Prints the effective data class, the decision, which rule matched (or
"policy default"), the reason, and (for `require_approval`) how many
approvers of which roles it needs. Useful for checking a policy change
against a specific request before it's live.
