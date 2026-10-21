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

## Alternative backend: OPA

Everything above describes `custody.policy.PolicyEngine`'s evaluation,
the default. `custody.policy.opa_backend.OPAPolicyEngine` evaluates the
exact same `policy.yaml` (same loader, same Pydantic validation, same
first-match-wins semantics) by querying a real OPA server instead of
evaluating rules in this process. See docs/opa-policy-backend.md for
when you'd want that and how to wire it into a `Gateway`.

## Signed policy bundles

A policy file determines every decision in this document. Someone
reviewed a specific `policy.yaml` and approved it; a signed bundle
lets that approval be checked later, mechanically, instead of by a
manual byte diff against a copy the reviewer kept themselves.

```bash
# After a compliance review, sign the exact file that was reviewed.
custody policy sign policy.yaml --key .custody/signing_key.pem
# wrote policy.yaml.sig.json
# policy sha256: 3f9a...
# signed by public key: a1c4...

# Later (deploy time, CI, or an ad hoc check): confirm it still matches.
custody policy verify policy.yaml
# OK: policy.yaml matches the bundle signed 2026-10-21T00:00:00+00:00
# by public key a1c4...
```

`custody policy sign` writes `<file>.sig.json` next to the policy file
by default (`--out` to choose a different path). The bundle records
the policy file's exact SHA-256 (over the bytes on disk, not a
parsed/re-serialized form -- a whitespace-only edit invalidates it),
when it was signed, and an Ed25519 signature over those two fields.
Reuses the same signing key machinery as audit checkpoints
(`custody.audit.keys`, see docs/audit-log.md); a deployment can share
one key for both, or keep them separate, `custody policy sign` takes
whatever Ed25519 PEM you point it at.

`custody policy verify` fails (exit 1) if the policy file has changed
since signing, or if the bundle's signature doesn't verify against its
own embedded public key. It does **not** check the policy's own
contents are sane, run `custody policy check` for that.

To load a policy only when a valid bundle covers it (skip the loader
if someone swapped in an unsigned or modified file), use
`PolicyEngine.load_verified(path)` in place of `PolicyEngine.load(path)`
in your own integration code. `build_gateway()` in `mcp_server.py`
still uses plain `load()` by default in v0.1; wiring `load_verified`
into `custody serve` itself (behind an opt-in flag) is tracked in
ROADMAP.md.

This is a different guarantee from the audit log's hash chain: that
chain proves what happened was recorded faithfully (see
docs/audit-log.md). A policy bundle proves what's about to happen is
governed by a file someone actually reviewed, checked once at load
time, not continuously, and it says nothing about files signed on a
machine or key you don't trust, trust in the public key itself is
still established out of band (e.g. check it into a second,
independently-reviewed channel, or compare it to a value a compliance
reviewer read out loud).
