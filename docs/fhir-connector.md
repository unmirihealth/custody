# FHIR connector

`fhir.search` is a read-only tool for searching a FHIR server,
policy-checked and audited exactly like every other built-in tool. It
is one dataset `source` kind alongside the original file-backed kind
(`custody.catalog.SourceKind`); the same `catalog.yaml`, the same
policy rules, the same approval gates, the same audit log all apply to
a FHIR-backed dataset without any changes to `custody.policy` or
`custody.gateway`.

## Scope: FHIR only, not OMOP CDM

ROADMAP.md tracked "FHIR and OMOP connectors" as one combined item.
This is the FHIR half only. OMOP CDM (a relational common data model
distinct from FHIR's REST/resource model) remains unbuilt and
deferred, split out explicitly rather than implied done.

## Catalog entry shape

```yaml
datasets:
  - id: onco_fhir
    data_class: limited_data_set
    source: fhir
    base_url: https://fhir.example.org/fhir
    resource_types: [Condition, Observation]
```

`source: fhir` entries have no `path`/`format` (those are `source:
file`-only, the original, still-default kind); they have `base_url`
and `resource_types` instead, both required. `resource_types` is an
**allowlist, deny-by-default**: an empty list denies every resource
type, not "any type" -- same posture as `model_allowlist`'s empty-entry
handling in `custody.policy.engine.check_model_allowlist`. A request
for a type not on the list is denied before any network call happens.

## Why this tool doesn't use `custody.sandbox`

`sql.query` and `shell.run` run inside a locked-down Docker container
because they execute arbitrary code or arbitrary SQL an agent supplies.
`fhir.search` does neither: it issues one bounded `GET` against a
single pre-configured, catalog-declared base URL and an allowlisted
resource type, with FHIR search parameters passed through verbatim (not
validated against FHIR's own search grammar -- a malformed parameter
just gets whatever error the FHIR server itself returns, the same "the
real validation lives one layer down" posture `sql.query` takes with
its own query string). That is the same category of "direct, narrow,
policy-gated network call" as the webhook notifier
(`custody/approvals/notifier.py`) and the OPA policy backend
(`custody/policy/opa_backend.py`), both of which also call out via
stdlib `urllib` directly rather than through the sandbox. No new
dependency, same as those two.

## What is and is not enforced

- **Policy and approval gates, in full.** `fhir.search` goes through
  `Gateway.authorize("fhir.search", datasets=[source_id])` exactly
  like every other tool; a `source: fhir` entry's `data_class`
  participates in policy rules, approval requirements, and model
  routing identically to a file-backed one.
- **Read-only.** The tool only ever constructs a `GET`; there is no
  code path to a FHIR `POST`/`PUT`/`DELETE`.
- **Resource-type allowlisting**, described above.
- **Result count is capped** at 100 per call (`_count` is clamped, not
  merely defaulted), so a call can't ask for an unbounded page.
- **Audit entries carry a count, never resource content.** The
  `result` audit entry records `result_count` only
  (docs/threat-model.md T6); a FHIR `Patient` or `Condition` resource
  is exactly the shape of content that must never appear in an audit
  payload.
- **The output guard's small-cell suppression does NOT apply here.**
  `sql.query`'s guard only engages for a result shaped like a `GROUP
  BY` aggregate; a FHIR search returns row-level resources, the same
  "approval gate controls row-level access, not the output guard"
  posture `sql.query` already documents for its own non-aggregate
  results.

## Testing

`tests/test_fhir_tool.py` has two layers:

- **Unit tests** (`TestFhirSearchUnit`, no Docker needed): every policy
  and error-handling branch the tool itself owns, using an injected
  fake HTTP `get` callable the same dependency-injection pattern as
  the webhook notifier and the OPA backend's tests -- allowlist
  enforcement, a non-FHIR dataset, a non-200 status, malformed JSON, a
  non-Bundle response, a connection failure, count clamping, and the
  audit-payload-never-carries-content guarantee.
- **Real-server integration tests** (`TestFhirSearchAgainstRealServer`,
  against a real `hapiproject/hapi` container, not a mock or a public
  test server): creates a synthetic `Patient` and `Condition` via FHIR
  `PUT`/`POST`, then confirms `fhir_search` actually finds it, and
  confirms a deny-everything policy actually blocks the same call --
  proving the tool is really gated by `Gateway.authorize`, not
  bypassing it.

A real HAPI FHIR JPA server's search index lags writes by a few
seconds (confirmed while building this: a search run immediately after
a create returns `total: 0`, correct only a handful of seconds later).
The integration test polls for this rather than asserting on the first
result, so it is not flaky, just slower than a unit test
(`_search_count_eventually`, capped at 30s).

A locally-run container was chosen over a public test server (e.g.
`https://hapi.fhir.org/baseR4`) specifically so these tests, and this
project's CI, don't depend on an external service's uptime, rate
limits, or shared-state cleanliness between unrelated test runs.

## No real patient data

Every example, fixture, and test resource here is synthetic (ids
containing `synthetic`, invented SNOMED codes attached to invented
patients, the same `CONTRIBUTING.md` rule everything else in this
project follows). A FHIR server a real deployment points this
connector at is where actual PHI would flow; that server's own
compliance posture (BAA, access controls, logging) is that
deployment's responsibility, not something this connector adds on top.
