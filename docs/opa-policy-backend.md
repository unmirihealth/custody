# OPA policy backend

`custody.policy.opa_backend.OPAPolicyEngine` is a second way to
evaluate a policy, alongside the default `custody.policy.PolicyEngine`.
It is not a different policy *format*: the same `policy.yaml`, parsed
by the same Pydantic models (`custody/policy/models.py`) docs
/policy-reference.md describes, works with either backend. What
changes is where the first-match-wins evaluation actually happens: in
this process (`PolicyEngine`) or inside a real running
[Open Policy Agent](https://www.openpolicyagent.org/) server
(`OPAPolicyEngine`).

## Why reuse policy.yaml instead of asking authors to write Rego

ROADMAP.md tracked "OPA/Cedar policy backends" as one item. OPA's
native policy language is Rego, and a literal reading of that roadmap
line might suggest Custody should let a deployment author policy
directly in Rego. That is NOT what this implementation does, on
purpose: docs/policy-reference.md's whole audience (a compliance
reviewer who reads YAML, not a Rego engineer) stays intact either way.
Instead, `docker/opa/policy.rego` is one small, fixed Rego module,
written once and covered by its own test suite
(`docker/opa/policy_test.rego`, run via `opa test`, see CI), that
reproduces `PolicyEngine`'s exact algorithm: first-match-wins over an
ordered rule list, falling through to a deny-by-default default. A
deployment's actual `policy.yaml` becomes plain data pushed into that
module at runtime (`PUT /v1/data/policy_input`), not Rego source code
compiled per deployment.

This means switching from `PolicyEngine` to `OPAPolicyEngine` changes
*where enforcement happens*, which matters for deployments that
already run OPA as their organization-wide policy enforcement point
(for audit consolidation, a shared Rego toolchain, or an existing OPA
sidecar convention), without changing *how anyone authors policy*.

## What is NOT built

**Cedar** (AWS's policy language) is not implemented. ROADMAP.md's
combined "OPA/Cedar policy backends" line is split: OPA is built (this
page); Cedar remains deferred, with no backend and no timeline.

**Rego-native policy authoring** (bypassing policy.yaml entirely to
write Rego modules per deployment) is not implemented. Every rule
`policy.yaml` can express, this backend can evaluate; a rule shape
`policy.yaml`'s Pydantic models cannot express (arbitrary Rego logic)
is out of scope here, same as it always was for the local engine.

**`custody serve` does not yet have a flag to pick this backend.**
Construct an `OPAPolicyEngine` and pass it to `Gateway(policy=...)` in
your own integration code (see below); wiring a `--policy-backend opa`
CLI option is left for a future release.

## Using it

```bash
docker build -f docker/opa.Dockerfile -t custody-opa:latest .
docker run -d --name custody-opa -p 8181:8181 custody-opa:latest
```

```python
from custody.policy.engine import PolicyEngine
from custody.policy.opa_backend import OPAPolicyEngine
from custody.gateway import Gateway

local = PolicyEngine.load("policy.yaml")           # same loader, same validation
opa_policy = OPAPolicyEngine(local.policy, "http://localhost:8181")

gateway = Gateway(policy=opa_policy, catalog=catalog, audit=audit, ...)
```

`Gateway`'s `policy` parameter is typed as `custody.policy.PolicyBackend`,
a `Protocol` with exactly the two methods `Gateway` and `ModelRouter`
actually call (`evaluate`, `check_model`) -- `OPAPolicyEngine` satisfies
it structurally, no inheritance or registration needed, so this is a
true drop-in. `tests/test_opa_backend.py::test_drop_in_for_gateway`
builds a real `Gateway` this way and runs real requests through it.

After editing `policy.yaml` and re-loading it, call
`opa_policy.push_policy()` (or construct a new `OPAPolicyEngine`) to
update the same running OPA server; nothing watches the file for you.

## Model routing does not go through OPA

`check_model()` (the per-data-class model allowlist check) is answered
by `custody.policy.engine.check_model_allowlist`, plain Python, shared
by both backends, not a Rego query. Model routing is a fast fnmatch
lookup, not a rule-matching decision in the same sense as `evaluate()`;
routing it through a network call to OPA would add latency for no real
benefit. If your deployment specifically wants model routing decisions
auditable inside OPA too, that is a reasonable future extension, not
built here.

## One OPA server, one deployment's policy

`OPAPolicyEngine` pushes its policy to a fixed path
(`data.policy_input`) on whatever `opa_url` it is given. Two
`OPAPolicyEngine` instances pointed at the *same* OPA server share that
one path: constructing the second overwrites the data the first
depends on. Run one OPA server per logical Custody deployment, the
same way you would run one `LocalFileSink` directory per deployment's
audit log, not shared across deployments.
`tests/test_opa_backend.py::test_two_engines_sharing_one_opa_server_DO_cross_contaminate`
demonstrates this explicitly so it is documented behavior, not a
surprise.

## What is verified

Two independent test suites, both run in CI:

- `docker/opa/policy_test.rego` (`opa test docker/opa/`): the Rego
  module's own logic, correct in isolation, no Python or network
  involved.
- `tests/test_opa_backend.py` (pytest, against a real `custody-opa`
  container, not a mock): `OPAPolicyEngine` pushes policy data
  correctly, queries correctly, translates results back into the same
  `PolicyResult` shape `PolicyEngine` produces, and (the `test_drop_in
  _for_gateway` case) a complete real `Gateway` built with this backend
  in place of the local one behaves identically for an allow and a
  deny case.
- `tests/test_opa_backend_errors.py` (pytest, no Docker needed): every
  error path (OPA unreachable, a non-2xx response, a malformed or
  unexpected response body) raises `OPABackendError` with a clear
  message rather than letting a raw exception escape or silently
  returning a wrong decision.
