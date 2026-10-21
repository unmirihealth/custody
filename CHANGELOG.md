# Changelog

All notable changes to this project are documented here. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- `custody.approvals.notifier`: `WebhookNotifier`, the third approval
  channel named in v0.1's own design (CLI, local web UI, webhook) but
  not actually built for the initial release. Posts a Slack-compatible
  `{"text": ...}` payload (tool, data class, approval id, required
  roles, optionally a review URL -- never dataset content) via stdlib
  `urllib`; failures (bad URL, network down, non-2xx) are logged and
  swallowed, never raised, so a notification outage cannot break an
  approval request. `Gateway` takes an optional `notifier` (defaults to
  a no-op `NullNotifier`); `custody serve` reads a webhook URL from the
  `CUSTODY_WEBHOOK_URL` environment variable.
- `custody.policy.bundle`: signed policy bundles. `custody policy sign
  <file> --key <signing-key>` writes a `<file>.sig.json` sidecar
  recording the policy file's exact SHA-256, a timestamp, and an
  Ed25519 signature (reusing `custody.audit.keys`, the same crypto as
  audit checkpoints). `custody policy verify <file>` confirms the file
  on disk still matches a reviewed-and-signed version. `PolicyEngine
  .load_verified(path)` loads a policy only when a valid bundle covers
  it. See docs/policy-reference.md.
- `custody.evidence`: evidence-pack export. `custody evidence export
  <dest-dir>` writes a manifest, a human-readable README, a full audit
  export, and a copy of the policy file and its signed bundle (if
  present) to a new directory. The manifest includes counts per audit
  event type and per policy decision, a fresh `custody audit verify`
  result, and a fixed set of mappings from Custody's own mechanisms to
  SOC 2 Common Criteria language (`custody/evidence/framework.py`),
  each naming a real mechanism and a real limitation, same honest style
  as docs/threat-model.md. Explicitly not a certification or an audit,
  every pack says so in its own `README.md` and `manifest.json`. See
  docs/evidence-pack.md.
- `custody.sandbox.egress_proxy`: a scoped alternative to
  `allow_egress=True`'s old plain on/off switch. Setting
  `SandboxConfig.egress_allowlist` attaches an egress-allowed sandboxed
  run to a Docker network created with `internal=True` (no route out
  at all) alongside a small stdlib-only forward proxy
  (`docker/egress_proxy_server.py`, `docker/egress-proxy.Dockerfile`)
  that refuses to `CONNECT` or forward anywhere not on the allowlist.
  An empty allowlist still falls back to the previous unscoped
  behavior (documented, not silently removed). See
  docs/egress-proxy.md and docs/threat-model.md T9.
- `custody.audit.s3_sink.S3ObjectLockSink`: a second `AuditSink`
  implementation, filling in the write-once storage hook
  docs/audit-log.md has documented since v0.1. Requires the optional
  `s3` dependency group (`pip install custody-mcp[s3]`); never
  imported by `custody.audit`'s own `__init__`, so Custody still does
  not require AWS to run. Tested against a real LocalStack container
  for read/write/list/ordering correctness; the retention guarantee
  itself (an actual blocked delete) is explicitly NOT verified in this
  environment, LocalStack's free Community edition accepts Object Lock
  parameters but does not enforce them, a known gap documented in
  docs/s3-object-lock-sink.md alongside what IS verified.
- `custody.policy.opa_backend.OPAPolicyEngine`: an alternative to the
  local YAML/Pydantic `PolicyEngine` that evaluates the same
  `policy.yaml` by querying a real OPA (Open Policy Agent) server. A
  small, fixed Rego module (`docker/opa/policy.rego`, its own test
  suite via `opa test`, run in CI) reproduces `PolicyEngine`'s exact
  first-match-wins algorithm against policy data pushed at runtime;
  policy authoring stays in YAML, nothing about docs/policy-reference
  .md changes. Structurally satisfies the new `custody.policy
  .PolicyBackend` Protocol, so it is a genuine drop-in for
  `Gateway(policy=...)` -- confirmed by a test building a real Gateway
  with it in place of the local engine. Model routing
  (`check_model()`) stays plain Python either way, shared by both
  backends via the new `check_model_allowlist` free function; routing
  it through a network call added no real benefit. Only the OPA half
  of ROADMAP.md's "OPA/Cedar policy backends" item: Cedar remains
  unbuilt. See docs/opa-policy-backend.md.
- Refactored `custody.policy.engine`: `effective_data_class` and
  `check_model_allowlist` are now free functions (previously private
  `PolicyEngine` methods), reused by `OPAPolicyEngine`. No behavior
  change for `PolicyEngine` itself.
- Kubernetes deployment: `k8s/` (plain manifests + `kustomization.yaml`,
  no Helm chart) and `docker/custody.Dockerfile`. `custody serve`
  gained `--transport streamable-http --host --port` (stdio stays the
  default), using the MCP Python SDK's own `streamable-http` transport
  mode, no new protocol code. Single-replica by design: `LocalFileSink`
  and `ApprovalStore` both assume one writer, documented plainly in
  docs/kubernetes.md rather than silently allowing a broken
  multi-replica deployment. Sandbox execution tools (`shell.run`,
  `sql.query`) resolve to denied inside a plain Pod (no Docker daemon
  available by default, intentionally not wired up, see the doc for
  why). Verified end to end against a real local `kind` cluster:
  `k8s/smoke-test.sh` builds the image, deploys it, confirms the
  signing key survives a Pod restart (audit chain continuity), and
  runs a real MCP `initialize` handshake through the Service from an
  in-cluster Pod -- the same script a new `.github/workflows
  /k8s-smoke.yml` CI workflow now runs on every push touching `k8s/`,
  the Dockerfile, or `src/custody/`.

## [0.1.0] - 2026-10-21

### Fixed
- `custody.approvals.store.ApprovalStore`: a shared SQLite connection
  accessed from more than one thread without a lock could produce a
  torn read under real concurrency (`check_same_thread=False` permits
  multi-threaded use, it does not make it safe). Found by CI on Python
  3.13 specifically, not locally. Every store method now holds an
  internal lock for its full duration.
- `custody.cli`'s GitHub Actions matrix: `setup-uv`'s `python-version`
  input doesn't exist and was silently ignored, so both matrix legs
  were quietly testing against the same Python instead of 3.12 and
  3.13 separately -- which is exactly how the bug above went
  undetected until the matrix was fixed to actually test both.

### Added
- Project skeleton, threat model (docs/threat-model.md), Apache 2.0
  licensing matching `unmiri-ngs-fhir-schema`.
- `custody.catalog`: data classification (`synthetic < deidentified <
  limited_data_set < identified`), deny-by-default for an unlisted
  dataset id, relative dataset paths resolved against `catalog.yaml`'s
  own directory.
- `custody.policy`: deterministic, first-match-wins rule evaluation;
  `default: deny` enforced at load time, not just convention;
  per-data-class model routing allowlist.
- `custody.audit`: append-only, SHA-256 hash-chained log with periodic
  Ed25519-signed checkpoints; `verify_sink()` recomputes the whole
  chain and reports the first broken link, including corrupted (not
  just wrong) entries.
- `custody.approvals`: SQLite-backed approval broker enforcing
  self-approval, role, duplicate-approver, and expiry rules as raised
  exceptions; fail-fast on a single denial in a multi-approver rule.
- `custody.sandbox`: Docker-backed executor, non-root, read-only
  rootfs, no network by default, dropped capabilities, resource
  limits; a missing Docker daemon or a container that fails to start
  both resolve to a denied result, not an exception.
- `custody.guard`: small-cell suppression on aggregate results for
  `limited_data_set` and `identified` data (not below).
- `custody.routing`: model-allowlist routing, independent of the
  tool/data policy decision.
- `custody.gateway`: the orchestration layer (policy -> model routing
  -> approval wait -> audit, at every step).
- `custody.tools`: the six built-in tools (`catalog.list`, `sql.query`,
  `shell.run`, `files.write`, `files.export`, `approvals.status`).
- `custody.mcp_server`: wires the six tools to a real `mcp.server.MCPServer`
  (MCP Python SDK v2, `mcp>=2.3`).
- `custody.cli`: `init`, `serve`, `policy check|explain`,
  `approvals list|approve|deny`, `audit verify|export|tail`, `demo`,
  `ui`.
- `custody.approvals_ui`: the local approvals web UI, server-rendered,
  no JS framework, bound to `127.0.0.1`, startup-token gated.
- `custody.demo`: the end-to-end scripted scenario, including a
  synthetic 5,000-patient tumor registry generator.
- `custody.hooks.claude_code`: the `PreToolUse` hook adapter for Claude
  Code (`Bash`, `Write`, `Edit`, `WebFetch`).
- docs/policy-reference.md, docs/audit-log.md,
  docs/integrations/claude-code.md, docs/demo.md.

### Scope notes (what's intentionally not in this release)
- Proxying a downstream MCP server's tools through the gateway: not
  implemented, every tool call resolves to one of the six built-ins.
- Microsoft Presidio integration in the output guard: not implemented.
- A fully isolated egress allowlist proxy: not implemented,
  `allow_egress=True` is a plain on/off switch.
- SSO/OIDC approver identity, OPA/Cedar policy backends, FHIR/OMOP
  connectors, gVisor/Firecracker sandboxing, an S3 Object Lock audit
  sink, Kubernetes deployment, signed policy bundles, approver mobile
  notifications, evidence-pack export: see ROADMAP.md.
