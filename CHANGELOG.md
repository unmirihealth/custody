# Changelog

All notable changes to this project are documented here. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
