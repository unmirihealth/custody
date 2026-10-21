# Custody

Custody sits between an AI agent and the tools it uses on oncology data,
so the agent can work under controls a privacy or compliance officer can
actually review: data-aware policy, approval gates for anything sensitive,
a tamper-evident audit log, and isolated execution for every command.

```
Agent (Claude Code / Codex / OpenHands / Goose / any MCP client)
   |  MCP (stdio or streamable HTTP)
   v
Custody Gateway
   1. Identify principal + session
   2. Classify request (tool, datasets, data class, egress, model target)
   3. Policy engine  -> allow | deny | require_approval
   4. Approval broker -> wait for human decision (timeout = deny)
   5. Executor       -> sandboxed container
   6. Output guard   -> redact/summarize results by data class
   7. Audit log      -> hash-chained entry at every step
   |
   v
Custody's own tools: catalog.list, sql.query, shell.run, files.write,
files.export, approvals.status, fhir.search
```

Status: v0.1.0 tagged and public (285 tests, 96% coverage on
`src/custody`, `ruff` and `mypy --strict` clean); `main` carries
several items since merged in from ROADMAP.md (signed policy bundles,
an OPA policy backend, a Kubernetes deployment, a FHIR connector, an
S3 Object Lock audit sink, an egress allowlist proxy, OIDC-verified
approver identity) -- see CHANGELOG.md's `[Unreleased]` section for
exactly what, and for what shipped in v0.1.0 itself. One scope note:
the architecture above describes a gateway that can also proxy a
downstream MCP server's tools, that proxying is **not implemented**,
every tool call this release handles goes through one of the
built-ins listed above (see `custody/mcp_server.py`'s module
docstring).

## Quickstart (under 5 minutes to the demo, Docker required)

`custody-mcp` is [on PyPI](https://pypi.org/project/custody-mcp/)
(`pip install custody-mcp`) for the CLI and the gateway itself. The
demo specifically needs a clone, though: it builds the sandbox's
DuckDB image from `docker/sandbox.Dockerfile`, which only a clone
carries.

```bash
git clone https://github.com/unmirihealth/custody
cd custody
uv sync --extra dev
docker build -f docker/sandbox.Dockerfile -t custody-sandbox:duckdb .
uv run custody demo
```

`custody demo` generates a synthetic oncology dataset with a fixed
seed, writes a sample policy/catalog/principals to disk, and walks
through: an allowed catalog listing, a de-identified cohort query
(not small-cell suppressed, that only applies at `limited_data_set`
and above), the same cohort breakdown re-run on identified data (held
for approval, then approved, this time suppressed), a two-person
export denied by one of the two required approvers, a blocked network
call from the sandbox, and `custody audit verify` catching a
deliberately tampered log entry. See docs/demo.md for a narrated
walkthrough of the output.

Once initialized (`custody init` in an empty directory, or after
`custody demo`), run `custody serve --principal <your-agent-id>` to
start the real MCP gateway (stdio), or `custody ui` for the local
approvals web UI.

## Using it with Claude Code

Two integration modes:

- **MCP gateway (primary).** Custody runs as an MCP server
  (`custody serve`) exposing its built-in tools. See
  `examples/claude-code-mcp-config.json` for the config snippet.
- **`PreToolUse` hook adapter (secondary).** Routes Claude Code's own
  native tool calls (Bash, Write, Edit, WebFetch) through the same
  policy engine and audit log, as `claude_code.bash` /
  `claude_code.write` / `claude_code.edit` / `claude_code.web_fetch`
  in your policy. A `require_approval` decision here doesn't block the
  hook (a `PreToolUse` hook has roughly 30 seconds, Custody's default
  approval timeout is 15 minutes); it records the pending approval and
  returns Claude Code's own `"ask"` decision instead.

See docs/integrations/claude-code.md for both, with exact config.

## What Custody is not

- **Not a HIPAA certification.** Installing Custody does not make anyone
  compliant. The accurate phrase is that Custody provides controls that
  can support HIPAA-aligned programs.
- **Not an audit or a SOC 2 report.** `custody evidence export`
  produces a mechanical summary of the audit log and policy, mapped to
  SOC 2 Common Criteria language, for a reviewer's convenience. It is
  not an attestation and does not substitute for an independent
  auditor. See docs/evidence-pack.md.
- **Not a replacement for a business associate agreement, a risk
  assessment, or your institution's review process.**
- **Tamper-evident, not tamper-proof.** The audit log detects changes; it
  does not make them physically impossible. For long-term retention, ship
  checkpoints to write-once storage (see docs/audit-log.md).
- **Not a perfect sandbox.** Docker isolation is one layer in a
  defense-in-depth design, not the whole design. See docs/threat-model.md
  for exactly what v0.1 defends against and what it does not.
- **Not a full SSO login flow.** `principals.yaml` is still the one
  source of truth for which roles a principal holds. `custody
  approvals approve/deny --as-token` can verify an approver's identity
  against a real OIDC provider's signed token instead of trusting a
  bare `--as` string (see docs/sso-oidc.md), but there is no browser
  login flow, no session management, and the approvals web UI is
  unaffected (still its own startup-token gate).
- **Not sandboxed with gVisor or Firecracker.** Both require a Linux
  host with KVM; neither is buildable or verifiable on a macOS
  development machine, so neither is implemented here, see
  docs/threat-model.md T2 and ROADMAP.md.

## Components

| Component | Module | Docs |
|---|---|---|
| Data catalog | `custody/catalog.py` | this README |
| Policy engine | `custody/policy/` | docs/policy-reference.md |
| Signed policy bundles | `custody/policy/bundle.py` | docs/policy-reference.md, `custody policy sign/verify --help` |
| OPA policy backend (optional, same policy.yaml) | `custody/policy/opa_backend.py` | docs/opa-policy-backend.md |
| Kubernetes deployment | `k8s/`, `docker/custody.Dockerfile` | docs/kubernetes.md |
| Approval broker | `custody/approvals/` | this README, docs/threat-model.md |
| SSO/OIDC approver identity (optional, token verification only) | `custody/approvals/oidc.py` | docs/sso-oidc.md |
| Approval notifier (CLI, UI, webhook) | `custody/approvals/notifier.py` | docs/policy-reference.md, `custody serve --help` |
| Audit log | `custody/audit/` | docs/audit-log.md |
| S3 Object Lock audit sink (optional, `pip install custody-mcp[s3]`) | `custody/audit/s3_sink.py` | docs/s3-object-lock-sink.md |
| Evidence-pack export | `custody/evidence/` | docs/evidence-pack.md |
| Sandbox executor | `custody/sandbox/` | docs/threat-model.md |
| Egress allowlist proxy | `custody/sandbox/egress_proxy.py` | docs/egress-proxy.md, docs/threat-model.md T9 |
| Output guard | `custody/guard.py` | this README |
| Model routing | `custody/routing.py` | docs/threat-model.md |
| Gateway | `custody/gateway.py` | this README |
| Built-in tools | `custody/tools/` | this README |
| FHIR connector (read-only, FHIR only not OMOP) | `custody/tools/fhir.py` | docs/fhir-connector.md |
| MCP server | `custody/mcp_server.py` | docs/integrations/claude-code.md |
| CLI | `custody/cli/` | `custody --help` |
| Local approvals UI | `custody/approvals_ui.py` | this README |
| Claude Code hook | `custody/hooks/claude_code.py` | docs/integrations/claude-code.md |
| PyPI release workflow (Trusted Publishing) | `.github/workflows/publish.yml` | docs/releasing.md |

## Synthetic data only

Every example, fixture, and test in this repository uses generated
oncology records. No real patient data belongs anywhere near this
project, in an issue, a PR, or a commit. See CONTRIBUTING.md.

## License

Apache 2.0. See LICENSE and NOTICE.
