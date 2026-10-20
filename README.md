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
   5. Executor       -> sandboxed container or proxied downstream MCP server
   6. Output guard   -> redact/summarize results by data class
   7. Audit log      -> hash-chained entry at every step
   |
   v
Downstream tools: shell, SQL over local datasets, file read/write, other MCP servers
```

Status: v0.1 is under active development. The components and CLI listed
below are a planned surface, each currently raises `NotImplementedError`
until it is built; this README will stop saying that once it is true.
Track progress in CHANGELOG.md.

## Quickstart (target: under 5 minutes to the demo)

```bash
pip install custody-mcp
custody init
custody demo
```

`custody demo` generates a synthetic oncology dataset with a fixed seed,
ships a sample policy, and walks through: an allowed catalog listing, an
allowed de-identified cohort query, an identified-table query held for
approval, a denied two-person export, a denied network call from the
sandbox, and `custody audit verify` catching a deliberately tampered log
entry. See docs/demo.md.

## Using it with Claude Code

Two integration modes: Custody as an MCP server (the primary path, see
`examples/` for a Claude Code MCP config snippet), or a `PreToolUse` hook
adapter that routes Claude Code's native tool calls (Bash, Write, Edit,
WebFetch) through the same policy engine and audit log. See
docs/integrations/claude-code.md.

## What Custody is not

- **Not a HIPAA certification.** Installing Custody does not make anyone
  compliant. The accurate phrase is that Custody provides controls that
  can support HIPAA-aligned programs.
- **Not a replacement for a business associate agreement, a risk
  assessment, or your institution's review process.**
- **Tamper-evident, not tamper-proof.** The audit log detects changes; it
  does not make them physically impossible. For long-term retention, ship
  checkpoints to write-once storage (see docs/audit-log.md).
- **Not a perfect sandbox.** Docker isolation is one layer in a
  defense-in-depth design, not the whole design. See docs/threat-model.md
  for exactly what v0.1 defends against and what it does not.

## Synthetic data only

Every example, fixture, and test in this repository uses generated
oncology records. No real patient data belongs anywhere near this
project, in an issue, a PR, or a commit. See CONTRIBUTING.md.

## License

Apache 2.0. See LICENSE and NOTICE.
