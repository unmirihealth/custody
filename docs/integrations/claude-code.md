# Claude Code integration

Two ways to point a Claude Code session at Custody. They're not
mutually exclusive, but most setups need only one.

## MCP gateway (primary)

Custody runs as an MCP server over stdio and exposes its built-in
tools (`catalog.list`, `sql.query`, `shell.run`, `files.write`,
`files.export`, `approvals.status`). The agent calls these instead of
reaching data or a shell directly.

1. Initialize a deployment (once):

   ```bash
   mkdir my-custody-deployment && cd my-custody-deployment
   custody init
   # edit policy.yaml and catalog.yaml for your real datasets
   ```

2. Add Custody as an MCP server. In Claude Code's MCP config (see
   `examples/claude-code-mcp-config.json`):

   ```json
   {
     "mcpServers": {
       "custody": {
         "command": "custody",
         "args": [
           "serve",
           "--dir", "/absolute/path/to/my-custody-deployment",
           "--principal", "claude-code"
         ]
       }
     }
   }
   ```

   `--principal` is the identity recorded as the requester on every
   audit entry and approval Custody creates for this session, it is
   not an authentication credential, just a label. Pick something
   that identifies the session (a username, a project name).

3. Start a Claude Code session. The agent now sees Custody's tools
   instead of (or alongside) whatever it would otherwise use for data
   access. A tool call that needs approval blocks (up to the policy's
   configured timeout, default 15 minutes) while a human runs
   `custody ui` or `custody approvals approve/deny` against the same
   `--dir`.

## `PreToolUse` hook adapter (secondary)

Routes Claude Code's own native tools (`Bash`, `Write`, `Edit`,
`WebFetch`) through the same policy engine and audit log, without the
agent needing to call anything Custody-specific. Useful when you want
policy enforcement on an agent's *existing* tool use, not just on
calls it makes through an MCP server.

Register it in `.claude/settings.json` (project or user level):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|Write|Edit|WebFetch",
        "hooks": [
          {
            "type": "command",
            "command": "custody-claude-code-hook",
            "timeout": 10
          }
        ]
      }
    ]
  }
}
```

Set the deployment directory and principal via environment variables
(both optional; `CUSTODY_DIR` defaults to the hook event's own `cwd`,
`CUSTODY_PRINCIPAL` defaults to the Claude Code session id):

```json
"env": {
  "CUSTODY_DIR": "${CLAUDE_PROJECT_DIR}/.custody-deployment",
  "CUSTODY_PRINCIPAL": "claude-code"
}
```

(Claude Code hooks don't currently take a per-hook `env` block in the
shape shown above; set these in your shell profile, a wrapper script,
or however your Claude Code setup manages environment variables for
hook commands, whichever matches your actual settings.json hook
schema.)

### What this governs, and what it maps to

| Claude Code tool | Policy `tool` field |
|---|---|
| `Bash` | `claude_code.bash` |
| `Write` | `claude_code.write` |
| `Edit` | `claude_code.edit` |
| `WebFetch` | `claude_code.web_fetch` (always `egress: true`) |

Any other Claude Code tool (`Read`, `Grep`, etc.) is not governed by
this adapter, the hook returns `"defer"` and Claude Code's normal
permission flow handles it.

Write a policy rule for these the same way as any other
(docs/policy-reference.md), just using the `claude_code.*` tool names.
They are namespaced separately from Custody's own MCP tools
(`shell.run`, etc.) deliberately: a raw `Bash` command carries a
different risk shape than an MCP `sql.query` call that already went
through its own read-only validation, so sharing one rule between the
two would be misleading.

### How `require_approval` behaves here, specifically

A `PreToolUse` hook has roughly a 30-second execution budget, far
short of Custody's 15-minute default approval timeout, so this adapter
does **not** block the hook process waiting on a human decision the
way the MCP gateway's `Gateway.authorize()` does. Instead, a
`require_approval` decision:

1. Creates the pending approval record (so it shows up in
   `custody approvals list` / `custody ui`, on the record for
   compliance review).
2. Returns Claude Code's own `"ask"` decision immediately, handing the
   interactive moment to Claude Code's permission prompt, since the
   developer running the session is presumably right there.

`allow` and `deny` map directly to Claude Code's own `allow`/`deny`.
An event the adapter can't even parse (malformed stdin) exits 0 with
no output, a non-blocking error under Claude Code's hook contract, so
Claude Code's normal permission flow takes over rather than the hook
claiming an opinion about a tool call it couldn't read.
