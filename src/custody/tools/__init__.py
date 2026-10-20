"""Built-in MCP tools, each policy-checked before it runs.

catalog.list        -- list datasets and their data classes
sql.query            -- read-only DuckDB query over allowed datasets, in the sandbox
shell.run            -- run a command in the sandbox
files.write          -- write to the session workspace
files.export         -- copy an artifact out of the workspace (always policy-gated)
approvals.status     -- let the agent see whether its own request is pending/approved/denied

Each tool function's result passes through custody.guard before it
returns to the agent.

Not yet implemented.
"""

raise NotImplementedError("custody.tools is not yet implemented (v0.1 skeleton)")
