"""The built-in MCP tools, each policy-checked through
`Gateway.authorize` before it does anything:

catalog.list      -- custody.tools.catalog_list.catalog_list
sql.query         -- custody.tools.sql.sql_query
shell.run         -- custody.tools.shell.shell_run
files.write       -- custody.tools.files.files_write
files.export      -- custody.tools.files.files_export
approvals.status  -- custody.tools.approvals_status.approvals_status
fhir.search       -- custody.tools.fhir.fhir_search

See custody.mcp_server for how these get registered as actual MCP tools.
"""

from custody.tools.approvals_status import approvals_status
from custody.tools.catalog_list import catalog_list
from custody.tools.context import ToolContext
from custody.tools.fhir import FhirConnectionError, fhir_search
from custody.tools.files import files_export, files_write
from custody.tools.models import ToolResult
from custody.tools.shell import shell_run
from custody.tools.sql import UnsafeQueryError, sql_query

__all__ = [
    "FhirConnectionError",
    "ToolContext",
    "ToolResult",
    "UnsafeQueryError",
    "approvals_status",
    "catalog_list",
    "fhir_search",
    "files_export",
    "files_write",
    "shell_run",
    "sql_query",
]
