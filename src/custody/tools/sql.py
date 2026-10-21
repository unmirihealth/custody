"""sql.query: read-only SQL (DuckDB) over one catalog dataset, run inside
the sandbox, results passed through the output guard before they reach
the agent. See docker/sandbox.Dockerfile for the image this runs in and
docs/demo.md for the exact query the demo scenario uses.
"""

from __future__ import annotations

import json
import re
from hashlib import sha256

from custody.audit import EventType
from custody.guard import AggregateRow
from custody.sandbox import DatasetMount
from custody.tools.context import ToolContext
from custody.tools.models import ToolResult

# A deliberately blunt allow-list, not a SQL parser: the real security
# boundary is the sandbox (read-only mount, no network, ephemeral
# container), not this check. This exists to reject the obviously wrong
# thing (an agent trying to write) before it ever reaches the sandbox,
# not to be airtight against a determined adversary who already has SQL
# execution.
_READONLY_PATTERN = re.compile(r"^\s*(SELECT|WITH)\b", re.IGNORECASE)
_BANNED_KEYWORDS = re.compile(
    r"\b(INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|ATTACH|DETACH|COPY|PRAGMA|EXPORT|IMPORT|CALL)\b",
    re.IGNORECASE,
)


class UnsafeQueryError(ValueError):
    pass


def _validate_readonly(query: str) -> None:
    if not _READONLY_PATTERN.match(query):
        raise UnsafeQueryError("query must start with SELECT or WITH")
    if _BANNED_KEYWORDS.search(query):
        raise UnsafeQueryError(
            "query contains a keyword that isn't allowed for sql.query "
            "(writes, schema changes, and DuckDB's file-system-reaching "
            "extensions are all out of scope for this tool)"
        )
    if ";" in query.rstrip(";"):
        raise UnsafeQueryError("only a single statement is allowed, no ';'-separated chaining")


def _build_script(container_csv_path: str, query: str) -> str:
    # This builds a Python SOURCE STRING, not a live SQL query: ruff's
    # S608 pattern-matches "execute(" next to an f-string and flags it
    # as a SQL-injection shape regardless of context. The actual safety
    # property here is that repr() of a Python string always produces a
    # syntactically valid, safely escaped Python string literal, so
    # embedding container_csv_path and query this way can't break out of
    # the literal no matter what quotes or backslashes either contains.
    create_view = f"con.execute({_create_view_sql(container_csv_path)!r})\n"  # noqa: S608
    run_query = f"rows = con.execute({query!r}).fetchall()\n"
    return (
        "import duckdb, json\n"
        "con = duckdb.connect(':memory:')\n"
        + create_view
        + run_query
        + "cols = [d[0] for d in con.description]\n"
        "print(json.dumps([dict(zip(cols, r)) for r in rows]))\n"
    )


def _create_view_sql(container_csv_path: str) -> str:
    # container_csv_path always comes from a DatasetMount this module
    # constructs itself (never from agent input), so a standard SQL
    # string literal (doubled single quotes) is enough here. The agent's
    # `query` is the untrusted value and IS meant to run as arbitrary SQL
    # against this view, that's the tool's whole purpose; what repr() in
    # _build_script protects is the PYTHON source around it (so `query`
    # can't break out of its Python string literal and inject extra
    # Python statements into the generated script), not the SQL itself.
    # The actual SQL-level defense is _validate_readonly() plus the
    # sandbox's own isolation, not string escaping.
    escaped = container_csv_path.replace("'", "''")
    return f"CREATE VIEW data AS SELECT * FROM read_csv_auto('{escaped}')"  # noqa: S608


def sql_query(ctx: ToolContext, dataset_id: str, query: str) -> ToolResult:
    authz = ctx.gateway.authorize("sql.query", datasets=[dataset_id])
    if not authz.allowed:
        return ToolResult(denied=True, reason=authz.reason)

    try:
        _validate_readonly(query)
    except UnsafeQueryError as exc:
        ctx.gateway.audit.append(
            EventType.error, {"tool": "sql.query", "dataset": dataset_id, "error": str(exc)}
        )
        return ToolResult(denied=True, reason=str(exc))

    entry = ctx.catalog.get(dataset_id)
    if entry is None:
        return ToolResult(denied=True, reason=f"dataset {dataset_id!r} is not in the catalog")

    container_path = f"/data/{dataset_id}{entry.path.suffix}"
    mount = DatasetMount(dataset_id=dataset_id, host_path=entry.path, container_path=container_path)
    script = _build_script(container_path, query)

    exec_result = ctx.sandbox.run(
        ["python3", "-c", script], mounts=[mount], image=ctx.sql_image
    )
    ctx.gateway.audit.append(
        EventType.execution,
        {
            "tool": "sql.query",
            "dataset": dataset_id,
            "exit_code": exec_result.exit_code,
            "timed_out": exec_result.timed_out,
            "denied": exec_result.denied,
            "stdout_sha256": sha256(exec_result.stdout.encode()).hexdigest(),
        },
    )

    if exec_result.denied:
        return ToolResult(denied=True, reason=exec_result.denial_reason or "sandbox denied")
    if exec_result.timed_out:
        return ToolResult(denied=True, reason="query timed out")
    if exec_result.exit_code != 0:
        return ToolResult(denied=True, reason=f"query failed: {exec_result.stderr.strip()}")

    try:
        raw_rows: list[dict[str, object]] = json.loads(exec_result.stdout)
    except json.JSONDecodeError:
        return ToolResult(denied=True, reason="query result was not valid JSON")

    # Treat a result as a GROUP BY aggregate (and therefore small-cell
    # suppressible) only when every row carries an integer "count"
    # column; anything else passes through ungaurded by this layer, the
    # approval gate is what already controls access to row-level
    # identified data.
    if raw_rows and all(
        isinstance(r.get("count"), int) and set(r.keys()) - {"count"} for r in raw_rows
    ):
        aggregate_rows = [
            AggregateRow(group={k: str(v) for k, v in r.items() if k != "count"}, count=r["count"])  # type: ignore[arg-type]
            for r in raw_rows
        ]
        guarded = ctx.guard.guard_aggregate(aggregate_rows, authz.data_class)
        data = [g.model_dump() for g in guarded]
    else:
        data = raw_rows

    ctx.gateway.audit.append(
        EventType.result,
        {"tool": "sql.query", "dataset": dataset_id, "row_count": len(raw_rows)},
    )
    return ToolResult(denied=False, reason="ok", data=data)
