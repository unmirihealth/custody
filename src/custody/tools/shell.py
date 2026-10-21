"""shell.run: run a command in the sandbox, with zero or more catalog
datasets mounted read-only for it to work against.
"""

from __future__ import annotations

from hashlib import sha256

from custody.audit import EventType
from custody.sandbox import DatasetMount
from custody.tools.context import ToolContext
from custody.tools.models import ToolResult


def shell_run(
    ctx: ToolContext,
    command: list[str],
    datasets: list[str] | None = None,
    *,
    egress: bool = False,
) -> ToolResult:
    """`egress=True` is the agent ASKING for network access, it is not a
    grant: the policy still has to have a rule that allows egress for
    this to actually reach the sandbox with networking enabled (most
    policies won't, see the "no-egress" rule in the shipped starter
    policy). Passing egress=True against a policy that denies it fails
    at Gateway.authorize before the sandbox is ever touched.
    """
    authz = ctx.gateway.authorize("shell.run", datasets=datasets or [], egress=egress)
    if not authz.allowed:
        return ToolResult(denied=True, reason=authz.reason)

    mounts: list[DatasetMount] = []
    for dataset_id in datasets or []:
        entry = ctx.catalog.get(dataset_id)
        if entry is None:
            return ToolResult(denied=True, reason=f"dataset {dataset_id!r} is not in the catalog")
        if entry.path is None:  # a fhir-source entry; see custody.connectors.fhir instead
            return ToolResult(
                denied=True,
                reason=f"dataset {dataset_id!r} is not a file dataset (source={entry.source})",
            )
        mounts.append(
            DatasetMount(
                dataset_id=dataset_id,
                host_path=entry.path,
                container_path=f"/data/{dataset_id}{entry.path.suffix}",
            )
        )

    exec_result = ctx.sandbox.run(command, mounts=mounts, allow_egress=egress)
    ctx.gateway.audit.append(
        EventType.execution,
        {
            "tool": "shell.run",
            "datasets": datasets or [],
            "exit_code": exec_result.exit_code,
            "timed_out": exec_result.timed_out,
            "denied": exec_result.denied,
            "stdout_sha256": sha256(exec_result.stdout.encode()).hexdigest(),
            "stderr_sha256": sha256(exec_result.stderr.encode()).hexdigest(),
        },
    )

    if exec_result.denied:
        return ToolResult(denied=True, reason=exec_result.denial_reason or "sandbox denied")

    return ToolResult(
        denied=False,
        reason="executed",
        data={
            "exit_code": exec_result.exit_code,
            "timed_out": exec_result.timed_out,
            "stdout": exec_result.stdout,
            "stderr": exec_result.stderr,
        },
    )
