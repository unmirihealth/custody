"""fhir.search: a read-only FHIR search against one catalog dataset
whose `source` is `fhir` (custody.catalog.SourceKind.fhir), policy-
checked and audited exactly like every other tool. See
docs/fhir-connector.md for the full design and its limitations (FHIR
only, not OMOP CDM; read-only; no sandbox execution).

Unlike sql.query and shell.run, this tool does NOT run inside
custody.sandbox: a FHIR search is a single bounded GET against a
pre-configured, catalog-declared base URL and an allowlisted resource
type, not arbitrary code execution, the same category of "direct,
narrow, policy-gated network call" as the webhook notifier
(custody/approvals/notifier.py) and the OPA policy backend
(custody/policy/opa_backend.py), both of which also call out over
stdlib urllib directly rather than through the sandbox.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from typing import Any

from custody.audit import EventType
from custody.tools.context import ToolContext
from custody.tools.models import ToolResult

_DEFAULT_TIMEOUT = 10.0
_DEFAULT_COUNT = 20
_MAX_COUNT = 100


def _http_get(url: str, timeout: float) -> tuple[int, bytes]:
    request = urllib.request.Request(url, method="GET")  # noqa: S310 - base_url is catalog-configured, not agent input
    request.add_header("Accept", "application/fhir+json")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            return int(response.status), response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()
    except (urllib.error.URLError, OSError) as exc:
        raise FhirConnectionError(f"could not reach {url}: {exc}") from exc


class FhirConnectionError(Exception):
    """The FHIR server could not be reached at all (DNS, connection
    refused, timeout). Distinct from an HTTP error status, which the
    server DID respond with and fhir_search turns into a denied
    ToolResult instead of raising."""


def _build_search_url(base_url: str, resource_type: str, params: dict[str, str], count: int) -> str:
    query = dict(params)
    query["_count"] = str(count)
    return f"{base_url.rstrip('/')}/{resource_type}?{urllib.parse.urlencode(query)}"


def fhir_search(
    ctx: ToolContext,
    source_id: str,
    resource_type: str,
    params: dict[str, str] | None = None,
    count: int = _DEFAULT_COUNT,
    *,
    get: Callable[[str, float], tuple[int, bytes]] = _http_get,
    timeout: float = _DEFAULT_TIMEOUT,
) -> ToolResult:
    """`params` is passed straight through as FHIR search parameters
    (e.g. `{"subject": "Patient/123", "code": "254637007"}`), not
    validated against FHIR's own search grammar -- a malformed or
    unsupported parameter simply gets whatever error response the FHIR
    server itself returns for it, same "the real validation lives one
    layer down" posture `sql.query` takes with its own query string.
    `count` is clamped to `_MAX_COUNT`, a tool call can't ask for an
    unbounded page.
    """
    authz = ctx.gateway.authorize("fhir.search", datasets=[source_id])
    if not authz.allowed:
        return ToolResult(denied=True, reason=authz.reason)

    entry = ctx.catalog.get(source_id)
    if entry is None:
        return ToolResult(denied=True, reason=f"dataset {source_id!r} is not in the catalog")
    if entry.base_url is None:
        return ToolResult(
            denied=True,
            reason=f"dataset {source_id!r} is not a FHIR dataset (source={entry.source})",
        )
    if resource_type not in entry.resource_types:
        # Deny-by-default: an empty resource_types list denies every
        # type, not just unlisted ones, same posture as
        # check_model_allowlist's empty-allowlist handling.
        return ToolResult(
            denied=True,
            reason=(
                f"resource type {resource_type!r} is not on dataset {source_id!r}'s "
                f"resource_types allowlist {entry.resource_types}"
            ),
        )

    clamped_count = min(count, _MAX_COUNT)
    url = _build_search_url(entry.base_url, resource_type, params or {}, clamped_count)

    try:
        status, body = get(url, timeout)
    except FhirConnectionError as exc:
        ctx.gateway.audit.append(
            EventType.error,
            {
                "tool": "fhir.search",
                "dataset": source_id,
                "resource_type": resource_type,
                "error": str(exc),
            },
        )
        return ToolResult(denied=True, reason=str(exc))

    ctx.gateway.audit.append(
        EventType.execution,
        {
            "tool": "fhir.search",
            "dataset": source_id,
            "resource_type": resource_type,
            "http_status": status,
        },
    )

    if status != 200:
        return ToolResult(denied=True, reason=f"FHIR server returned HTTP {status}")

    try:
        bundle: dict[str, Any] = json.loads(body)
    except json.JSONDecodeError:
        return ToolResult(denied=True, reason="FHIR server response was not valid JSON")

    if bundle.get("resourceType") != "Bundle":
        return ToolResult(denied=True, reason="FHIR server response was not a Bundle")

    resources = [e.get("resource") for e in bundle.get("entry", []) if "resource" in e]

    ctx.gateway.audit.append(
        EventType.result,
        {
            "tool": "fhir.search",
            "dataset": source_id,
            "resource_type": resource_type,
            # Only a count ever reaches the audit log, never a resource
            # body (docs/threat-model.md T6): a FHIR Patient/Condition
            # resource is exactly the shape of content that must never
            # appear in an audit payload.
            "result_count": len(resources),
        },
    )
    return ToolResult(denied=False, reason="ok", data=resources)
