from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from custody.approvals import ApprovalBroker, ApprovalStore, PrincipalDirectory
from custody.audit import AuditLog, EventType, LocalFileSink
from custody.catalog import Catalog, CatalogEntry, DataClass, SourceKind
from custody.gateway import Gateway
from custody.guard import OutputGuard
from custody.policy import Decision, Policy, PolicyEngine, Rule, WhenClause
from custody.sandbox import SandboxConfig, SandboxExecutor
from custody.tools import FhirConnectionError, ToolContext, fhir_search
from tests.conftest import requires_docker


def _permissive_policy() -> Policy:
    return Policy(
        rules=[Rule(id="fhir-ok", when=WhenClause(tool="fhir.search"), decision=Decision.allow)],
        default=Decision.deny,
        model_allowlist={},
    )


@pytest.fixture
def catalog() -> Catalog:
    return Catalog(
        {
            "onco_fhir": CatalogEntry(
                id="onco_fhir",
                data_class=DataClass.limited_data_set,
                source=SourceKind.fhir,
                base_url="http://fhir.example/fhir",
                resource_types=["Condition", "Observation"],
            ),
            "a_file_dataset": CatalogEntry(
                id="a_file_dataset",
                data_class=DataClass.deidentified,
                source=SourceKind.file,
                path=Path("/tmp/doesnt-matter.csv"),  # noqa: S108
                format="csv",  # type: ignore[arg-type]
            ),
        }
    )


@pytest.fixture
def ctx(tmp_path: Path, catalog: Catalog) -> Iterator[ToolContext]:
    policy = PolicyEngine(_permissive_policy())
    audit = AuditLog(
        LocalFileSink(tmp_path / "audit"),
        Ed25519PrivateKey.generate(),
        session_id="test-session",
        principal="agent_session",
    )
    broker = ApprovalBroker(ApprovalStore(tmp_path / "approvals.db"), PrincipalDirectory.empty())
    gateway = Gateway(
        policy=policy,
        catalog=catalog,
        audit=audit,
        approvals=broker,
        session_id="test-session",
        principal="agent_session",
    )
    sandbox = SandboxExecutor(SandboxConfig())
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    try:
        yield ToolContext(
            gateway=gateway,
            sandbox=sandbox,
            catalog=catalog,
            guard=OutputGuard(),
            workspace_dir=workspace,
        )
    finally:
        gateway.close()


def _bundle_response(resources: list[dict[str, object]]) -> bytes:
    import json

    return json.dumps(
        {
            "resourceType": "Bundle",
            "type": "searchset",
            "entry": [{"resource": r} for r in resources],
        }
    ).encode()


class TestFhirSearchUnit:
    """Injected fake `get`, no network or Docker needed: every policy
    and error-handling branch the tool itself is responsible for."""

    def test_returns_resources_on_success(self, ctx: ToolContext) -> None:
        resources = [{"resourceType": "Condition", "id": "1"}]
        result = fhir_search(
            ctx,
            "onco_fhir",
            "Condition",
            get=lambda url, timeout: (200, _bundle_response(resources)),
        )
        assert result.denied is False
        assert result.data == resources

    def test_unknown_dataset_denied(self, ctx: ToolContext) -> None:
        result = fhir_search(ctx, "nope", "Condition", get=lambda url, timeout: (200, b"{}"))
        assert result.denied is True
        assert "not in the catalog" in result.reason

    def test_non_fhir_dataset_denied(self, ctx: ToolContext) -> None:
        result = fhir_search(
            ctx, "a_file_dataset", "Condition", get=lambda url, timeout: (200, b"{}")
        )
        assert result.denied is True
        assert "not a FHIR dataset" in result.reason

    def test_resource_type_not_on_allowlist_denied(self, ctx: ToolContext) -> None:
        result = fhir_search(
            ctx, "onco_fhir", "Patient", get=lambda url, timeout: (200, _bundle_response([]))
        )
        assert result.denied is True
        assert "resource_types allowlist" in result.reason

    def test_empty_allowlist_denies_everything(self, tmp_path: Path) -> None:
        catalog = Catalog(
            {
                "locked_down": CatalogEntry(
                    id="locked_down",
                    data_class=DataClass.identified,
                    source=SourceKind.fhir,
                    base_url="http://fhir.example/fhir",
                    resource_types=[],
                )
            }
        )
        policy = PolicyEngine(_permissive_policy())
        audit = AuditLog(
            LocalFileSink(tmp_path / "audit"),
            Ed25519PrivateKey.generate(),
            session_id="s",
            principal="agent_session",
        )
        broker = ApprovalBroker(
            ApprovalStore(tmp_path / "approvals.db"), PrincipalDirectory.empty()
        )
        gateway = Gateway(
            policy=policy,
            catalog=catalog,
            audit=audit,
            approvals=broker,
            session_id="s",
            principal="agent_session",
        )
        ctx = ToolContext(
            gateway=gateway,
            sandbox=SandboxExecutor(SandboxConfig()),
            catalog=catalog,
            guard=OutputGuard(),
            workspace_dir=tmp_path,
        )
        result = fhir_search(
            ctx, "locked_down", "Condition", get=lambda url, timeout: (200, _bundle_response([]))
        )
        assert result.denied is True
        gateway.close()

    def test_non_200_status_denied(self, ctx: ToolContext) -> None:
        result = fhir_search(
            ctx, "onco_fhir", "Condition", get=lambda url, timeout: (500, b"server error")
        )
        assert result.denied is True
        assert "HTTP 500" in result.reason

    def test_malformed_json_denied(self, ctx: ToolContext) -> None:
        result = fhir_search(
            ctx, "onco_fhir", "Condition", get=lambda url, timeout: (200, b"not json")
        )
        assert result.denied is True
        assert "not valid JSON" in result.reason

    def test_non_bundle_response_denied(self, ctx: ToolContext) -> None:
        result = fhir_search(
            ctx,
            "onco_fhir",
            "Condition",
            get=lambda url, timeout: (200, b'{"resourceType": "OperationOutcome"}'),
        )
        assert result.denied is True
        assert "not a Bundle" in result.reason

    def test_connection_failure_denied_not_raised(self, ctx: ToolContext) -> None:
        def failing_get(url: str, timeout: float) -> tuple[int, bytes]:
            raise FhirConnectionError("connection refused")

        result = fhir_search(ctx, "onco_fhir", "Condition", get=failing_get)
        assert result.denied is True
        assert "connection refused" in result.reason

    def test_count_is_clamped(self, ctx: ToolContext) -> None:
        captured_urls: list[str] = []

        def recording_get(url: str, timeout: float) -> tuple[int, bytes]:
            captured_urls.append(url)
            return 200, _bundle_response([])

        fhir_search(ctx, "onco_fhir", "Condition", count=99999, get=recording_get)
        assert "_count=100" in captured_urls[0]

    def test_audit_never_carries_resource_content(self, ctx: ToolContext) -> None:
        resources = [{"resourceType": "Condition", "id": "1", "code": {"text": "lung cancer"}}]
        fhir_search(
            ctx,
            "onco_fhir",
            "Condition",
            get=lambda url, timeout: (200, _bundle_response(resources)),
        )
        entries = list(ctx.gateway.audit._sink.read_entries())  # test-only introspection
        for e in entries:
            assert "lung cancer" not in str(e.payload)
        result_entries = [e for e in entries if e.event_type == EventType.result]
        assert result_entries[0].payload["result_count"] == 1


# ── Real HAPI FHIR server integration ──────────────────────────────


HAPI_IMAGE = "hapiproject/hapi:latest"


def _hapi_available() -> bool:
    try:
        import docker

        docker.from_env().ping()
        return True
    except Exception:  # noqa: BLE001
        return False


requires_hapi = pytest.mark.skipif(not _hapi_available(), reason="Docker daemon not reachable")


@pytest.fixture(scope="module")
def hapi_base_url() -> Iterator[str]:

    import docker

    client = docker.from_env()
    name = "custody-test-hapi"
    try:
        client.containers.get(name).remove(force=True)
    except docker.errors.NotFound:
        pass

    container = client.containers.run(
        HAPI_IMAGE, detach=True, name=name, ports={"8080/tcp": 18082}
    )
    url = "http://localhost:18082/fhir"
    try:
        _wait_for_ready(url)
        yield url
    finally:
        container.remove(force=True)


def _wait_for_ready(url: str, timeout: float = 90.0) -> None:
    import time
    import urllib.error
    import urllib.request

    deadline = time.monotonic() + timeout
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            urllib.request.urlopen(f"{url}/metadata", timeout=3)  # noqa: S310
            return
        except (urllib.error.URLError, OSError) as exc:
            last_exc = exc
            time.sleep(1.5)
    raise RuntimeError(f"HAPI FHIR server never became ready: {last_exc}")


def _put_fhir_resource(base_url: str, resource_type: str, resource_id: str, body: bytes) -> None:
    import urllib.request

    request = urllib.request.Request(  # noqa: S310
        f"{base_url}/{resource_type}/{resource_id}", data=body, method="PUT"
    )
    request.add_header("Content-Type", "application/fhir+json")
    urllib.request.urlopen(request, timeout=10)  # noqa: S310


def _post_fhir_resource(base_url: str, resource_type: str, body: bytes) -> None:
    import urllib.request

    request = urllib.request.Request(  # noqa: S310
        f"{base_url}/{resource_type}", data=body, method="POST"
    )
    request.add_header("Content-Type", "application/fhir+json")
    urllib.request.urlopen(request, timeout=10)  # noqa: S310


def _search_count_eventually(
    ctx: ToolContext, dataset: str, resource_type: str, timeout: float = 30.0
) -> int:
    """HAPI FHIR's search index lags writes by a few seconds in this
    image (confirmed while building this test: a `total: 0` search
    immediately after a create, which only becomes correct a handful of
    seconds later); poll instead of asserting on the first result."""
    import time

    deadline = time.monotonic() + timeout
    last_count = -1
    while time.monotonic() < deadline:
        result = fhir_search(ctx, dataset, resource_type)
        last_count = len(result.data) if result.data else 0
        if last_count > 0:
            return last_count
        time.sleep(2)
    return last_count


@requires_docker
@requires_hapi
class TestFhirSearchAgainstRealServer:
    @pytest.fixture
    def ctx_for_real_server(self, tmp_path: Path, hapi_base_url: str) -> Iterator[ToolContext]:
        catalog = Catalog(
            {
                "onco_fhir": CatalogEntry(
                    id="onco_fhir",
                    data_class=DataClass.limited_data_set,
                    source=SourceKind.fhir,
                    base_url=hapi_base_url,
                    resource_types=["Condition"],
                )
            }
        )
        policy = PolicyEngine(_permissive_policy())
        audit = AuditLog(
            LocalFileSink(tmp_path / "audit"),
            Ed25519PrivateKey.generate(),
            session_id="s",
            principal="agent_session",
        )
        broker = ApprovalBroker(
            ApprovalStore(tmp_path / "approvals.db"), PrincipalDirectory.empty()
        )
        gateway = Gateway(
            policy=policy,
            catalog=catalog,
            audit=audit,
            approvals=broker,
            session_id="s",
            principal="agent_session",
        )
        try:
            yield ToolContext(
                gateway=gateway,
                sandbox=SandboxExecutor(SandboxConfig()),
                catalog=catalog,
                guard=OutputGuard(),
                workspace_dir=tmp_path,
            )
        finally:
            gateway.close()

    def test_search_finds_a_created_condition(
        self, ctx_for_real_server: ToolContext, hapi_base_url: str
    ) -> None:
        import json
        import uuid

        patient_id = f"synthetic-{uuid.uuid4().hex[:8]}"
        _put_fhir_resource(
            hapi_base_url,
            "Patient",
            patient_id,
            json.dumps(
                {"resourceType": "Patient", "id": patient_id, "name": [{"family": "SyntheticTest"}]}
            ).encode(),
        )
        _post_fhir_resource(
            hapi_base_url,
            "Condition",
            json.dumps(
                {
                    "resourceType": "Condition",
                    "code": {
                        "coding": [
                            {
                                "system": "http://snomed.info/sct",
                                "code": "254637007",
                                "display": "Non-small cell lung cancer",
                            }
                        ]
                    },
                    "subject": {"reference": f"Patient/{patient_id}"},
                }
            ).encode(),
        )

        count = _search_count_eventually(ctx_for_real_server, "onco_fhir", "Condition")
        assert count > 0

    def test_search_goes_through_gateway_authorize(
        self, ctx_for_real_server: ToolContext
    ) -> None:
        """Swap the policy to deny everything; confirm fhir_search is
        actually gated by Gateway.authorize, not bypassing it."""
        ctx_for_real_server.gateway.policy = PolicyEngine(
            Policy(rules=[], default=Decision.deny, model_allowlist={})
        )
        result = fhir_search(ctx_for_real_server, "onco_fhir", "Condition")
        assert result.denied is True
