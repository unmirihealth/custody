"""Tests against a real (local) OPA server, not a mock: the whole
point of this backend is a specific Data API push plus a specific
Rego module's actual evaluation, which a mocked HTTP layer could pass
while the real round trip was subtly wrong. `docker/opa/policy_test.rego`
(run via `opa test`, not pytest) separately proves the Rego module
itself is correct in isolation; these tests prove `OPAPolicyEngine`
talks to a real running instance of it correctly end to end.
"""

from __future__ import annotations

import time
from collections.abc import Iterator

import pytest
import yaml

from custody.catalog import Catalog
from custody.policy.engine import ToolRequest
from custody.policy.models import Policy
from custody.policy.opa_backend import OPABackendError, OPAPolicyEngine, policy_to_opa_data
from tests.conftest import requires_docker

OPA_IMAGE = "custody-opa:latest"
_PORT = 18181  # fixed, unusual port: avoids clashing with a developer's own 8181


def _opa_image_available() -> bool:
    try:
        import docker

        client = docker.from_env()
        client.ping()
        client.images.get(OPA_IMAGE)
        return True
    except Exception:  # noqa: BLE001
        return False


requires_opa_image = pytest.mark.skipif(
    not _opa_image_available(),
    reason=(
        f"{OPA_IMAGE} not built locally "
        f"(docker build -f docker/opa.Dockerfile -t {OPA_IMAGE} .)"
    ),
)


@pytest.fixture(scope="module")
def opa_url() -> Iterator[str]:
    import docker

    client = docker.from_env()
    name = "custody-test-opa"
    try:
        client.containers.get(name).remove(force=True)
    except docker.errors.NotFound:
        pass

    container = client.containers.run(
        OPA_IMAGE, detach=True, name=name, ports={"8181/tcp": _PORT}
    )
    url = f"http://localhost:{_PORT}"
    try:
        _wait_for_ready(url)
        yield url
    finally:
        container.remove(force=True)


def _wait_for_ready(url: str, timeout: float = 15.0) -> None:
    import urllib.error
    import urllib.request

    deadline = time.monotonic() + timeout
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            urllib.request.urlopen(f"{url}/health", timeout=1)  # noqa: S310
            return
        except (urllib.error.URLError, OSError) as exc:
            last_exc = exc
            time.sleep(0.3)
    raise RuntimeError(f"OPA never became ready: {last_exc}")


def _load_policy(yaml_text: str) -> Policy:
    return Policy.model_validate(yaml.safe_load(yaml_text))


POLICY_YAML = """
rules:
  - id: catalog-list-ok
    when: { tool: catalog.list }
    decision: allow
  - id: deid-ok
    when: { max_data_class: deidentified }
    decision: allow
  - id: identified-needs-approval
    when: { tool: sql.query, min_data_class: identified }
    decision: require_approval
    approvals: { count: 1, roles: [data_steward] }
  - id: no-egress
    when: { egress: true }
    decision: deny
default: deny
model_allowlist:
  identified: ["ollama/*"]
"""

CATALOG_YAML = """
datasets:
  - id: tumor_registry_deid
    data_class: deidentified
    path: data/dummy.csv
    format: csv
  - id: tumor_registry_identified
    data_class: identified
    path: data/dummy.csv
    format: csv
"""


@pytest.fixture
def catalog(tmp_path) -> Catalog:  # type: ignore[no-untyped-def]
    catalog_path = tmp_path / "catalog.yaml"
    catalog_path.write_text(CATALOG_YAML)
    return Catalog.load(catalog_path)


@requires_docker
@requires_opa_image
class TestOPAPolicyEngine:
    def test_tool_rule_allows(self, opa_url: str, catalog: Catalog) -> None:
        engine = OPAPolicyEngine(_load_policy(POLICY_YAML), opa_url)
        result = engine.evaluate(ToolRequest(tool="catalog.list"), catalog)
        assert result.decision.value == "allow"
        assert result.matched_rule_id == "catalog-list-ok"

    def test_deidentified_query_allowed(self, opa_url: str, catalog: Catalog) -> None:
        engine = OPAPolicyEngine(_load_policy(POLICY_YAML), opa_url)
        result = engine.evaluate(
            ToolRequest(tool="sql.query", datasets=["tumor_registry_deid"]), catalog
        )
        assert result.decision.value == "allow"
        assert result.matched_rule_id == "deid-ok"

    def test_identified_query_requires_approval(self, opa_url: str, catalog: Catalog) -> None:
        engine = OPAPolicyEngine(_load_policy(POLICY_YAML), opa_url)
        result = engine.evaluate(
            ToolRequest(tool="sql.query", datasets=["tumor_registry_identified"]), catalog
        )
        assert result.decision.value == "require_approval"
        assert result.approvals is not None
        assert result.approvals.count == 1
        assert result.approvals.roles == ["data_steward"]

    def test_unknown_tool_denies_by_falling_through_to_default(
        self, opa_url: str, catalog: Catalog
    ) -> None:
        engine = OPAPolicyEngine(_load_policy(POLICY_YAML), opa_url)
        result = engine.evaluate(ToolRequest(tool="nobody.registered.this"), catalog)
        assert result.decision.value == "deny"
        assert result.matched_rule_id is None

    def test_check_model_does_not_require_opa_to_be_reachable(
        self, opa_url: str, catalog: Catalog
    ) -> None:
        """check_model is deliberately pure Python (see the module
        docstring); confirms it still returns the right answer even
        though it never touches opa_url."""
        engine = OPAPolicyEngine(_load_policy(POLICY_YAML), opa_url)
        from custody.catalog import DataClass

        allowed = engine.check_model(DataClass.identified, "ollama/llama3")
        denied = engine.check_model(DataClass.identified, "gpt-4o")
        assert allowed.allowed is True
        assert denied.allowed is False

    def test_two_engines_sharing_one_opa_server_DO_cross_contaminate(
        self, opa_url: str, catalog: Catalog
    ) -> None:
        """Deliberately documents a sharp edge rather than letting it be
        discovered by surprise: there is one `policy_input` data path
        per OPA server, not one per `OPAPolicyEngine` instance.
        Constructing `engine_b` against the SAME `opa_url` overwrites
        the data `engine_a` depends on; `engine_a.policy` (the Python
        object) is unaffected, but `engine_a.evaluate()` immediately
        starts reflecting engine_b's policy until something re-pushes
        engine_a's own data. One OPA server should serve one logical
        Custody deployment's policy at a time, same as one
        `LocalFileSink` directory should back one deployment's audit
        log."""
        engine_a = OPAPolicyEngine(_load_policy(POLICY_YAML), opa_url)
        first_result = engine_a.evaluate(ToolRequest(tool="catalog.list"), catalog)
        assert first_result.decision.value == "allow"

        stricter_yaml = """
rules: []
default: deny
model_allowlist: {}
"""
        engine_b = OPAPolicyEngine(_load_policy(stricter_yaml), opa_url)
        assert engine_b.policy.rules == []

        # engine_a's own in-memory Policy object is unchanged...
        assert engine_a.policy.rules != []
        # ...but querying through it now sees engine_b's pushed data.
        result_after_b = engine_a.evaluate(ToolRequest(tool="catalog.list"), catalog)
        assert result_after_b.decision.value == "deny"

        # Re-pushing engine_a's own (unchanged) policy restores it.
        engine_a.push_policy()
        result_after_repush = engine_a.evaluate(ToolRequest(tool="catalog.list"), catalog)
        assert result_after_repush.decision.value == "allow"

    def test_unreachable_opa_raises_a_clear_error(self, catalog: Catalog) -> None:
        with pytest.raises(OPABackendError):
            OPAPolicyEngine(_load_policy(POLICY_YAML), "http://localhost:1")

    def test_drop_in_for_gateway(self, opa_url: str, fixtures_dir) -> None:  # type: ignore[no-untyped-def]
        """The actual point of `PolicyBackend`: a real `Gateway`, built
        exactly like test_gateway.py's own fixture, works unmodified
        with `OPAPolicyEngine` in place of `PolicyEngine`."""
        import tempfile
        from datetime import timedelta
        from pathlib import Path

        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        from custody.approvals import ApprovalBroker
        from custody.audit import AuditLog, LocalFileSink
        from custody.catalog import Catalog as RealCatalog
        from custody.gateway import Gateway
        from custody.policy.engine import PolicyEngine

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            catalog = RealCatalog.load(fixtures_dir / "catalog.yaml")
            local_engine = PolicyEngine.load(fixtures_dir / "policy.yaml")
            opa_engine = OPAPolicyEngine(local_engine.policy, opa_url)
            audit = AuditLog(
                LocalFileSink(tmp_path / "audit"),
                Ed25519PrivateKey.generate(),
                session_id="test-session",
                principal="agent_session",
            )
            broker = ApprovalBroker.open(
                tmp_path / "approvals.db", fixtures_dir / "principals.yaml"
            )

            gw = Gateway(
                policy=opa_engine,
                catalog=catalog,
                audit=audit,
                approvals=broker,
                session_id="test-session",
                principal="agent_session",
                approval_poll_interval=timedelta(milliseconds=1),
                approval_sleep=lambda _s: None,
            )
            try:
                allowed = gw.authorize("catalog.list")
                assert allowed.allowed is True
                assert allowed.policy_result.matched_rule_id == "catalog-list-ok"

                denied = gw.authorize("nobody.registered.this")
                assert denied.allowed is False
            finally:
                gw.close()

    def test_policy_to_opa_data_shape(self) -> None:
        policy = _load_policy(POLICY_YAML)
        data = policy_to_opa_data(policy)
        assert data["default"] == "deny"
        ids = [r["id"] for r in data["rules"]]
        assert ids == ["catalog-list-ok", "deid-ok", "identified-needs-approval", "no-egress"]
        approval_rule = next(r for r in data["rules"] if r["id"] == "identified-needs-approval")
        assert approval_rule["when"] == {"tool": "sql.query", "min_rank": 3}
        assert approval_rule["approvals"] == {"count": 1, "roles": ["data_steward"]}
