"""Unit tests for OPAPolicyEngine's error paths, using injected fake
`put`/`post` callables rather than a real OPA server -- the same
dependency-injection pattern as test_notifier.py's WebhookNotifier
tests. tests/test_opa_backend.py covers the real-server integration
path; this file covers what happens when OPA (real or not) returns
something this module doesn't expect.
"""

from __future__ import annotations

import json

import pytest
import yaml

from custody.catalog import Catalog
from custody.policy.engine import ToolRequest
from custody.policy.models import Policy
from custody.policy.opa_backend import OPABackendError, OPAPolicyEngine

MINIMAL_POLICY = Policy.model_validate(
    yaml.safe_load("rules: []\ndefault: deny\nmodel_allowlist: {}\n")
)


def _ok_put(url: str, payload: bytes, timeout: float) -> int:
    return 204


class TestPushPolicyErrors:
    def test_non_2xx_status_raises(self) -> None:
        with pytest.raises(OPABackendError, match="HTTP 500"):
            OPAPolicyEngine(
                MINIMAL_POLICY,
                "http://opa.example",
                put=lambda url, payload, timeout: 500,
                post=lambda url, payload, timeout: (200, b"{}"),
            )

    def test_push_policy_can_be_called_again(self) -> None:
        calls: list[bytes] = []

        def recording_put(url: str, payload: bytes, timeout: float) -> int:
            calls.append(payload)
            return 204

        engine = OPAPolicyEngine(
            MINIMAL_POLICY, "http://opa.example", put=recording_put, post=_ok_put  # type: ignore[arg-type]
        )
        assert len(calls) == 1
        engine.push_policy()
        assert len(calls) == 2
        assert calls[0] == calls[1]


class TestEvaluateErrors:
    def test_non_200_status_raises(self) -> None:
        engine = OPAPolicyEngine(
            MINIMAL_POLICY,
            "http://opa.example",
            put=_ok_put,
            post=lambda url, payload, timeout: (503, b"service unavailable"),
        )
        with pytest.raises(OPABackendError, match="HTTP 503"):
            engine.evaluate(ToolRequest(tool="catalog.list"), Catalog.empty())

    def test_malformed_json_response_raises(self) -> None:
        engine = OPAPolicyEngine(
            MINIMAL_POLICY,
            "http://opa.example",
            put=_ok_put,
            post=lambda url, payload, timeout: (200, b"not json"),
        )
        with pytest.raises(OPABackendError, match="could not interpret"):
            engine.evaluate(ToolRequest(tool="catalog.list"), Catalog.empty())

    def test_response_missing_result_key_raises(self) -> None:
        engine = OPAPolicyEngine(
            MINIMAL_POLICY,
            "http://opa.example",
            put=_ok_put,
            post=lambda url, payload, timeout: (200, b'{"not_result": {}}'),
        )
        with pytest.raises(OPABackendError, match="could not interpret"):
            engine.evaluate(ToolRequest(tool="catalog.list"), Catalog.empty())

    def test_unknown_decision_value_raises(self) -> None:
        body = json.dumps(
            {"result": {"decision": "maybe", "matched_rule_id": None, "approvals": None}}
        ).encode()
        engine = OPAPolicyEngine(
            MINIMAL_POLICY,
            "http://opa.example",
            put=_ok_put,
            post=lambda url, payload, timeout: (200, body),
        )
        with pytest.raises(OPABackendError, match="could not interpret"):
            engine.evaluate(ToolRequest(tool="catalog.list"), Catalog.empty())

    def test_well_formed_response_does_not_raise(self) -> None:
        body = json.dumps(
            {"result": {"decision": "allow", "matched_rule_id": "r1", "approvals": None}}
        ).encode()
        engine = OPAPolicyEngine(
            MINIMAL_POLICY,
            "http://opa.example",
            put=_ok_put,
            post=lambda url, payload, timeout: (200, body),
        )
        result = engine.evaluate(ToolRequest(tool="catalog.list"), Catalog.empty())
        assert result.decision.value == "allow"
        assert result.matched_rule_id == "r1"
