"""Tests against a real (mock) OIDC provider, not a hand-rolled JWT:
the whole point of OidcVerifier is a specific signature/issuer/expiry
verification against a REAL IdP's REAL JWKS endpoint, which a
self-signed test fixture could pass while the real verification logic
was subtly wrong (e.g. accepting the wrong algorithm, not actually
fetching the JWKS, trusting an unsigned token). See
docs/sso-oidc.md for what this is and is not (no login flow, no
session management).
"""

from __future__ import annotations

import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterator

import pytest

from custody.approvals.oidc import OidcVerificationError, OidcVerifier
from tests.conftest import requires_docker

MOCK_OIDC_IMAGE = "ghcr.io/navikt/mock-oauth2-server:2.1.10"
_PORT = 18444  # fixed, unusual port: avoids clashing with a developer's own


def _mock_oidc_available() -> bool:
    try:
        import docker

        docker.from_env().ping()
        return True
    except Exception:  # noqa: BLE001
        return False


requires_mock_oidc = pytest.mark.skipif(
    not _mock_oidc_available(), reason="Docker daemon not reachable"
)


@pytest.fixture(scope="module")
def issuer_url() -> Iterator[str]:
    import docker

    client = docker.from_env()
    name = "custody-test-oidc"
    try:
        client.containers.get(name).remove(force=True)
    except docker.errors.NotFound:
        pass

    container = client.containers.run(
        MOCK_OIDC_IMAGE, detach=True, name=name, ports={"8080/tcp": _PORT}
    )
    url = f"http://localhost:{_PORT}/default"
    try:
        _wait_for_ready(url)
        yield url
    finally:
        container.remove(force=True)


def _wait_for_ready(issuer: str, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            urllib.request.urlopen(f"{issuer}/.well-known/openid-configuration", timeout=2)  # noqa: S310
            return
        except (urllib.error.URLError, OSError) as exc:
            last_exc = exc
            time.sleep(1)
    raise RuntimeError(f"mock OIDC server never became ready: {last_exc}")


def _mint_token(issuer: str, client_id: str) -> str:
    """The mock server's client_credentials grant echoes `client_id`
    as the token's `sub` claim -- used here as a stand-in for "the
    approver this token identifies", since minting a token with an
    arbitrary custom claim isn't this server's primary test surface,
    and `sub` is exactly the claim a real deployment would configure
    `subject_claim` to anyway."""
    body = urllib.parse.urlencode(
        {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": "test-secret",
            "scope": "openid",
        }
    ).encode()
    request = urllib.request.Request(f"{issuer}/token", data=body, method="POST")  # noqa: S310
    with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310
        import json

        return str(json.load(response)["access_token"])


@requires_docker
@requires_mock_oidc
class TestOidcVerifier:
    def test_valid_token_verifies_to_the_subject_claim(self, issuer_url: str) -> None:
        token = _mint_token(issuer_url, "jane_steward")
        verifier = OidcVerifier(issuer=issuer_url, jwks_url=f"{issuer_url}/jwks")
        assert verifier.verify(token) == "jane_steward"

    def test_tampered_signature_rejected(self, issuer_url: str) -> None:
        token = _mint_token(issuer_url, "jane_steward")
        tampered = token[:-5] + ("a" if token[-5] != "a" else "b") + token[-4:]
        verifier = OidcVerifier(issuer=issuer_url, jwks_url=f"{issuer_url}/jwks")
        with pytest.raises(OidcVerificationError):
            verifier.verify(tampered)

    def test_wrong_issuer_rejected(self, issuer_url: str) -> None:
        token = _mint_token(issuer_url, "jane_steward")
        verifier = OidcVerifier(issuer="http://not-the-real-issuer", jwks_url=f"{issuer_url}/jwks")
        with pytest.raises(OidcVerificationError, match="issuer"):
            verifier.verify(token)

    def test_garbage_token_rejected_not_a_bare_exception(self, issuer_url: str) -> None:
        verifier = OidcVerifier(issuer=issuer_url, jwks_url=f"{issuer_url}/jwks")
        with pytest.raises(OidcVerificationError):
            verifier.verify("not.a.jwt")

    def test_audience_enforced_only_when_configured(self, issuer_url: str) -> None:
        token = _mint_token(issuer_url, "jane_steward")
        # No audience configured: a token with no aud claim still verifies.
        lenient = OidcVerifier(issuer=issuer_url, jwks_url=f"{issuer_url}/jwks")
        assert lenient.verify(token) == "jane_steward"
        # Audience configured, but the token carries no aud claim at all:
        # PyJWT's own "token has no aud claim" rejection, surfaced as ours.
        strict = OidcVerifier(
            issuer=issuer_url, jwks_url=f"{issuer_url}/jwks", audience="some-required-audience"
        )
        with pytest.raises(OidcVerificationError):
            strict.verify(token)

    def test_custom_subject_claim(self, issuer_url: str) -> None:
        token = _mint_token(issuer_url, "priya_privacy")
        verifier = OidcVerifier(
            issuer=issuer_url, jwks_url=f"{issuer_url}/jwks", subject_claim="sub"
        )
        assert verifier.verify(token) == "priya_privacy"

    def test_missing_subject_claim_rejected(self, issuer_url: str) -> None:
        token = _mint_token(issuer_url, "jane_steward")
        verifier = OidcVerifier(
            issuer=issuer_url, jwks_url=f"{issuer_url}/jwks", subject_claim="email"
        )
        with pytest.raises(OidcVerificationError, match="no 'email' claim"):
            verifier.verify(token)

    def test_leeway_is_accepted_without_breaking_a_valid_token(self, issuer_url: str) -> None:
        token = _mint_token(issuer_url, "jane_steward")
        verifier = OidcVerifier(
            issuer=issuer_url, jwks_url=f"{issuer_url}/jwks", leeway_seconds=30
        )
        assert verifier.verify(token) == "jane_steward"
