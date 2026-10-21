"""Mock-IdP-verified approver identity: part of ROADMAP.md's "SSO/OIDC
approver identity" item. Scoped deliberately: this verifies an
already-issued ID token's signature, issuer, and expiry against a real
identity provider's JWKS, and returns the verified subject claim as the
approver's principal id. It does NOT implement a browser login flow
(no redirect/callback HTTP handling, no session cookies, no token
refresh) -- that is real additional scope, a CLI or a local web UI
getting a user through an actual OIDC authorization-code dance, not
built here. See docs/sso-oidc.md for exactly what this covers and what
it does not, and for how it was tested against a real (mock) IdP
rather than only unit-tested with a hand-rolled JWT.

Requires the optional `sso` dependency group (`pip install
custody-mcp[sso]`, `PyJWT[crypto]`); this module is never imported by
`custody.approvals`'s own `__init__`, so a deployment that never
configures OIDC never needs PyJWT installed, the same posture
`custody.audit.s3_sink` takes with boto3.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from jwt import PyJWKClient


class OidcVerificationError(Exception):
    """A token failed verification: bad signature, wrong issuer,
    expired, or (if an audience is configured) wrong audience. Carries
    a human-readable reason; never carries the raw token itself in its
    message, a JWT can embed arbitrary claims and a crash log is not
    where those should end up."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


@dataclass
class OidcVerifier:
    """One instance per configured identity provider. `jwks_url` is
    fetched (and cached) by PyJWT's own `PyJWKClient`; construct a new
    `OidcVerifier` if the IdP's signing keys rotate and the cache needs
    clearing, there is no explicit cache-busting method here.
    """

    issuer: str
    jwks_url: str
    audience: str | None = None
    subject_claim: str = "sub"
    algorithms: tuple[str, ...] = ("RS256", "RS384", "RS512", "ES256", "ES384")
    leeway_seconds: int = 0
    _jwks_client: PyJWKClient = field(init=False, repr=False)

    def __post_init__(self) -> None:
        from jwt import PyJWKClient  # local import: PyJWT is an optional dependency

        self._jwks_client = PyJWKClient(self.jwks_url)

    def verify(self, token: str) -> str:
        """Returns the verified principal id (the value of
        `subject_claim`, `sub` by default), or raises
        OidcVerificationError. A deployment that wants the IdP's email
        claim as the principal id instead of its opaque `sub` would
        construct this with `subject_claim="email"`.
        """
        import jwt

        try:
            signing_key = self._jwks_client.get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=list(self.algorithms),
                issuer=self.issuer,
                audience=self.audience,
                leeway=self.leeway_seconds,
                options={"verify_aud": self.audience is not None},
            )
        except jwt.PyJWTError as exc:
            raise OidcVerificationError(str(exc)) from exc

        principal_id = claims.get(self.subject_claim)
        if not principal_id:
            raise OidcVerificationError(f"token has no {self.subject_claim!r} claim")
        return str(principal_id)


__all__ = ["OidcVerificationError", "OidcVerifier"]
