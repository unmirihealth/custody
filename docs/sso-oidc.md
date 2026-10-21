# SSO/OIDC approver identity

v0.1 approver identity is whatever string someone types after `--as`:
the CLI trusts it outright (`custody approvals approve <id> --as
jane_steward --reason ...`), and the approval broker only checks that
string against `principals.yaml`'s roles. README.md's "What Custody is
not" has always called this out plainly: "Not SSO-backed."

`custody.approvals.oidc.OidcVerifier` is the first piece of closing
that gap: `--as-token <jwt>` is a second way to identify an approver,
one backed by a real identity provider's signature instead of a bare
trusted string.

## Scope: token verification, not a login flow

This is deliberately narrow. It verifies an **already-issued** ID
token: signature (against the IdP's real JWKS, fetched over HTTPS/HTTP
the same way any OIDC relying party would), issuer, expiry, and
(optionally) audience. It does **not** implement:

- A browser-based OIDC authorization-code flow (no redirect handling,
  no callback HTTP server).
- Session management, token refresh, or token storage.
- Wiring into the approvals web UI (`custody/approvals_ui.py`) -- that
  surface still uses its own startup-token gate, unchanged.

Getting an actual ID token into an approver's hands (a real IdP login,
a `kubectl get secret`-style side channel, whatever an organization's
SSO setup already does) is the deployment's job, same as it always has
been for any OIDC relying party that only verifies tokens rather than
running its own IdP.

## Using it

```bash
export CUSTODY_OIDC_ISSUER=https://your-idp.example.com/
export CUSTODY_OIDC_JWKS_URL=https://your-idp.example.com/.well-known/jwks.json
# optional:
export CUSTODY_OIDC_AUDIENCE=your-client-id
export CUSTODY_OIDC_SUBJECT_CLAIM=email   # default: sub

custody approvals approve <approval-id> --as-token "$ID_TOKEN" --reason "reviewed, looks fine"
```

`--as` and `--as-token` are mutually exclusive; exactly one is
required. `--as-token` fails loudly (exit 1, a clear message) if
`CUSTODY_OIDC_ISSUER` or `CUSTODY_OIDC_JWKS_URL` isn't set, or if the
token fails verification for any reason -- there is no silent fallback
to trusting the token's claims unverified.

Whatever `subject_claim` resolves to (`sub` by default) becomes the
approver's principal id, checked against `principals.yaml`'s roles
exactly as a bare `--as` string would be. **The identity is now
cryptographically backed; the authorization model (who holds which
role) is unchanged** -- `principals.yaml` is still the source of truth
for roles, OIDC only strengthens how a caller proves which identity
they claim.

## Installing it

PyJWT is optional (`pip install custody-mcp[sso]`, `PyJWT[crypto]`);
`custody.approvals.oidc` is never imported by `custody.approvals`'s own
`__init__`, the same posture `custody.audit.s3_sink` takes with boto3 --
a deployment that never configures OIDC never needs PyJWT installed.

## Using `OidcVerifier` directly

```python
from custody.approvals.oidc import OidcVerifier, OidcVerificationError

verifier = OidcVerifier(
    issuer="https://your-idp.example.com/",
    jwks_url="https://your-idp.example.com/.well-known/jwks.json",
    audience="your-client-id",       # optional; omit to skip audience checking
    subject_claim="email",           # default "sub"
    leeway_seconds=30,                # optional clock-skew tolerance
)
try:
    approver_id = verifier.verify(id_token)
except OidcVerificationError as exc:
    ...  # exc.reason is a human-readable message, never the raw token
```

One `OidcVerifier` per configured IdP; its JWKS fetch is cached by
PyJWT's own `PyJWKClient`, construct a new instance if the IdP rotates
its signing keys and the cache needs clearing.

## What is verified

`tests/test_oidc.py` runs against a real, local mock OIDC provider
(`ghcr.io/navikt/mock-oauth2-server`), not a hand-rolled JWT or a
mocked HTTP layer -- the whole point of this module is a specific
signature/issuer/audience/expiry verification against a real IdP's
real JWKS endpoint, which a self-signed test fixture could pass while
the real verification logic was subtly wrong:

- a validly signed token verifies to the expected subject claim
- a tampered signature is rejected
- a token from the wrong issuer is rejected
- a garbage string (not a JWT at all) is rejected with a clear error,
  not a crash
- an audience check, when configured, actually rejects a token that
  doesn't carry the expected (or any) `aud` claim; when NOT configured,
  the same token still verifies -- `audience` is opt-in, not implied
- a configurable `subject_claim` other than `sub` is honored, and
  rejected clearly when the claim is absent
- `leeway_seconds` is accepted without breaking a currently-valid token

`tests/test_cli.py`'s `TestApprovalsOidcToken` covers the CLI wiring
specifically (also against the real mock IdP): a verified token
actually resolves and records a real approval decision, and a tampered
token is rejected with `custody approvals approve` exiting non-zero.

A real local mock IdP was chosen over a public test IdP for the same
reason the FHIR connector and the S3 sink tests use local containers:
CI shouldn't depend on an external service's uptime, and a local
container is actually faster.
