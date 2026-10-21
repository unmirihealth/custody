# Roadmap

Not in v0.1 scope. Listed here instead of built so v0.1 stayed small and
every claim in the README stayed true on release day. Items move to
"Built" below as they land; see CHANGELOG.md for exact detail on each.

- Cedar policy backend (OPA is built, see Built below; policy.yaml plus
  the default `PolicyEngine` remains the baseline either way)
- OMOP CDM connector (FHIR is built, see Built below; a relational
  common data model is a different problem from FHIR's REST/resource
  model, not an extension of the same connector)
- ~~gVisor/Firecracker sandbox options~~ **will not be built on this
  project's current macOS development machine.** Both require a Linux
  host with KVM (gVisor's runsc needs ptrace or KVM platform support;
  Firecracker needs `/dev/kvm` directly); there is no way to build,
  run, or verify either on macOS, and shipping unverified sandbox
  isolation code would be worse than not shipping it. Revisit if this
  project ever gets a Linux CI runner or dev box with KVM. v0.1 uses
  standard Docker; see docs/threat-model.md T2.
- Approver mobile notifications

## Built (moved here from the list above)

- **Signed policy bundles** -- `custody policy sign`/`verify`,
  `PolicyEngine.load_verified`. See docs/policy-reference.md and
  CHANGELOG.md [Unreleased].
- **Evidence-pack export mapped to common control frameworks** --
  `custody evidence export`. See docs/evidence-pack.md and
  CHANGELOG.md [Unreleased].
- **OPA policy backend** -- `custody.policy.opa_backend.OPAPolicyEngine`,
  evaluating the same `policy.yaml` through a real OPA server instead
  of in-process. Verified against a real OPA container, plus the Rego
  module's own `opa test` suite. Cedar remains deferred above. See
  docs/opa-policy-backend.md and CHANGELOG.md [Unreleased].
- **FHIR connector** -- `fhir.search`, `custody.catalog.SourceKind
  .fhir`. FHIR only, not OMOP CDM (split out above). Verified against
  a real local HAPI FHIR server. See docs/fhir-connector.md and
  CHANGELOG.md [Unreleased].
- **Kubernetes deployment** -- `k8s/` (plain manifests, no Helm
  chart), `docker/custody.Dockerfile`, `custody serve --transport
  streamable-http`. Single replica by design; sandbox execution tools
  need a deployment-provided Docker daemon, not wired up by default.
  Verified against a real local `kind` cluster, including a signing-
  key-survives-a-restart check and a real MCP handshake through the
  Service; `.github/workflows/k8s-smoke.yml` runs the same script in
  CI. See docs/kubernetes.md and CHANGELOG.md [Unreleased].
- **S3 Object Lock audit sink** -- `custody.audit.s3_sink
  .S3ObjectLockSink`. Verified against real LocalStack for
  read/write/list/ordering correctness; the retention guarantee itself
  is explicitly NOT verified in this environment (LocalStack Community
  does not enforce Object Lock), see docs/s3-object-lock-sink.md for
  exactly what that means. CHANGELOG.md [Unreleased].
- **A fully isolated egress allowlist proxy** --
  `custody.sandbox.egress_proxy`, `SandboxConfig.egress_allowlist`. See
  docs/egress-proxy.md, docs/threat-model.md T9, and CHANGELOG.md
  [Unreleased].
- **SSO/OIDC approver identity** -- partial: `custody.approvals.oidc
  .OidcVerifier`, `custody approvals approve/deny --as-token`. Token
  verification only (signature, issuer, expiry, optional audience,
  against a real IdP's JWKS); no browser login flow, no session
  management, the approvals web UI is unaffected.
  `principals.yaml` remains the one source of truth for roles.
  Verified against a real local mock OIDC provider
  (`ghcr.io/navikt/mock-oauth2-server`). See docs/sso-oidc.md and
  CHANGELOG.md [Unreleased].
- **Webhook approval notifications** -- this was actually v0.1's own
  stated scope (the approval broker's three channels: CLI, local web
  UI, webhook), just not built in time for the v0.1.0 release. Not a
  roadmap item strictly speaking, listed here for the same reason: it
  was missing, now it isn't. See `custody/approvals/notifier.py` and
  CHANGELOG.md [Unreleased].
