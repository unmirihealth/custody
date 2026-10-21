# Roadmap

Not in v0.1 scope. Listed here instead of built so v0.1 stayed small and
every claim in the README stayed true on release day. Items move to
"Built" below as they land; see CHANGELOG.md for exact detail on each.

- SSO/OIDC approver identity (v0.1 uses a local `principals.yaml`)
- OPA/Cedar policy backends (v0.1 is YAML + Pydantic only)
- FHIR and OMOP connectors
- ~~gVisor/Firecracker sandbox options~~ **will not be built on this
  project's current macOS development machine.** Both require a Linux
  host with KVM (gVisor's runsc needs ptrace or KVM platform support;
  Firecracker needs `/dev/kvm` directly); there is no way to build,
  run, or verify either on macOS, and shipping unverified sandbox
  isolation code would be worse than not shipping it. Revisit if this
  project ever gets a Linux CI runner or dev box with KVM. v0.1 uses
  standard Docker; see docs/threat-model.md T2.
- S3 Object Lock audit sink (the sink interface is documented and
  implemented locally in v0.1; the S3 implementation itself is not)
- Kubernetes deployment
- Approver mobile notifications
- A fully isolated egress allowlist proxy, if it cannot be implemented to
  the same rigor as the rest of the sandbox in time for v0.1 (see
  docs/threat-model.md T9)

## Built (moved here from the list above)

- **Signed policy bundles** -- `custody policy sign`/`verify`,
  `PolicyEngine.load_verified`. See docs/policy-reference.md and
  CHANGELOG.md [Unreleased].
- **Evidence-pack export mapped to common control frameworks** --
  `custody evidence export`. See docs/evidence-pack.md and
  CHANGELOG.md [Unreleased].
- **Webhook approval notifications** -- this was actually v0.1's own
  stated scope (the approval broker's three channels: CLI, local web
  UI, webhook), just not built in time for the v0.1.0 release. Not a
  roadmap item strictly speaking, listed here for the same reason: it
  was missing, now it isn't. See `custody/approvals/notifier.py` and
  CHANGELOG.md [Unreleased].
