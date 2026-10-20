# Roadmap

Not in v0.1 scope. Listed here instead of built so v0.1 stays small and
every claim in the README stays true on release day.

- SSO/OIDC approver identity (v0.1 uses a local `principals.yaml`)
- OPA/Cedar policy backends (v0.1 is YAML + Pydantic only)
- FHIR and OMOP connectors
- gVisor/Firecracker sandbox options (v0.1 uses standard Docker; see
  docs/threat-model.md T2)
- S3 Object Lock audit sink (the sink interface is documented and
  implemented locally in v0.1; the S3 implementation itself is not)
- Kubernetes deployment
- Signed policy bundles
- Approver mobile notifications
- Evidence-pack export mapped to common control frameworks
- A fully isolated egress allowlist proxy, if it cannot be implemented to
  the same rigor as the rest of the sandbox in time for v0.1 (see
  docs/threat-model.md T9)
