# The OPA policy backend's server image (custody.policy.opa_backend,
# ROADMAP.md's "OPA/Cedar policy backends" item). Bakes the fixed Rego
# evaluator in at build time so a deployment does not need to manage a
# separate bundle or volume mount; the per-deployment policy.yaml is
# uploaded at runtime through OPA's own Data API, not baked into this
# image, see docs/opa-policy-backend.md.
FROM openpolicyagent/opa:latest-static

COPY docker/opa/policy.rego /policies/policy.rego

ENTRYPOINT ["/opa", "run", "--server", "--addr", "0.0.0.0:8181", "/policies"]
