"""A small, honest mapping from Custody's own mechanisms to a public
control framework's language. See the module docstring in
`custody.evidence.pack` for what this is and is not.

The framework used is SOC 2's Trust Services Criteria (the "Common
Criteria", CC-series, published by the AICPA), because it is public,
widely recognized, and its category names are generic enough to map
cleanly onto a tool like this rather than something healthcare
specific like the HIPAA Security Rule's numbered safeguards (which
would invite exactly the false-precision this module is trying to
avoid). This is a mapping, not an attestation: nothing here says
Custody IS SOC 2 compliant, or that a deployment using it passes any
audit. A real SOC 2 report requires an independent auditor; this
module exists to make that auditor's job of finding relevant evidence
faster, nothing more.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class ControlMapping(BaseModel):
    """One row connecting a control framework category to a concrete
    Custody mechanism, phrased the same honest way as
    docs/threat-model.md: what the mechanism does, and what it leaves
    uncovered."""

    model_config = ConfigDict(frozen=True)

    control_id: str
    framework: str
    title: str
    mechanism: str
    limitation: str


# Deliberately a small, defensible set. Every `mechanism` claim here
# must be true of the code as shipped; every `limitation` claim must
# match a real gap documented in docs/threat-model.md or ROADMAP.md.
# Do not add a row whose mechanism isn't literally implemented.
CONTROL_MAPPINGS: tuple[ControlMapping, ...] = (
    ControlMapping(
        control_id="CC6.1",
        framework="SOC 2 (AICPA Trust Services Criteria)",
        title="Logical access security measures",
        mechanism=(
            "Every tool call is evaluated by the policy engine before it runs; "
            "the policy's own default is enforced as deny at load time, not "
            "merely by convention (custody/policy/engine.py, custody/policy/models.py)."
        ),
        limitation=(
            "Approver and requester identity in v0.1 comes from a local "
            "principals.yaml, not an external identity provider; the strength "
            "of this control is bounded by how that file and its access are "
            "managed (see README.md 'What Custody is not', ROADMAP.md SSO/OIDC)."
        ),
    ),
    ControlMapping(
        control_id="CC6.3",
        framework="SOC 2 (AICPA Trust Services Criteria)",
        title="Role-based access, segregation of duties",
        mechanism=(
            "Two-person approval rules require a configurable count of "
            "distinct, role-eligible approvers; a requester can never approve "
            "their own request (custody/approvals/broker.py)."
        ),
        limitation=(
            "Role assignment itself is a manually edited YAML file; there is "
            "no workflow enforcing periodic access review in v0.1."
        ),
    ),
    ControlMapping(
        control_id="CC7.2",
        framework="SOC 2 (AICPA Trust Services Criteria)",
        title="Monitoring for anomalies and security events",
        mechanism=(
            "Every request, decision, approval event, execution, and error is "
            "written to an append-only, hash-chained audit log with periodic "
            "Ed25519-signed checkpoints (custody/audit/). `custody audit "
            "verify` recomputes the whole chain and reports the first broken "
            "link, not just a generic failure."
        ),
        limitation=(
            "Tamper-evident, not tamper-proof (docs/threat-model.md T3): an "
            "attacker with write access to the log store and enough time "
            "could still rebuild a consistent-looking chain from a point "
            "they control. v0.1 ships a local-file sink; true immutability "
            "depends on shipping checkpoints to write-once storage, which "
            "Custody documents but does not require."
        ),
    ),
    ControlMapping(
        control_id="CC7.3",
        framework="SOC 2 (AICPA Trust Services Criteria)",
        title="Evaluation and response to security events",
        mechanism=(
            "An approval decision records the approver identity, a free-text "
            "reason, and a timestamp, all written into the same hash-chained "
            "log as the request that triggered it (custody/approvals/, "
            "custody/audit/)."
        ),
        limitation=(
            "Custody records that a decision happened and by whom; it does "
            "not itself alert anyone or drive an incident response process. "
            "Wiring that up (e.g. the webhook notifier) is the integrator's "
            "job."
        ),
    ),
    ControlMapping(
        control_id="CC8.1",
        framework="SOC 2 (AICPA Trust Services Criteria)",
        title="Change management over infrastructure and configuration",
        mechanism=(
            "A policy.yaml can be cryptographically signed after review "
            "(`custody policy sign`); `custody policy verify` confirms the "
            "file in a deployment still matches what was reviewed, byte for "
            "byte (custody/policy/bundle.py)."
        ),
        limitation=(
            "Signing is opt-in and checked by a separate command in v0.1, "
            "not enforced automatically by `custody serve` on every start "
            "(see ROADMAP.md). Trust in the signing key itself is "
            "established out of band, the same as any signing scheme."
        ),
    ),
    ControlMapping(
        control_id="CC6.6",
        framework="SOC 2 (AICPA Trust Services Criteria)",
        title="Logical access restrictions over data classified by sensitivity",
        mechanism=(
            "Every dataset is classified (synthetic, deidentified, "
            "limited_data_set, identified); policy rules can key on a "
            "request's effective (most restrictive) data class, and model "
            "routing enforces a separate allowlist per class "
            "(custody/catalog.py, custody/routing.py)."
        ),
        limitation=(
            "Classification is declared in catalog.yaml by whoever configures "
            "a deployment; Custody does not inspect dataset content to infer "
            "or verify a class is correct."
        ),
    ),
)


def mappings_for(control_ids: tuple[str, ...] | None = None) -> tuple[ControlMapping, ...]:
    """All mappings, or just the ones named in `control_ids` (in the
    order given). Raises KeyError naming the first id not found."""
    if control_ids is None:
        return CONTROL_MAPPINGS
    by_id = {m.control_id: m for m in CONTROL_MAPPINGS}
    result = []
    for cid in control_ids:
        if cid not in by_id:
            raise KeyError(f"no control mapping for {cid!r}")
        result.append(by_id[cid])
    return tuple(result)
