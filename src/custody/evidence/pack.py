"""Evidence-pack export: turn an audit log and a policy file into a
directory a compliance reviewer or auditor can actually use, instead of
making them run `custody audit tail` and squint.

What this IS: a data transform. Everything in a pack is derived,
mechanically and reproducibly, from what the audit log and policy
already contain; this module adds no new recording, no new source of
truth. Re-running export on the same inputs produces the same
`manifest.json` (modulo `generated_at`).

What this is NOT: a certification, an audit, or a claim that a
deployment passes any specific framework's requirements. Every control
mapping in `custody.evidence.framework` is written the same honest way
as docs/threat-model.md, naming both a real mechanism and its real
limitation. `write_evidence_pack` stamps that honesty into the pack
itself (see `_DISCLAIMER` below) so it survives being handed to someone
who never reads this docstring.
"""

from __future__ import annotations

import shutil
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from custody.audit import AuditEntry, AuditSink, EventType, VerifyResult, verify_sink
from custody.evidence.framework import CONTROL_MAPPINGS, ControlMapping
from custody.policy.bundle import SignedPolicyBundle, bundle_path_for

_DISCLAIMER = (
    "This evidence pack is a mechanical export of what Custody's audit log "
    "and policy file already contain. It is not a certification, not an "
    "audit opinion, and not proof that any specific control framework's "
    "requirements are fully met. Each control mapping below names both "
    "the mechanism it draws on and that mechanism's documented limitation; "
    "read both. A real compliance determination requires a qualified "
    "reviewer and, for most frameworks, an independent auditor."
)


class EventTypeCounts(BaseModel):
    model_config = ConfigDict(frozen=True)

    request: int = 0
    decision: int = 0
    approval: int = 0
    execution: int = 0
    result: int = 0
    error: int = 0


class DecisionCounts(BaseModel):
    """Counts from `decision` entries specifically, keyed by the
    decision value (allow / deny / require_approval). Unknown values
    (there shouldn't be any, Decision is a closed enum) are dropped
    rather than crashing the export; an audit log being summarized is
    exactly the wrong place to raise on a surprise."""

    model_config = ConfigDict(frozen=True)

    allow: int = 0
    deny: int = 0
    require_approval: int = 0


class EvidencePackManifest(BaseModel):
    """The structured summary written as `manifest.json`. Everything in
    a pack's human-readable README.md is derived from this, so a tool
    ingesting a pack programmatically only needs to parse this file."""

    model_config = ConfigDict(frozen=True)

    generated_at: datetime
    window_since: datetime | None
    window_until: datetime | None
    entries_in_window: int
    event_type_counts: EventTypeCounts
    decision_counts: DecisionCounts
    audit_integrity: VerifyResult
    policy_bundle: SignedPolicyBundle | None
    control_mappings: tuple[ControlMapping, ...]
    disclaimer: str = _DISCLAIMER


def _event_type_counts(entries: list[AuditEntry]) -> EventTypeCounts:
    counts = {t.value: 0 for t in EventType}
    for e in entries:
        counts[e.event_type.value] += 1
    return EventTypeCounts(**counts)


def _decision_counts(entries: list[AuditEntry]) -> DecisionCounts:
    counts = {"allow": 0, "deny": 0, "require_approval": 0}
    for e in entries:
        if e.event_type != EventType.decision:
            continue
        value = e.payload.get("decision")
        if value in counts:
            counts[value] += 1
    return DecisionCounts(**counts)


def build_manifest(
    sink: AuditSink,
    *,
    policy_path: Path | None = None,
    bundle_path: Path | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    control_ids: tuple[str, ...] | None = None,
) -> EvidencePackManifest:
    """Build the manifest without writing anything to disk. Useful on
    its own (e.g. to check a window's counts) as well as via
    `write_evidence_pack` below.
    """
    all_entries = list(sink.read_entries())
    entries = [
        e
        for e in all_entries
        if (since is None or e.timestamp >= since) and (until is None or e.timestamp <= until)
    ]

    integrity = verify_sink(sink)

    bundle: SignedPolicyBundle | None = None
    if policy_path is not None:
        resolved_bundle_path = bundle_path or bundle_path_for(policy_path)
        if resolved_bundle_path.exists():
            bundle = SignedPolicyBundle.model_validate_json(resolved_bundle_path.read_text())

    mappings = CONTROL_MAPPINGS
    if control_ids is not None:
        by_id = {m.control_id: m for m in CONTROL_MAPPINGS}
        mappings = tuple(by_id[c] for c in control_ids if c in by_id)

    return EvidencePackManifest(
        generated_at=datetime.now(UTC),
        window_since=since,
        window_until=until,
        entries_in_window=len(entries),
        event_type_counts=_event_type_counts(entries),
        decision_counts=_decision_counts(entries),
        audit_integrity=integrity,
        policy_bundle=bundle,
        control_mappings=mappings,
    )


def _render_readme(manifest: EvidencePackManifest) -> str:
    lines = [
        "# Custody evidence pack",
        "",
        manifest.disclaimer,
        "",
        f"Generated: {manifest.generated_at.isoformat()}",
    ]
    if manifest.window_since or manifest.window_until:
        lines.append(
            f"Window: {manifest.window_since.isoformat() if manifest.window_since else '(start)'} "
            f"to {manifest.window_until.isoformat() if manifest.window_until else '(end)'}"
        )
    lines += [
        f"Entries in window: {manifest.entries_in_window}",
        "",
        "## Audit integrity",
        "",
        f"`custody audit verify` result: {'OK' if manifest.audit_integrity.ok else 'BROKEN'}",
        f"- entries checked: {manifest.audit_integrity.entries_checked}",
        f"- checkpoints checked: {manifest.audit_integrity.checkpoints_checked}",
    ]
    if not manifest.audit_integrity.ok:
        lines.append(
            f"- **first broken entry: seq {manifest.audit_integrity.first_broken_seq}** "
            f"({manifest.audit_integrity.reason})"
        )
    lines += [
        "",
        "## Decision counts",
        "",
        f"- allow: {manifest.decision_counts.allow}",
        f"- deny: {manifest.decision_counts.deny}",
        f"- require_approval: {manifest.decision_counts.require_approval}",
        "",
        "## Policy bundle",
        "",
    ]
    if manifest.policy_bundle is None:
        lines.append(
            "No signed policy bundle found. See docs/policy-reference.md "
            "(`custody policy sign`) to produce one for a future export."
        )
    else:
        lines += [
            f"- policy sha256: `{manifest.policy_bundle.policy_sha256}`",
            f"- signed at: {manifest.policy_bundle.signed_at.isoformat()}",
            f"- signed by public key: `{manifest.policy_bundle.public_key}`",
            "",
            "`policy.yaml` and `policy.yaml.sig.json` in this pack are the exact "
            "files this entry covers; re-run `custody policy verify policy.yaml` "
            "against them to confirm.",
        ]
    lines += ["", "## Control mappings", ""]
    for m in manifest.control_mappings:
        lines += [
            f"### {m.control_id} -- {m.title} ({m.framework})",
            "",
            f"**Mechanism:** {m.mechanism}",
            "",
            f"**Limitation:** {m.limitation}",
            "",
        ]
    lines += [
        "## Files in this pack",
        "",
        "- `manifest.json` -- the structured form of everything above",
        "- `audit_export.jsonl` -- every audit entry in the window, one JSON object per line",
        "- `policy.yaml`, `policy.yaml.sig.json` -- copied if present",
        "",
    ]
    return "\n".join(lines)


def write_evidence_pack(
    dest_dir: Path,
    sink: AuditSink,
    *,
    policy_path: Path | None = None,
    bundle_path: Path | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    control_ids: tuple[str, ...] | None = None,
) -> EvidencePackManifest:
    """Write a complete evidence pack to `dest_dir` (created if needed;
    refuses to write into a non-empty existing directory to avoid
    silently mixing an old pack's files with a new one). Returns the
    manifest that was written.
    """
    if dest_dir.exists() and any(dest_dir.iterdir()):
        raise FileExistsError(f"{dest_dir} already exists and is not empty")
    dest_dir.mkdir(parents=True, exist_ok=True)

    manifest = build_manifest(
        sink,
        policy_path=policy_path,
        bundle_path=bundle_path,
        since=since,
        until=until,
        control_ids=control_ids,
    )

    (dest_dir / "manifest.json").write_text(manifest.model_dump_json(indent=2) + "\n")
    (dest_dir / "README.md").write_text(_render_readme(manifest))

    all_entries = list(sink.read_entries())
    entries = [
        e
        for e in all_entries
        if (since is None or e.timestamp >= since) and (until is None or e.timestamp <= until)
    ]
    with (dest_dir / "audit_export.jsonl").open("w", encoding="utf-8") as f:
        for e in entries:
            f.write(e.model_dump_json())
            f.write("\n")

    if policy_path is not None and policy_path.exists():
        shutil.copy(policy_path, dest_dir / policy_path.name)
        resolved_bundle_path = bundle_path or bundle_path_for(policy_path)
        if resolved_bundle_path.exists():
            shutil.copy(resolved_bundle_path, dest_dir / resolved_bundle_path.name)

    return manifest


__all__ = [
    "DecisionCounts",
    "EventTypeCounts",
    "EvidencePackManifest",
    "build_manifest",
    "write_evidence_pack",
]
