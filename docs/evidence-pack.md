# Evidence-pack export

`custody evidence export <dest-dir>` turns an audit log and (if present)
a signed policy bundle into a directory a compliance reviewer can
actually open and use, instead of asking them to run `custody audit
tail` and squint.

## What this is

A mechanical data transform. Everything in a pack is derived from what
the audit log and policy file already contain:

- `manifest.json` -- a structured summary: the time window, counts of
  each audit event type, counts of each policy decision (allow / deny
  / require_approval), the result of `custody audit verify` run fresh
  against the log, the signed policy bundle's details if one covers
  the current `policy.yaml`, and a set of control mappings (see
  below).
- `README.md` -- the same information, rendered for a human.
- `audit_export.jsonl` -- every audit entry in the window, one JSON
  object per line (same format as `custody audit export`).
- `policy.yaml` and `policy.yaml.sig.json` -- copied in if a policy
  file (and its signed bundle) are present at the deployment root.

Re-running export on the same inputs reproduces the same counts and
mappings (`generated_at` is the only thing that changes); nothing here
adds a new source of truth, it only summarizes the audit log and
policy that already exist.

```bash
custody evidence export ./evidence-2026-10 --dir . \
  --since 2026-10-01T00:00:00+00:00 --until 2026-10-31T23:59:59+00:00
# wrote evidence pack to evidence-2026-10
# 142 entries, audit integrity: OK
```

`--dest` must be a new or currently-empty directory; export refuses to
write into one that already has files in it, so an old pack's content
is never silently mixed with a new one.

## What this is NOT

**Not a certification. Not an audit. Not proof that a specific control
framework's requirements are fully met.** Every pack carries this same
disclaimer (`manifest.json`'s `disclaimer` field, and the top of
`README.md`), because a pack handed off to someone who never reads
this doc should still say so itself.

## Control mappings

`custody/evidence/framework.py` defines a small, fixed set of mappings
from Custody's own mechanisms to SOC 2's Trust Services Criteria (the
AICPA's public "Common Criteria," CC-series). SOC 2 was chosen over
something healthcare-specific like the HIPAA Security Rule's numbered
safeguards because its category names are generic enough to map
honestly onto a tool like this; mapping to HIPAA's actual safeguards
would invite a precision this project cannot back up (Custody is not
a covered entity or business associate in its own right, see README's
"What Custody is not").

Each mapping has four parts, in the same honest style as
docs/threat-model.md's Mitigation/Residual-risk columns:

| Field | Meaning |
|---|---|
| `control_id` | the SOC 2 Common Criteria id (e.g. `CC7.2`) |
| `title` | that criteria's plain-language name |
| `mechanism` | the specific Custody code that provides relevant evidence |
| `limitation` | what that mechanism does NOT cover |

Every `mechanism` claim must be literally true of the shipped code;
every `limitation` claim must match a real, already-documented gap
(docs/threat-model.md or ROADMAP.md). Do not add a row whose mechanism
isn't actually implemented, and do not soften a limitation to make a
mapping look stronger than it is -- this list exists specifically so
nobody has to take Custody's word for a compliance claim; it is
supposed to be checkable against the code.

The CLI command always includes every mapping. To export a narrower
pack with only specific controls (e.g. just the ones a particular
reviewer asked about), call `custody.evidence.write_evidence_pack(...,
control_ids=("CC7.2", "CC8.1"))` directly rather than through the CLI;
an unrecognized id is dropped rather than raised, when going through
`write_evidence_pack`, see `custody.evidence.framework.mappings_for`
for the strict (raises on an unknown id) variant used internally.

## Using `build_manifest` without writing a pack

```python
from custody.audit import LocalFileSink
from custody.evidence import build_manifest

sink = LocalFileSink(Path(".custody/audit"))
manifest = build_manifest(sink, policy_path=Path("policy.yaml"))
print(manifest.decision_counts)
```

Useful for a quick check (how many denials this week?) without writing
anything to disk.
