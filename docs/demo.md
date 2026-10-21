# Demo walkthrough

```bash
docker build -f docker/sandbox.Dockerfile -t custody-sandbox:duckdb .
custody demo
```

Builds a sandbox image with DuckDB in it (one-time, a few seconds),
then runs the full scripted scenario end to end on your laptop. No
network access required, no cloud account, no real patient data
anywhere. Below is an actual run, lightly trimmed, with notes on what
each step demonstrates.

## 1-2. Setup

```
[1/8] Generating a synthetic tumor registry (5,000 patients, fixed seed)...
  wrote data/tumor_registry_deidentified.synthetic.csv
  wrote data/tumor_registry_identified.synthetic.csv  (fake MRNs and names, clearly synthetic)

[2/8] Writing the sample policy, catalog, and principals...
  wrote policy.yaml, catalog.yaml, principals.yaml
```

5,000 synthetic patients, fixed seed (`custody/demo/synthetic_data.py`)
so the run is reproducible. Two CSVs: a de-identified variant and an
identified variant with generated (clearly fake) MRNs and patient
names added. The policy, catalog, and principals this run uses are
also written to disk (`policy.yaml` etc. under the demo directory), so
you can open and read exactly what's governing the scenario, not just
take the walkthrough's word for it.

## 3. An allowed, unconditional call

```
[3/8] Agent lists the catalog...
  -> allowed: [{'id': 'tumor_registry_deidentified', ...}, {'id': 'tumor_registry_identified', ...}]
```

`catalog.list` has an unconditional `allow` rule, metadata only, no
dataset content.

## 4. A de-identified query, correctly NOT suppressed

```
[4/8] Agent runs a cohort query on de-identified data (stage IV lung, four biomarkers
positive, grouped by treatment line -- narrow enough that some cells land under the
suppression minimum)...
  -> allowed (de-identified data isn't small-cell suppressed, the guard only applies
     at limited_data_set and above): [{'group': {'treatment_line': '1L'}, 'count': 12,
     'suppressed': False}, {'group': {'treatment_line': '3L+'}, 'count': 7, 'suppressed':
     False}, {'group': {'treatment_line': '2L'}, 'count': 3, 'suppressed': False}]
```

The query is deliberately narrow (four biomarkers all positive) so
some of these counts would be small enough to suppress if this were
`limited_data_set` or `identified` data. It's not, this dataset is
`deidentified`, and the output guard's own design only suppresses at
`limited_data_set` and above (`custody/guard.py`), so every count
comes back as-is. That's not a gap, it's the guard doing what it's
specified to do, step 5 shows the same numbers through the guard for
real.

## 5. The same query, on identified data: held, approved, suppressed

```
[5/8] Agent runs the SAME cohort breakdown on the identified table (this time the
guard applies)...
  -> held for approval (identified-query-needs-approval, 1 of [data_steward])
  [simulated human] dr_steward approved it: 'routine QA spot-check, authorized by
     team lead' (step 5)
  -> allowed: [{'group': {'treatment_line': '1L'}, 'count': 12, 'suppressed': False},
     {'group': {'treatment_line': '3L+'}, 'count': None, 'suppressed': True},
     {'group': {'treatment_line': '2L'}, 'count': None, 'suppressed': True}]
```

Same query, same underlying numbers (12 / 7 / 3), but this time
against the `identified` dataset. The policy's
`identified-query-needs-approval` rule holds it for one `data_steward`
approval before it runs at all, and once it does run, the two cells
under the minimum (7 and 3) come back with `count: null, suppressed:
true` instead of their real values; 12 clears the minimum and passes
through.

**This approval is simulated** for a one-shot, non-interactive `custody
demo` (`custody/demo/scenario.py` decides it directly through the
broker on a background thread, narrated as simulated so it reads as
what it is). Run `custody ui` against the same directory yourself
to approve or deny something for real instead.

## 6. A two-person approval, denied

```
[6/8] Agent tries to export identified rows (export-two-person: 2 of [data_steward,
privacy_officer])...
  [simulated human] dr_privacy denied it: 'export scope too broad for a routine QA
     check, re-submit with a narrower cohort' (step 6)
  -> DENIED: approval denied
```

Exporting identified rows needs two distinct approvers
(`data_steward` and `privacy_officer`). A single denial from either
one resolves the whole request to denied immediately, fail-fast, it
does not wait to see what the other approver might have said.

## 7. Sandbox network isolation

```
[7/8] Agent tries to reach the network from the sandbox (curl-equivalent, no egress
requested)...
  -> wget: can't connect to remote host (10.255.255.1): Network unreachable
BLOCKED
```

No network interface exists in the container by default (not a
firewall rule, there's genuinely nothing to route through), so this
fails the same way regardless of whether the host itself has internet
access.

## 8. Audit verify, then deliberate tampering

```
[8/8] Verifying the audit log, then deliberately tampering with it...
  before tampering: ok=True, 23 entries checked
  after flipping one byte: ok=False, first broken at seq 0: audit log is corrupted:
     'utf-8' codec can't decode byte 0xc5 in position 20: invalid continuation byte
```

A clean `verify()` first, then the demo flips one byte in
`entries.jsonl` on purpose and verifies again. `verify_sink()` reports
the corruption (in this run, the flipped byte happened to break UTF-8
decoding outright; a different byte could just as easily have produced
a valid-but-wrong hash instead, both are caught the same way) rather
than crashing. See docs/audit-log.md for what verification does and
does not catch.

## After it finishes

```
custody audit tail --dir <demo dir>
custody policy explain <policy> <catalog> sql.query --dataset tumor_registry_identified
custody ui --dir <demo dir>   # approve/deny something for real, not simulated
```

Everything the demo wrote (`policy.yaml`, `catalog.yaml`,
`principals.yaml`, the synthetic CSVs, `.custody/`) is on disk under
the directory you passed to `--dir` (`./demo` by default), ordinary
files you can open, edit, or point a real deployment at.
