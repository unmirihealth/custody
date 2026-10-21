"""The scripted end-to-end scenario `custody demo` runs. See
docs/demo.md for a narrated walkthrough of what each step demonstrates
and why.

Steps 3 and 4 need a human decision. A one-shot, non-interactive `custody
demo` can't actually pop a browser and wait for a click, so this
simulates the approval/denial by calling the broker directly on a
background thread, the same mechanism `custody ui` or `custody
approvals approve/deny` would use, narrated clearly as simulated so
nobody mistakes this for Custody somehow bypassing the approval gate.
Run `custody ui` yourself against this demo's directory to approve or
deny the identified-data query for real instead.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path

from custody.audit.log import verify_sink
from custody.audit.sinks import LocalFileSink
from custody.demo.config import CATALOG_YAML, POLICY_YAML, PRINCIPALS_YAML
from custody.demo.synthetic_data import add_fake_identifiers, generate_tumor_registry, write_csv
from custody.gateway import Gateway
from custody.guard import OutputGuard
from custody.mcp_server import ServerPaths, build_gateway
from custody.sandbox import SandboxConfig, SandboxExecutor
from custody.tools import ToolContext, catalog_list, files_export, files_write, shell_run, sql_query


def _say(msg: str) -> None:
    print(msg, flush=True)


def _decide_in_background(
    gateway: Gateway, approver: str, approve: bool, reason: str, label: str
) -> threading.Thread:
    def worker() -> None:
        for _ in range(60):
            pending = gateway.approvals.list_pending()
            if pending:
                gateway.approvals.decide(pending[0].id, approver, approve, reason)
                verb = "approved" if approve else "denied"
                _say(f"  [simulated human] {approver} {verb} it: {reason!r} ({label})")
                return
            time.sleep(0.25)

    t = threading.Thread(target=worker, daemon=True)
    t.start()
    return t


def run_demo(dir: Path) -> None:  # noqa: C901 - a linear narrated script, not meant to be split up
    dir = dir.resolve()
    dir.mkdir(parents=True, exist_ok=True)
    paths = ServerPaths.under(dir)

    _say(f"=== Custody demo === (writing everything under {dir})\n")

    _say("[1/8] Generating a synthetic tumor registry (5,000 patients, fixed seed)...")
    deid_rows = generate_tumor_registry()
    deid_path = dir / "data" / "tumor_registry_deidentified.synthetic.csv"
    write_csv(deid_path, deid_rows)
    identified_rows = add_fake_identifiers(deid_rows)
    identified_path = dir / "data" / "tumor_registry_identified.synthetic.csv"
    write_csv(identified_path, identified_rows)
    _say(f"  wrote {deid_path.relative_to(dir)}")
    _say(f"  wrote {identified_path.relative_to(dir)}  (fake MRNs and names, clearly synthetic)\n")

    _say("[2/8] Writing the sample policy, catalog, and principals...")
    paths.catalog.write_text(CATALOG_YAML)
    paths.policy.write_text(POLICY_YAML)
    paths.principals.write_text(PRINCIPALS_YAML)
    _say(f"  wrote {paths.policy.relative_to(dir)}, {paths.catalog.relative_to(dir)}, "
         f"{paths.principals.relative_to(dir)}\n")

    gateway = build_gateway(paths, session_id="demo", principal="demo-agent")
    sandbox = SandboxExecutor(SandboxConfig(image="custody-sandbox:duckdb", timeout_seconds=30))
    ctx = ToolContext(
        gateway=gateway,
        sandbox=sandbox,
        catalog=gateway.catalog,
        guard=OutputGuard(),
        workspace_dir=paths.workspace_dir,
    )

    try:
        _say("[3/8] Agent lists the catalog...")
        result = catalog_list(ctx)
        outcome = "allowed" if not result.denied else "DENIED"
        _say(f"  -> {outcome}: {result.data if not result.denied else result.reason}\n")

        _say(
            "[4/8] Agent runs a cohort query on de-identified data "
            "(stage IV lung, four biomarkers positive, grouped by treatment line -- "
            "narrow enough that some cells land under the suppression minimum)..."
        )
        result = sql_query(
            ctx,
            "tumor_registry_deidentified",
            "SELECT treatment_line AS treatment_line, count(*) AS count FROM data "
            "WHERE stage = 'IV' AND primary_site = 'lung' "
            "AND egfr_status = 'positive' AND alk_status = 'positive' "
            "AND her2_status = 'positive' AND kras_status = 'positive' "
            "GROUP BY treatment_line",
        )
        outcome = "allowed" if not result.denied else "DENIED"
        detail = result.data if not result.denied else result.reason
        _say(
            f"  -> {outcome} (de-identified data isn't small-cell suppressed, the "
            f"guard only applies at limited_data_set and above): {detail}\n"
        )

        _say(
            "[5/8] Agent runs the SAME cohort breakdown on the identified table "
            "(this time the guard applies)..."
        )
        _say("  -> held for approval (identified-query-needs-approval, 1 of [data_steward])")
        thread = _decide_in_background(
            gateway,
            "dr_steward",
            True,
            "routine QA spot-check, authorized by team lead",
            "step 5",
        )
        result = sql_query(
            ctx,
            "tumor_registry_identified",
            "SELECT treatment_line AS treatment_line, count(*) AS count FROM data "
            "WHERE stage = 'IV' AND primary_site = 'lung' "
            "AND egfr_status = 'positive' AND alk_status = 'positive' "
            "AND her2_status = 'positive' AND kras_status = 'positive' "
            "GROUP BY treatment_line",
        )
        thread.join(timeout=20)
        outcome = "allowed" if not result.denied else "denied"
        _say(f"  -> {outcome}: {result.data or result.reason}\n")

        _say(
            "[6/8] Agent tries to export identified rows "
            "(export-two-person: 2 of [data_steward, privacy_officer])..."
        )
        files_write(ctx, "export_candidate.csv", "mrn,patient_name\nSYN-MRN-100000,Jordan Rivera\n")
        thread = _decide_in_background(
            gateway,
            "dr_privacy",
            False,
            "export scope too broad for a routine QA check, re-submit with a narrower cohort",
            "step 6",
        )
        result = files_export(ctx, "export_candidate.csv", dir / "exported.csv")
        thread.join(timeout=20)
        outcome = "allowed" if not result.denied else "DENIED"
        _say(f"  -> {outcome}: {result.reason}\n")

        _say(
            "[7/8] Agent tries to reach the network from the sandbox "
            "(curl-equivalent, no egress requested)..."
        )
        result = shell_run(
            ctx,
            ["sh", "-c", "wget -T 2 -q -O /dev/null http://10.255.255.1/ 2>&1 || echo BLOCKED"],
        )
        _say(f"  -> {result.data['stdout'].strip() if result.data else result.reason}\n")

        _say("[8/8] Verifying the audit log, then deliberately tampering with it...")
        clean = gateway.audit.verify()
        _say(f"  before tampering: ok={clean.ok}, {clean.entries_checked} entries checked")

        entries_path = paths.audit_dir / "entries.jsonl"
        raw = bytearray(entries_path.read_bytes())
        flip_at = min(20, len(raw) - 1)
        raw[flip_at] ^= 0xFF
        entries_path.write_bytes(bytes(raw))

        tampered = verify_sink(LocalFileSink(paths.audit_dir))
        _say(
            f"  after flipping one byte: ok={tampered.ok}, "
            f"first broken at seq {tampered.first_broken_seq}: {tampered.reason}\n"
        )
    finally:
        gateway.close()

    _say("=== Demo complete ===")
    _say(f"Everything is under {dir}. Try:")
    _say(f"  custody audit tail --dir {dir}")
    _say(f"  custody policy explain {paths.policy} {paths.catalog} sql.query "
         f"--dataset tumor_registry_identified")
    _say(f"  custody ui --dir {dir}   (then approve/deny something for real, not simulated)")
