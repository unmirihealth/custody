"""SQLite persistence for pending approvals and the decisions against
them. One file per deployment; safe for the CLI, the web UI, and the
gateway process to share since SQLite handles the file locking.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime
from pathlib import Path

from custody.approvals.models import (
    ApprovalDecision,
    ApprovalStatus,
    ApprovalSummary,
    PendingApproval,
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS approvals (
    id TEXT PRIMARY KEY,
    requester TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    summary_json TEXT NOT NULL,
    required_count INTEGER NOT NULL,
    required_roles_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    status TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS approval_decisions (
    approval_id TEXT NOT NULL,
    approver TEXT NOT NULL,
    approve INTEGER NOT NULL,
    reason TEXT NOT NULL,
    decided_at TEXT NOT NULL,
    PRIMARY KEY (approval_id, approver),
    FOREIGN KEY (approval_id) REFERENCES approvals(id)
);
"""


class DuplicateApproverError(Exception):
    """Raised when the same approver tries to decide on the same
    approval twice. Enforced at the database level (a composite primary
    key), not just in application logic, so it holds even under
    concurrent access from the CLI and the web UI at once."""


class ApprovalNotFoundError(Exception):
    pass


class ApprovalStore:
    """`check_same_thread=False` lets more than one thread use this
    connection at all, it does NOT make concurrent use of it safe:
    Python's sqlite3 connections are not internally synchronized, two
    threads calling `execute()` at the same moment can corrupt each
    other's cursor state. Found in CI (not locally) as an intermittent
    `sqlite3.InterfaceError` / a row read back with an empty-string
    `created_at`, exactly the signature of a torn read racing a write.
    Every method here holds `self._lock` for its full duration, callers
    (the gateway thread and, in the demo, a background decider thread)
    never need to know this store is shared.
    """

    def __init__(self, db_path: Path) -> None:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def create(self, approval: PendingApproval) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO approvals "
                "(id, requester, rule_id, summary_json, required_count, "
                " required_roles_json, created_at, expires_at, status) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    approval.id,
                    approval.requester,
                    approval.rule_id,
                    approval.summary.model_dump_json(),
                    approval.required_count,
                    json.dumps(approval.required_roles),
                    approval.created_at.isoformat(),
                    approval.expires_at.isoformat(),
                    approval.status.value,
                ),
            )
            self._conn.commit()

    def get(self, approval_id: str) -> PendingApproval | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT id, requester, rule_id, summary_json, required_count, "
                "required_roles_json, created_at, expires_at, status "
                "FROM approvals WHERE id = ?",
                (approval_id,),
            ).fetchone()
        if row is None:
            return None
        return _row_to_approval(row)

    def list_pending(self) -> list[PendingApproval]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, requester, rule_id, summary_json, required_count, "
                "required_roles_json, created_at, expires_at, status "
                "FROM approvals WHERE status = ? ORDER BY created_at",
                (ApprovalStatus.pending.value,),
            ).fetchall()
        return [_row_to_approval(r) for r in rows]

    def set_status(self, approval_id: str, status: ApprovalStatus) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE approvals SET status = ? WHERE id = ?",
                (status.value, approval_id),
            )
            self._conn.commit()

    def add_decision(self, decision: ApprovalDecision) -> None:
        with self._lock:
            try:
                self._conn.execute(
                    "INSERT INTO approval_decisions "
                    "(approval_id, approver, approve, reason, decided_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (
                        decision.approval_id,
                        decision.approver,
                        int(decision.approve),
                        decision.reason,
                        decision.decided_at.isoformat(),
                    ),
                )
                self._conn.commit()
            except sqlite3.IntegrityError as exc:
                raise DuplicateApproverError(
                    f"{decision.approver!r} already decided on approval "
                    f"{decision.approval_id!r}"
                ) from exc

    def list_decisions(self, approval_id: str) -> list[ApprovalDecision]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT approval_id, approver, approve, reason, decided_at "
                "FROM approval_decisions WHERE approval_id = ? ORDER BY decided_at",
                (approval_id,),
            ).fetchall()
        return [
            ApprovalDecision(
                approval_id=r[0],
                approver=r[1],
                approve=bool(r[2]),
                reason=r[3],
                decided_at=datetime.fromisoformat(r[4]),
            )
            for r in rows
        ]


def _row_to_approval(row: tuple[object, ...]) -> PendingApproval:
    return PendingApproval(
        id=row[0],  # type: ignore[arg-type]
        requester=row[1],  # type: ignore[arg-type]
        rule_id=row[2],  # type: ignore[arg-type]
        summary=ApprovalSummary.model_validate_json(row[3]),  # type: ignore[arg-type]
        required_count=row[4],  # type: ignore[arg-type]
        required_roles=json.loads(row[5]),  # type: ignore[arg-type]
        created_at=datetime.fromisoformat(row[6]),  # type: ignore[arg-type]
        expires_at=datetime.fromisoformat(row[7]),  # type: ignore[arg-type]
        status=ApprovalStatus(str(row[8])),
    )
