"""Cross-run state and de-duplication, backed by SQLite (stdlib, crash-safe, multi-process safe).

Two concepts:

* **Items**: per-stage processing record keyed by an arbitrary string (an OSV ID, a fix-commit key...).
  `should_process()` tells a stage whether to (re)do the work, so re-running a stage - or scaling
  `--limit` from 50 to 400 - never repeats finished work, and never hammers permanently broken items.
* **Fingerprints**: first-writer-wins claims used to de-duplicate across *different* keys that
  describe the same thing (e.g. two advisories fixed by one commit).

Statuses
  DONE / REJECTED / SKIPPED / FAILED_ORACLE / REJECTED_TOO_EASY / ACCEPTED
                             terminal: never reprocessed (use reset() to override)
  FAILED                     retried until `attempts` reaches `max_attempts`
"""
from __future__ import annotations

import json
import logging
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Iterator, Optional

log = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS items (
    stage      TEXT NOT NULL,
    key        TEXT NOT NULL,
    status     TEXT NOT NULL,
    attempts   INTEGER NOT NULL DEFAULT 0,
    detail     TEXT NOT NULL DEFAULT '',
    payload    TEXT,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (stage, key)
);
CREATE INDEX IF NOT EXISTS idx_items_stage_status ON items (stage, status);
CREATE TABLE IF NOT EXISTS fingerprints (
    namespace   TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    owner       TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    PRIMARY KEY (namespace, fingerprint)
);
"""


class Status(str, Enum):
    DONE = "done"
    FAILED = "failed"
    REJECTED = "rejected"
    SKIPPED = "skipped"
    FAILED_ORACLE = "failed_oracle"          # stage 4: oracle/pre-patch checks failed; never retried
    REJECTED_TOO_EASY = "rejected_too_easy"  # stage 5: some model solved it (pass@3 > 0)
    ACCEPTED = "accepted"                    # stage 5: all attempts failed AND trial analysis blames the models
    REJECTED_RUBRIC = "rejected_rubric"      # stage 4: task failed the quality rubric (hints, unfair tests, ...)
    REJECTED_TASK_DEFECT = "rejected_task_defect"  # stage 5: failures were caused by the task, not model capability
    NEEDS_REVIEW = "needs_review"            # stage 5: trial analysis inconclusive - a human decides


TERMINAL = {Status.DONE, Status.REJECTED, Status.SKIPPED, Status.FAILED_ORACLE, Status.REJECTED_TOO_EASY,
            Status.ACCEPTED, Status.REJECTED_RUBRIC, Status.REJECTED_TASK_DEFECT, Status.NEEDS_REVIEW}


@dataclass(frozen=True)
class Record:
    stage: str
    key: str
    status: Status
    attempts: int
    detail: str
    payload: Optional[dict[str, Any]]
    updated_at: str


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class StateManager:
    def __init__(self, db_path: Path):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(db_path, timeout=30, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.executescript(_SCHEMA)

    # -- lifecycle ---------------------------------------------------------- #
    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __enter__(self) -> "StateManager":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield self._conn
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            else:
                self._conn.execute("COMMIT")

    # -- items -------------------------------------------------------------- #
    def get(self, stage: str, key: str) -> Optional[Record]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM items WHERE stage=? AND key=?", (stage, key)).fetchone()
        if not row:
            return None
        return Record(row["stage"], row["key"], Status(row["status"]), row["attempts"],
                      row["detail"], json.loads(row["payload"]) if row["payload"] else None,
                      row["updated_at"])

    def should_process(self, stage: str, key: str, max_attempts: int = 3) -> bool:
        rec = self.get(stage, key)
        if rec is None:
            return True
        if rec.status in TERMINAL:
            return False
        return rec.attempts < max_attempts  # FAILED

    def mark(self, stage: str, key: str, status: Status, detail: str = "",
             payload: Optional[dict[str, Any]] = None) -> None:
        """Upsert a record. Marking FAILED increments the attempt counter."""
        with self._tx() as c:
            c.execute(
                """INSERT INTO items (stage, key, status, attempts, detail, payload, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(stage, key) DO UPDATE SET
                     status=excluded.status,
                     attempts=items.attempts + ?,
                     detail=excluded.detail,
                     payload=COALESCE(excluded.payload, items.payload),
                     updated_at=excluded.updated_at""",
                (stage, key, status.value, 1 if status is Status.FAILED else 0, detail[:2000],
                 json.dumps(payload) if payload is not None else None, _now(),
                 1 if status is Status.FAILED else 0))

    def mark_many(self, stage: str, keys: list[str], status: Status, detail: str = "") -> None:
        for k in keys:
            self.mark(stage, k, status, detail)

    def keys(self, stage: str, status: Optional[Status] = None) -> set[str]:
        sql, args = "SELECT key FROM items WHERE stage=?", [stage]
        if status:
            sql += " AND status=?"
            args.append(status.value)
        with self._lock:
            return {r["key"] for r in self._conn.execute(sql, args)}

    def counts(self, stage: str) -> dict[str, int]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT status, COUNT(*) n FROM items WHERE stage=? GROUP BY status", (stage,))
            return {r["status"]: r["n"] for r in rows}

    def reset(self, stage: str, key: Optional[str] = None) -> int:
        """Forget a stage (or one key) so it is processed again. Returns rows removed."""
        with self._tx() as c:
            if key is None:
                cur = c.execute("DELETE FROM items WHERE stage=?", (stage,))
            else:
                cur = c.execute("DELETE FROM items WHERE stage=? AND key=?", (stage, key))
            return cur.rowcount

    # -- fingerprints ------------------------------------------------------- #
    def claim_fingerprint(self, namespace: str, fingerprint: str, owner: str) -> bool:
        """True if this caller is the first to claim `fingerprint`; False if already claimed."""
        with self._tx() as c:
            cur = c.execute(
                "INSERT OR IGNORE INTO fingerprints (namespace, fingerprint, owner, created_at) "
                "VALUES (?, ?, ?, ?)", (namespace, fingerprint, owner, _now()))
            return cur.rowcount == 1

    def fingerprint_owner(self, namespace: str, fingerprint: str) -> Optional[str]:
        with self._lock:
            row = self._conn.execute(
                "SELECT owner FROM fingerprints WHERE namespace=? AND fingerprint=?",
                (namespace, fingerprint)).fetchone()
        return row["owner"] if row else None

    def release_fingerprint(self, namespace: str, fingerprint: str) -> None:
        with self._tx() as c:
            c.execute("DELETE FROM fingerprints WHERE namespace=? AND fingerprint=?",
                      (namespace, fingerprint))
