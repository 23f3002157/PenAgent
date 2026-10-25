"""Encrypted SQLite audit journal. Reservations precede network side effects.

BEGIN IMMEDIATE serializes budgets, cancellation and duplicate reservations
across processes. An interrupted reservation is never automatically replayed.
"""
import hashlib
import json
import sqlite3
import time
from contextlib import contextmanager

from cryptography.fernet import Fernet
from penagent_common.models import SessionState, StateWrite
from penagent_common.policy import Rejected


class Store:
    def __init__(self, settings):
        self.settings = settings
        self.cipher = Fernet(settings.encryption_key.encode())
        with self.connection() as db:
            db.executescript("""
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS audits (
              id TEXT PRIMARY KEY, owner TEXT NOT NULL, target TEXT NOT NULL,
              created REAL NOT NULL, cancelled INTEGER NOT NULL DEFAULT 0,
              state TEXT NOT NULL DEFAULT 'PLANNING', probes INTEGER NOT NULL DEFAULT 0,
              llm_calls INTEGER NOT NULL DEFAULT 0, halted INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS state (
              audit TEXT, category TEXT, key TEXT, value BLOB NOT NULL,
              PRIMARY KEY(audit, category, key));
            CREATE TABLE IF NOT EXISTS probes (
              id TEXT PRIMARY KEY, audit TEXT NOT NULL, hypothesis TEXT NOT NULL,
              fingerprint TEXT NOT NULL, mutation INTEGER NOT NULL,
              context BLOB NOT NULL, result BLOB, interpretation BLOB,
              UNIQUE(audit, fingerprint));
            CREATE TABLE IF NOT EXISTS events (
              seq INTEGER PRIMARY KEY AUTOINCREMENT, audit TEXT NOT NULL,
              kind TEXT NOT NULL, data BLOB NOT NULL);
            CREATE TABLE IF NOT EXISTS handoffs (
              audit TEXT, probe TEXT, kind TEXT, status TEXT NOT NULL,
              PRIMARY KEY(audit, probe, kind));
            CREATE TABLE IF NOT EXISTS leases (
              audit TEXT PRIMARY KEY, holder TEXT NOT NULL, expires REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS network_slots (
              holder TEXT PRIMARY KEY, expires REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS rate_clock (
              id INTEGER PRIMARY KEY CHECK(id=1), next_start REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS approvals (
              probe TEXT PRIMARY KEY, audit TEXT NOT NULL, requested REAL NOT NULL,
              status TEXT NOT NULL DEFAULT 'pending', description BLOB NOT NULL,
              decided_by TEXT, decided REAL, reason TEXT);
            """)

    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.settings.database, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def pack(self, value):
        if hasattr(value, "model_dump"):
            value = value.model_dump(mode="json")
        return self.cipher.encrypt(json.dumps(value, allow_nan=False).encode())

    def unpack(self, value):
        return json.loads(self.cipher.decrypt(value)) if value else None

    def create(self, audit: str, owner: str, target: str):
        with self.connection() as db:
            try:
                db.execute("INSERT INTO audits(id,owner,target,created) VALUES(?,?,?,?)", (audit, owner, target, time.time()))
            except sqlite3.IntegrityError:
                raise Rejected("audit_already_exists") from None

    def audit(self, audit: str, owner: str):
        with self.connection() as db:
            row = db.execute("SELECT * FROM audits WHERE id=? AND owner=?", (audit, owner)).fetchone()
            if not row:
                raise Rejected("audit_not_found")
            return dict(row)

    def active(self, audit: str, owner: str):
        a = self.audit(audit, owner)
        if a["cancelled"]:
            raise Rejected("cancelled")
        if a["halted"]:
            raise Rejected("service_chain_halted")
        if time.time() - a["created"] >= self.settings.max_duration:
            raise Rejected("duration_budget_exhausted")
        return a

    def cancel(self, audit: str, owner: str):
        self.audit(audit, owner)
        with self.connection() as db:
            db.execute("UPDATE audits SET cancelled=1,state='CANCELLED' WHERE id=?", (audit,))

    def checkpoint(self, audit, owner, value):
        """Internal progress may be persisted after cancellation or a 5xx halt."""
        self.audit(audit, owner)
        with self.connection() as db:
            db.execute("INSERT INTO state(audit,category,key,value) VALUES(?,?,?,?) ON CONFLICT(audit,category,key) DO UPDATE SET value=excluded.value",
                       (audit, "observations", "__workflow", self.pack(value)))

    def transition(self, audit: str, state: str):
        with self.connection() as db:
            db.execute("UPDATE audits SET state=? WHERE id=? AND cancelled=0", (state, audit))
            db.execute("INSERT INTO events(audit,kind,data) VALUES(?,?,?)", (audit, "transition", self.pack({"state": state})))

    def reserve(self, audit, owner, result, probe, hypothesis, graph):
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            a = db.execute("SELECT * FROM audits WHERE id=? AND owner=?", (audit, owner)).fetchone()
            if not a:
                raise Rejected("audit_not_found")
            if a["cancelled"] or a["halted"]:
                raise Rejected("cancelled_or_halted")
            if time.time() - a["created"] >= self.settings.max_duration or a["probes"] >= self.settings.max_probes or probe.depth >= self.settings.max_depth:
                raise Rejected("execution_budget_exhausted")
            count = db.execute("SELECT COUNT(*) FROM probes WHERE audit=? AND hypothesis=? AND mutation=1", (audit, probe.hypothesis_id)).fetchone()[0]
            if probe.parent_probe_id and count >= self.settings.max_mutations:
                raise Rejected("mutation_budget_exhausted")
            try:
                db.execute("INSERT INTO probes(id,audit,hypothesis,fingerprint,mutation,context) VALUES(?,?,?,?,?,?)",
                           (result.probe_id, audit, probe.hypothesis_id, result.request_fingerprint, int(probe.parent_probe_id is not None),
                            self.pack({"probe": probe.model_dump(), "hypothesis": hypothesis.model_dump(), "graph": graph.model_dump(mode="json")})))
            except sqlite3.IntegrityError:
                raise Rejected("duplicate_probe_no_progress") from None
            db.execute("UPDATE audits SET probes=probes+1,state='EXECUTING' WHERE id=?", (audit,))

    def finish(self, result):
        with self.connection() as db:
            db.execute("UPDATE probes SET result=? WHERE id=? AND audit=?", (self.pack(result), result.probe_id, result.audit_id))
            if result.status_code and result.status_code >= 500:
                db.execute("UPDATE audits SET halted=1 WHERE id=?", (result.audit_id,))

    def get_probe(self, audit: str, owner: str, probe: str):
        self.audit(audit, owner)
        with self.connection() as db:
            row = db.execute("SELECT * FROM probes WHERE id=? AND audit=?", (probe, audit)).fetchone()
            if not row:
                raise Rejected("probe_not_found")
            return {"context": self.unpack(row["context"]), "result": self.unpack(row["result"]), "interpretation": self.unpack(row["interpretation"])}

    def interpretation(self, audit, probe, result):
        with self.connection() as db:
            db.execute("UPDATE probes SET interpretation=? WHERE id=? AND audit=?", (self.pack(result), probe, audit))

    def read(self, audit: str, owner: str, secrets: bool = False) -> SessionState:
        self.audit(audit, owner)
        with self.connection() as db:
            rows = db.execute("SELECT category,key,value FROM state WHERE audit=?", (audit,)).fetchall()
        values = {k: {} for k in ("tokens", "cookies", "object_ids", "observations")}
        for r in rows:
            values[r["category"]][r["key"]] = self.unpack(r["value"]) if secrets or r["category"] == "object_ids" else "[REDACTED]"
        return SessionState(audit_id=audit, values=values)

    def write(self, audit: str, owner: str, update: StateWrite):
        self.active(audit, owner)
        if len(json.dumps(update.value)) > self.settings.max_request_size:
            raise Rejected("state_value_too_large")
        with self.connection() as db:
            db.execute("INSERT INTO state(audit,category,key,value) VALUES(?,?,?,?) ON CONFLICT(audit,category,key) DO UPDATE SET value=excluded.value",
                       (audit, update.category, update.key, self.pack(update.value)))
        return self.read(audit, owner)

    def trace(self, audit: str, owner: str):
        a = self.audit(audit, owner)
        with self.connection() as db:
            rows = db.execute("SELECT id FROM probes WHERE audit=? ORDER BY rowid", (audit,)).fetchall()
            events = db.execute("SELECT kind,data FROM events WHERE audit=? ORDER BY seq", (audit,)).fetchall()
        return {"audit": {k: v for k, v in a.items() if k != "owner"},
                "probes": [{"probe_id": r["id"], **self.get_probe(audit, owner, r["id"])} for r in rows],
                "events": [{"kind": e["kind"], "data": self.unpack(e["data"])} for e in events]}

    def event(self, audit, kind, data):
        with self.connection() as db:
            db.execute("INSERT INTO events(audit,kind,data) VALUES(?,?,?)", (audit, kind, self.pack(data)))

    def llm_reserve(self, audit, owner):
        self.active(audit, owner)
        with self.connection() as db:
            cursor = db.execute("UPDATE audits SET llm_calls=llm_calls+1 WHERE id=? AND llm_calls<? AND cancelled=0", (audit, self.settings.max_llm_calls))
            if cursor.rowcount != 1:
                raise Rejected("llm_budget_exhausted")

    def handoff(self, audit, probe, kind, status=None):
        with self.connection() as db:
            if status:
                db.execute("INSERT INTO handoffs VALUES(?,?,?,?) ON CONFLICT(audit,probe,kind) DO UPDATE SET status=excluded.status", (audit, probe, kind, status))
            row = db.execute("SELECT status FROM handoffs WHERE audit=? AND probe=? AND kind=?", (audit, probe, kind)).fetchone()
            return row[0] if row else None

    def request_approval(self, audit, probe: str, description: dict):
        """Component 5: persist a pending human-approval record for an already
        reserved, already stored-as-pending probe. `description` is operator-facing
        only (hypothesis/op/risk/rationale); never raw target response text."""
        with self.connection() as db:
            db.execute("INSERT INTO approvals(probe,audit,requested,status,description) VALUES(?,?,?,?,?)",
                       (probe, audit, time.time(), "pending", self.pack(description)))

    def _expire_approvals(self, audit: str):
        """Lazy timeout sweep, mirroring how active() lazily enforces the duration
        budget. A pending approval older than approval_timeout is auto-skipped,
        never auto-approved."""
        cutoff = time.time() - self.settings.approval_timeout
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            stale = db.execute("SELECT probe FROM approvals WHERE audit=? AND status='pending' AND requested<=?", (audit, cutoff)).fetchall()
            for row in stale:
                db.execute("UPDATE approvals SET status='timed_out',decided=? WHERE probe=?", (time.time(), row["probe"]))
                probe_row = db.execute("SELECT result FROM probes WHERE id=?", (row["probe"],)).fetchone()
                if probe_row and probe_row["result"]:
                    result = self.unpack(probe_row["result"])
                    if result.get("status") == "awaiting_approval":
                        result["status"] = "blocked"
                        result["error"] = "approval_timed_out_destructive_action_skipped"
                        db.execute("UPDATE probes SET result=? WHERE id=?", (self.pack(result), row["probe"]))

    def approvals(self, audit: str, owner: str, pending_only: bool = False):
        self.audit(audit, owner)
        self._expire_approvals(audit)
        with self.connection() as db:
            query = "SELECT probe,audit,requested,status,description,decided_by,decided,reason FROM approvals WHERE audit=?"
            if pending_only:
                query += " AND status='pending'"
            rows = db.execute(query, (audit,)).fetchall()
        return [{"probe_id": r["probe"], "requested": r["requested"], "status": r["status"],
                 "description": self.unpack(r["description"]), "decided_by": r["decided_by"],
                 "decided": r["decided"], "reason": r["reason"]} for r in rows]

    def decide_approval(self, audit: str, owner: str, probe: str, decision: str, reason: str | None, decided_by: str):
        """Atomic compare-and-swap of the operator's decision (approve/deny), distinct
        from the execution outcome recorded on the probe afterward. Raises if already
        decided, timed out, or unknown."""
        self.active(audit, owner)
        self._expire_approvals(audit)
        with self.connection() as db:
            cursor = db.execute("UPDATE approvals SET status=?,decided_by=?,decided=?,reason=? WHERE probe=? AND audit=? AND status='pending'",
                                 (decision, decided_by, time.time(), reason, probe, audit))
            if cursor.rowcount != 1:
                row = db.execute("SELECT 1 FROM approvals WHERE probe=? AND audit=?", (probe, audit)).fetchone()
                raise Rejected("approval_not_found" if not row else "approval_already_decided")

    def lease(self, audit, owner, holder, release=False):
        self.audit(audit, owner)
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            if release:
                db.execute("DELETE FROM leases WHERE audit=? AND holder=?", (audit, holder))
                return
            row = db.execute("SELECT * FROM leases WHERE audit=?", (audit,)).fetchone()
            if row and row["expires"] > time.time() and row["holder"] != holder:
                raise Rejected("audit_execution_in_progress")
            db.execute("INSERT OR REPLACE INTO leases VALUES(?,?,?)", (audit, holder, time.time() + self.settings.max_duration + 30))

    def network_slot(self, holder, release=False):
        """Cross-process concurrency and pacing for this execution database."""
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            if release:
                db.execute("DELETE FROM network_slots WHERE holder=?", (holder,))
                return 0.0
            now = time.time()
            db.execute("DELETE FROM network_slots WHERE expires<=?", (now,))
            if db.execute("SELECT COUNT(*) FROM network_slots").fetchone()[0] >= self.settings.concurrency:
                return .02
            row = db.execute("SELECT next_start FROM rate_clock WHERE id=1").fetchone()
            if row and row[0] > now:
                return min(row[0] - now, .05)
            db.execute("INSERT OR REPLACE INTO rate_clock VALUES(1,?)", (now + 1 / self.settings.requests_per_second,))
            db.execute("INSERT INTO network_slots VALUES(?,?)", (holder, now + self.settings.request_timeout + 1))
            return 0.0
