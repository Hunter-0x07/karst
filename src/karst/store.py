"""Single-writer SQLite journal and immutable evidence blobs."""

from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
from uuid import uuid4

from karst.config import KarstError

SCHEMA = "karst-bootstrap-record/1"


def utcnow():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def encoded(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def new_id(kind):
    return f"{kind}_{uuid4().hex}"


def valid_id(value):
    if not isinstance(value, str) or not re.fullmatch(r"(?:run|operation|evidence)_[0-9a-f]{32}", value):
        raise KarstError("invalid record identifier")
    return value


@contextmanager
def host_lock(data_dir):
    root = Path(data_dir).resolve()
    root.mkdir(parents=True, exist_ok=True)
    handle = (root / "host.lock").open("a+b")
    acquired = False
    try:
        handle.seek(0, 2)
        if handle.tell() == 0:
            handle.write(b"0")
            handle.flush()
        handle.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            acquired = True
        except OSError as exc:
            raise KarstError("another Host owns this data directory") from exc
        yield root
    finally:
        if acquired:
            handle.seek(0)
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        handle.close()


class Store:
    def __init__(self, data_dir, *, readonly=False):
        self.root = Path(data_dir).resolve()
        self.readonly = readonly
        if (self.root / "state" / "research.db").exists():
            raise KarstError("legacy probes require a separate data directory from formal research")
        db_path = self.root / "state" / "karst.db"
        if readonly:
            if not db_path.is_file():
                raise KarstError("state database does not exist")
            self.db = sqlite3.connect(db_path.as_uri() + "?mode=ro", uri=True)
            self.db.execute("PRAGMA query_only=ON")
        else:
            db_path.parent.mkdir(parents=True, exist_ok=True)
            (self.root / "evidence").mkdir(parents=True, exist_ok=True)
            self.db = sqlite3.connect(db_path)
        self.db.row_factory = sqlite3.Row
        version = self.db.execute("PRAGMA user_version").fetchone()[0]
        if version not in (0, 1) or (readonly and version != 1):
            self.db.close()
            raise KarstError("unsupported database version")
        if not readonly:
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.executescript("""
                CREATE TABLE IF NOT EXISTS records (
                    id TEXT NOT NULL, version INTEGER NOT NULL, kind TEXT NOT NULL,
                    run_id TEXT NOT NULL, created_at TEXT NOT NULL, data TEXT NOT NULL,
                    PRIMARY KEY(id, version));
                CREATE INDEX IF NOT EXISTS run_records ON records(run_id, kind);
                PRAGMA user_version=1;
            """)

    def close(self):
        self.db.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def put(self, kind, record_id, run_id, data, *, expected_version=0):
        if self.readonly or kind not in ("run", "operation", "evidence"):
            raise KarstError("record write not allowed")
        valid_id(record_id)
        valid_id(run_id)
        if not record_id.startswith(kind + "_") or not run_id.startswith("run_"):
            raise KarstError("record type mismatch")
        if kind == "run" and record_id != run_id:
            raise KarstError("Run id must equal run_id")
        with self.db:
            row = self.db.execute("SELECT MAX(version) FROM records WHERE id=?", (record_id,)).fetchone()
            if (row[0] or 0) != expected_version:
                raise KarstError("stale record version")
            if kind != "run":
                self.get(run_id, run_id=run_id)
            if expected_version:
                current = self.get(record_id)
                if current["run_id"] != run_id or current["kind"] != kind or kind == "evidence":
                    raise KarstError("immutable record ownership or evidence")
            version = expected_version + 1
            self.db.execute("INSERT INTO records VALUES (?,?,?,?,?,?)",
                            (record_id, version, kind, run_id, utcnow(), encoded(data).decode("utf-8")))
        return self.get(record_id)

    @staticmethod
    def _record(row):
        if row is None:
            raise KarstError("record not found")
        record = dict(row)
        record["schema_version"] = SCHEMA
        record["data"] = json.loads(record["data"])
        return record

    def get(self, record_id, *, version=None, run_id=None):
        valid_id(record_id)
        if version is None:
            row = self.db.execute("SELECT * FROM records WHERE id=? ORDER BY version DESC LIMIT 1", (record_id,)).fetchone()
        else:
            row = self.db.execute("SELECT * FROM records WHERE id=? AND version=?", (record_id, version)).fetchone()
        record = self._record(row)
        if run_id is not None and record["run_id"] != run_id:
            raise KarstError("cross-run reference denied")
        return record

    def records(self, run_id, kind=None):
        self.get(run_id, run_id=run_id)
        rows = self.db.execute("""SELECT r.* FROM records r JOIN
            (SELECT id,MAX(version) v,MIN(rowid) first_seq FROM records WHERE run_id=? GROUP BY id) c
            ON r.id=c.id AND r.version=c.v ORDER BY c.first_seq""", (run_id,)).fetchall()
        return [self._record(r) for r in rows if kind is None or r["kind"] == kind]

    def unfinished(self):
        return [r for r in self.runs() if r["data"]["state"] == "running"]

    def runs(self):
        rows = self.db.execute("""SELECT r.* FROM records r JOIN
            (SELECT id,MAX(version) v FROM records WHERE kind='run' GROUP BY id) c
            ON r.id=c.id AND r.version=c.v""").fetchall()
        return [self._record(r) for r in rows]

    def save_evidence(self, run_id, operation, exchange, *, partial):
        evidence_id = new_id("evidence")
        raw = encoded(exchange)
        digest = hashlib.sha256(raw).hexdigest()
        # The ID is allocated internally. Never follow user-supplied storage paths.
        path = self.root / "evidence" / f"{evidence_id}.json"
        try:
            with path.open("xb") as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
            data = {"operation_ref": {"kind": "operation", "id": operation["id"], "version": operation["version"]},
                    "sha256": digest, "captured_bytes": len(raw), "media_type": "application/json",
                    "capture_state": "partial" if partial else "complete", "availability": "ready",
                    "storage_ref": evidence_id, "sensitivity": "restricted",
                    "redaction": "request authorization removed; response retained locally"}
            return self.put("evidence", evidence_id, run_id, data)
        except OSError as exc:
            raise KarstError("evidence_save_failed") from exc

    def evidence_bytes(self, evidence_id, *, run_id):
        record = self.get(evidence_id, run_id=run_id)
        if record["kind"] != "evidence":
            raise KarstError("reference is not evidence")
        path = self.root / "evidence" / f"{record['id']}.json"
        try:
            raw = path.read_bytes()
        except OSError as exc:
            raise KarstError("evidence_unavailable") from exc
        if len(raw) != record["data"]["captured_bytes"] or hashlib.sha256(raw).hexdigest() != record["data"]["sha256"]:
            raise KarstError("evidence_integrity_failed")
        return raw

    def status(self, run_id):
        run = self.get(run_id, run_id=run_id)
        result = {"run_id": run_id, "record_schema": SCHEMA, "run": run["data"],
                  "operations": [], "evidence": [], "findings": [],
                  "capability_status": "HTTP integration only; no autonomous research or vulnerability conclusions"}
        for record in self.records(run_id):
            if record["kind"] == "operation":
                result["operations"].append({"id": record["id"], **record["data"]})
            elif record["kind"] == "evidence":
                item = {"id": record["id"], **record["data"]}
                try:
                    self.evidence_bytes(record["id"], run_id=run_id)
                except KarstError:
                    item["availability"] = "unavailable"
                result["evidence"].append(item)
        return result
