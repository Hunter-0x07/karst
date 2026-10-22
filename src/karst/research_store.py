"""Versioned karst-design/1 records, atomic publications and private I0 audit ledger."""

from contextlib import contextmanager
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3

from karst.config import KarstError, exact
from karst.research_config import text
from karst.store import encoded, new_id, utcnow

FIELDS = {
    "run": "state stop_reason config_version spec",
    "asset": "asset_type canonical_key locator parent_refs provenance_refs",
    "identity": "label principal_attributes credential_ref source",
    "session": "identity_ref resource_ref generation channel auth_status checked_at evidence_refs",
    "task": "opportunity_ref role briefing allowed_tools prerequisites read_set write_set allocated_budget state result_ref outcome",
    "attempt": "task_ref attempt_no owner generation lease_until state stop_reason usage",
    "operation": "task_ref attempt_ref model_request_ref parent_operation_ref tool_name tool_version arguments_digest config_version identity_ref session_generation vantage_ref execution_state started_at ended_at error evidence_refs usage",
    "evidence": "operation_ref media_type storage_ref sha256 captured_bytes capture_state availability identity_ref session_generation vantage_ref observed_at redaction sensitivity",
    "observation": "statement evidence_refs subject_refs conditions provenance contradicts_refs",
    "result": "submission_kind task_ref attempt_ref proposal_digest payload accepted_refs",
}
I0_KINDS = tuple(FIELDS)
FIELDS.update({
    "hypothesis": "question basis_refs alternative_explanations missing_conditions status",
    "opportunity": "question lane target_refs basis_refs prerequisite_conditions expected_outcomes method_family priority reason dedup_key state wait_reason revisit_condition",
})
FIELDS.update({
    "security_rule": "statement applies_to_refs source_refs source_type status",
    "candidate": "claim_revision claim affected_refs rule_refs supporting_refs counterevidence_refs required_conditions alternative_explanations missing_conditions state",
    "verification": "candidate_ref candidate_claim_revision task_ref role_session_id evidence_refs conditions_checked counterevidence_refs verdict reproduction_status impact_boundary remaining_questions independence",
    "capability": "claim_revision subject_ref resource_ref actions session_ref vantage_ref conditions evidence_refs status origin validated_by_ref observed_at invalidated_reason",
    "capability_check": "capability_ref capability_claim_revision operation_refs evidence_refs predicate_id predicate_version conditions_checked verdict limitations",
    "path_edge": "input_capability_refs operation_refs output_capability_refs evidence_refs status",
})


def ref(record):
    return {k: record[k] for k in ("kind", "id", "version")}


def digest(value):
    def walk(v, depth=0):
        if depth > 32 or isinstance(v, float):
            raise KarstError("canonical proposal depth/float unsupported")
        if isinstance(v, dict):
            for x in v.values():
                walk(x, depth+1)
        elif isinstance(v, list):
            for x in v:
                walk(x, depth+1)
    walk(value)
    raw = encoded(value)
    if len(raw) > 262144:
        raise KarstError("proposal too large")
    return hashlib.sha256(raw).hexdigest()


class ResearchStore:
    def __init__(self, data_dir, *, readonly=False):
        self.root = Path(data_dir).resolve()
        self.readonly = readonly
        path = self.root / "state/research.db"
        if (self.root / "state/karst.db").exists():
            raise KarstError("formal research requires a separate data directory from legacy probes")
        if readonly:
            if not path.is_file():
                raise KarstError("research database does not exist")
            self.db = sqlite3.connect(path.as_uri()+"?mode=ro", uri=True)
            self.db.execute("PRAGMA query_only=ON")
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            (self.root / "evidence").mkdir(exist_ok=True)
            self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        version = self.db.execute("PRAGMA user_version").fetchone()[0]
        if version not in (0, 2) or (readonly and version != 2):
            self.db.close()
            raise KarstError("unsupported formal store version")
        if not readonly:
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.executescript('''
                CREATE TABLE IF NOT EXISTS records(id TEXT, version INTEGER, kind TEXT, run_id TEXT, created_at TEXT, data TEXT, PRIMARY KEY(id,version));
                CREATE INDEX IF NOT EXISTS by_run ON records(run_id,kind);
                CREATE TABLE IF NOT EXISTS changes(run_id TEXT, sequence INTEGER, data TEXT, PRIMARY KEY(run_id,sequence));
                CREATE TABLE IF NOT EXISTS receipts(run_id TEXT, endpoint TEXT, request_id TEXT, data TEXT, PRIMARY KEY(run_id,endpoint,request_id));
                CREATE TABLE IF NOT EXISTS audit(run_id TEXT, sequence INTEGER, kind TEXT, data TEXT, PRIMARY KEY(run_id,sequence));
                CREATE TABLE IF NOT EXISTS calls(run_id TEXT, attempt_id TEXT, call_id TEXT, digest TEXT, state TEXT, reply TEXT, PRIMARY KEY(run_id,attempt_id,call_id));
                CREATE TABLE IF NOT EXISTS reservations(run_id TEXT, key TEXT, amounts TEXT, actual TEXT, state TEXT, PRIMARY KEY(run_id,key));
                PRAGMA user_version=2;
            ''')

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.db.close()

    @contextmanager
    def atomic(self):
        if self.db.in_transaction:
            yield
        else:
            with self.db:
                self.db.execute("BEGIN IMMEDIATE")
                yield

    @staticmethod
    def decode(row):
        if row is None:
            raise KarstError("record not found")
        r = dict(row)
        r["schema_version"] = "karst-design/1"
        r["data"] = json.loads(r["data"])
        return r

    def get(self, record_id, *, version=None, run_id=None):
        if not isinstance(record_id, str) or not re.fullmatch(r"[a-z]+(?:_[a-z]+)*_[0-9a-f]{32}", record_id):
            raise KarstError("invalid formal identifier")
        if version is not None and (type(version) is not int or version < 1):
            raise KarstError("invalid reference version")
        row = self.db.execute("SELECT * FROM records WHERE id=?" + (" AND version=?" if version is not None else " ORDER BY version DESC LIMIT 1"),
                              (record_id, version) if version is not None else (record_id,)).fetchone()
        r = self.decode(row)
        if run_id is not None and r["run_id"] != run_id:
            raise KarstError("cross-run reference denied")
        return r

    def resolve(self, reference, run_id, kind=None, *, current=False):
        exact(reference, ["kind", "id", "version"])
        r = self.get(reference["id"], version=reference["version"], run_id=run_id)
        if r["kind"] != reference["kind"] or (kind and kind != r["kind"]):
            raise KarstError("reference type mismatch")
        if current and self.get(r["id"])["version"] != r["version"]:
            raise KarstError("stale record version")
        return r

    def put(self, kind, run_id, data, *, record_id=None, expected_version=0):
        if kind not in FIELDS or self.readonly:
            raise KarstError("unsupported formal record kind")
        exact(data, FIELDS[kind].split())
        enums = {"run": ("state", {"created", "running", "paused", "reconciling", "stopped", "completed", "failed"}),
                 "task": ("state", {"queued", "running", "delivered", "blocked", "failed", "cancelled"}),
                 "attempt": ("state", {"running", "delivered", "failed", "cancelled", "unknown"}),
                 "operation": ("execution_state", {"planned", "running", "succeeded", "failed", "unknown", "not_executed"}),
                 "session": ("auth_status", {"unverified", "authenticated", "expired", "revoked"}),
                 "identity": ("source", {"provided", "discovered"}),
                 "result": ("submission_kind", {"publish", "final"}),
                 "security_rule": ("status", {"proposed", "supported", "disputed", "superseded"}),
                 "candidate": ("state", {"open", "verifying", "supported", "ruled_out", "inconclusive", "needs_revalidation"}),
                 "verification": ("verdict", {"supported", "ruled_out", "inconclusive"}),
                 "capability": ("status", {"observed", "verified", "stale", "refuted"}),
                 "capability_check": ("verdict", {"satisfied", "not_satisfied", "unknown"}),
                 "path_edge": ("status", {"proposed", "proven", "stale", "refuted"})}
        if kind in ("candidate", "capability") and (type(data["claim_revision"]) is not int or data["claim_revision"] < 1):
            raise KarstError("invalid claim revision")
        if kind in enums:
            field, allowed = enums[kind]
            if not isinstance(data[field], str) or data[field] not in allowed:
                raise KarstError("unsupported formal state")
        if type(expected_version) is not int or expected_version < 0:
            raise KarstError("invalid expected version")
        if kind == "evidence" and (data["capture_state"] not in ("complete", "partial") or data["availability"] not in ("ready", "unavailable")):
            raise KarstError("invalid evidence state")
        digest(data)
        record_id = record_id or new_id(kind)
        if not isinstance(record_id, str) or not re.fullmatch(re.escape(kind)+r"_[0-9a-f]{32}", record_id) or (kind == "run" and record_id != run_id):
            raise KarstError("record ownership mismatch")
        with self.atomic():
            old = self.db.execute("SELECT MAX(version) FROM records WHERE id=?", (record_id,)).fetchone()[0] or 0
            if old != expected_version:
                raise KarstError("stale record version")
            if old and (self.get(record_id)["run_id"] != run_id or kind == "evidence"):
                raise KarstError("immutable record/evidence ownership")
            self.db.execute("INSERT INTO records VALUES(?,?,?,?,?,?)",
                            (record_id, old+1, kind, run_id, utcnow(), encoded(data).decode()))
            r = self.get(record_id)
            seq = self.db.execute("SELECT COALESCE(MAX(sequence),0)+1 FROM changes WHERE run_id=?", (run_id,)).fetchone()[0]
            change = {"sequence": seq, "run_id": run_id, "entity_ref": ref(r), "change_type": "updated" if old else "created",
                      "invalidates_refs": [], "reason": "I0 Host transaction"}
            self.db.execute("INSERT INTO changes VALUES(?,?,?)", (run_id, seq, encoded(change).decode()))
        return r

    def update(self, record, **changes):
        return self.put(record["kind"], record["run_id"], dict(record["data"], **changes),
                        record_id=record["id"], expected_version=record["version"])

    def records(self, run_id, kind=None):
        if kind is not None and kind not in FIELDS:
            raise KarstError("unsupported record query")
        rows = self.db.execute('''SELECT r.* FROM records r JOIN
            (SELECT id,MAX(version) v,MIN(rowid) seq FROM records WHERE run_id=? GROUP BY id) c
            ON r.id=c.id AND r.version=c.v ORDER BY c.seq''', (run_id,)).fetchall()
        return [self.decode(r) for r in rows if kind is None or r["kind"] == kind]

    def audit(self, run_id, kind, data):
        with self.atomic():
            seq = self.db.execute("SELECT COALESCE(MAX(sequence),0)+1 FROM audit WHERE run_id=?", (run_id,)).fetchone()[0]
            value = {"schema_version": "karst-i0-audit/1", "sequence": seq, "at": utcnow(), "kind": kind, **data}
            self.db.execute("INSERT INTO audit VALUES(?,?,?,?)", (run_id, seq, kind, encoded(value).decode()))
        return value

    def audits(self, run_id):
        return [json.loads(r[0]) for r in self.db.execute("SELECT data FROM audit WHERE run_id=? ORDER BY sequence", (run_id,))]

    def save_evidence(self, run_id, operation, exchange, *, partial):
        evidence_id = new_id("evidence")
        raw = encoded(exchange)
        path = self.root / "evidence" / (evidence_id+".json")
        tmp = path.with_suffix(".pending")
        try:
            with tmp.open("xb") as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, path)
            d = operation["data"]
            return self.put("evidence", run_id, {"operation_ref": ref(operation), "media_type": "application/json",
                "storage_ref": evidence_id, "sha256": hashlib.sha256(raw).hexdigest(), "captured_bytes": len(raw),
                "capture_state": "partial" if partial else "complete", "availability": "ready", "identity_ref": d["identity_ref"],
                "session_generation": d["session_generation"], "vantage_ref": None, "observed_at": utcnow(),
                "redaction": "request Authorization removed; restricted response retained locally", "sensitivity": "restricted"}, record_id=evidence_id)
        except OSError as exc:
            raise KarstError("evidence_save_failed") from exc

    def evidence_bytes(self, reference, run_id):
        r = self.resolve(reference, run_id, "evidence")
        d = r["data"]
        try:
            raw = (self.root / "evidence" / (r["id"]+".json")).read_bytes()
        except OSError as exc:
            raise KarstError("evidence_unavailable") from exc
        if d["availability"] != "ready" or len(raw) != d["captured_bytes"] or hashlib.sha256(raw).hexdigest() != d["sha256"]:
            raise KarstError("evidence_integrity_failed")
        return raw

    def usage(self, run_id):
        used = {}
        unknown = []
        for row in self.db.execute("SELECT key,amounts,actual,state FROM reservations WHERE run_id=?", (run_id,)):
            amount = json.loads(row["actual"] or row["amounts"])
            for k, v in amount.items():
                used[k] = used.get(k, 0)+v
            if row["state"] != "settled":
                unknown.append(row["key"])
        return {"charged_or_reserved": used, "unsettled": unknown, "cost": None}

    def reserve(self, run_id, key, amounts, limits):
        with self.atomic():
            used = self.usage(run_id)["charged_or_reserved"]
            if self.db.execute("SELECT 1 FROM reservations WHERE run_id=? AND key=?", (run_id, key)).fetchone():
                raise KarstError("reservation key already exists")
            if any(type(v) is not int or v < 0 or used.get(k, 0)+v > limits[k] for k, v in amounts.items()):
                raise KarstError("budget_exhausted")
            self.db.execute("INSERT INTO reservations VALUES(?,?,?,NULL,'reserved')", (run_id, key, encoded(amounts).decode()))

    def attempt_usage(self, run_id, attempt_id):
        current = self.usage(run_id)
        start = next((a["usage_start"] for a in self.audits(run_id)
                      if a["kind"] == "context" and a["context"]["attempt_ref"]["id"] == attempt_id
                      and "usage_start" in a), {"charged_or_reserved": {}, "unsettled": []})
        return {"charged_or_reserved": {k: v-start["charged_or_reserved"].get(k, 0)
                                       for k, v in current["charged_or_reserved"].items()},
                "unsettled": [k for k in current["unsettled"] if k not in start["unsettled"]], "cost": None}

    def settle(self, run_id, key, actual=None):
        with self.atomic():
            row = self.db.execute("SELECT amounts FROM reservations WHERE run_id=? AND key=?", (run_id, key)).fetchone()
            if row is None:
                raise KarstError("unknown reservation")
            reserved = json.loads(row[0])
            if actual is not None and (set(actual) != set(reserved) or any(type(v) is not int or v < 0 or v > reserved[k] for k, v in actual.items())):
                raise KarstError("usage exceeds reservation")
            self.db.execute("UPDATE reservations SET actual=?,state=? WHERE run_id=? AND key=?",
                            (encoded(actual).decode() if actual is not None else None, "settled" if actual is not None else "unknown", run_id, key))

    def receive(self, endpoint, envelope, *, owner, generation):
        exact(envelope, ["schema_version", "request_id", "run_ref", "task_ref", "attempt_ref", "expected_versions", "payload"])
        if endpoint not in ("publish", "final") or envelope["schema_version"] != "karst-design/1":
            raise KarstError("unsupported proposal schema/interface")
        text(envelope["request_id"], 200)
        run_id = envelope["run_ref"]["id"]
        run = self.resolve(envelope["run_ref"], run_id, "run")
        task = self.resolve(envelope["task_ref"], run_id, "task")
        attempt = self.resolve(envelope["attempt_ref"], run_id, "attempt")
        current_attempt = self.get(attempt["id"])
        if current_attempt["data"]["owner"] != owner or current_attempt["data"]["generation"] != generation or attempt["data"]["task_ref"]["id"] != task["id"]:
            raise KarstError("stale attempt owner/generation")
        proposal_digest = digest(envelope)
        with self.atomic():
            old = self.db.execute("SELECT data FROM receipts WHERE run_id=? AND endpoint=? AND request_id=?", (run_id, endpoint, envelope["request_id"])).fetchone()
            if old:
                receipt = json.loads(old[0])
                if receipt["proposal_digest"] != proposal_digest:
                    raise KarstError("IDEMPOTENCY_CONFLICT")
                return dict(receipt, status="duplicate")
            for r in [envelope["run_ref"], envelope["task_ref"], envelope["attempt_ref"], *envelope["expected_versions"]]:
                self.resolve(r, run_id, current=True)
            if run["data"]["state"] != "running" or task["data"]["state"] != "running" or attempt["data"]["state"] != "running":
                raise KarstError("inactive run/task/attempt")
            payload = deepcopy(envelope["payload"])
            exact(payload, ["summary", "outcome", "proposed_records", "suggested_opportunities"])
            text(payload["summary"])
            product = run["data"]["spec"]["runtime_profile"]["support_matrix_ref"] == "support:product-v1"
            research = product or run["data"]["spec"]["runtime_profile"]["support_matrix_ref"] == "support:research-v1"
            if product:
                for field in ("proposed_records", "suggested_opportunities"):
                    if not isinstance(payload[field], list):
                        raise KarstError(field+" must be a native JSON array, not a JSON-encoded string. "
                                         "Use [] or [{...}] directly; each proposed_records item needs local_ref,kind,data. "
                                         "Correct the arguments using a new tool call ID.")
            if payload["outcome"] not in ("progress", "no_progress", "partial", "inconclusive") or (not research and payload["suggested_opportunities"] != []):
                raise KarstError("unsupported outcome/opportunity proposal")
            proposals = payload["proposed_records"]
            opportunity_only = product and task["data"]["role"] == "research" and endpoint == "publish" and bool(payload["suggested_opportunities"])
            if not isinstance(proposals, list) or not (0 if opportunity_only else 1) <= len(proposals) <= 16:
                raise KarstError("an evidence-backed observation is required")
            keys, prepared = set(), []
            for p in ([] if research else proposals):
                exact(p, ["local_ref", "kind", "data"])
                text(p["local_ref"], 64)
                if p["local_ref"] in keys or p["kind"] != "observation":
                    raise KarstError("unsupported or duplicate proposal kind/key")
                keys.add(p["local_ref"])
                d = p["data"]
                exact(d, FIELDS["observation"].split())
                text(d["statement"])
                if d["provenance"] != "agent_interpreted" or d["conditions"] != []:
                    raise KarstError("I0 supports unconditional agent-interpreted observations only")
                if not isinstance(d["evidence_refs"], list) or not 1 <= len(d["evidence_refs"]) <= 16:
                    raise KarstError("observation requires current evidence")
                for r in d["evidence_refs"]:
                    self.evidence_bytes(r, run_id)
                for field in ("subject_refs", "contradicts_refs"):
                    if not isinstance(d[field], list) or len(d[field]) > 16:
                        raise KarstError("invalid observation references")
                    for r in d[field]:
                        self.resolve(r, run_id, "observation" if field == "contradicts_refs" else None, current=True)
                prepared.append(p)
            mapping = {}
            for p in prepared:
                mapping[p["local_ref"]] = ref(self.put("observation", run_id, p["data"]))
            if product and task["data"]["role"] == "verify":
                from karst.product import accept_verification
                mapping, payload = accept_verification(self, run, task, attempt, payload, endpoint)
            elif research:
                from karst.frontier import accept_research
                mapping, payload = accept_research(self, run, task, payload)
            # I0 has no cross-proposal local links: each observation cites existing material.
            result = self.put("result", run_id, {"submission_kind": endpoint, "task_ref": ref(task), "attempt_ref": ref(attempt),
                "proposal_digest": proposal_digest, "payload": payload, "accepted_refs": list(mapping.values())})
            if endpoint == "final":
                self.update(task, state="delivered", result_ref=ref(result), outcome=payload["outcome"])
                self.update(attempt, state="delivered", stop_reason="submitted", usage=self.attempt_usage(run_id, attempt["id"]))
            seq = self.db.execute("SELECT MAX(sequence) FROM changes WHERE run_id=?", (run_id,)).fetchone()[0]
            receipt = {"request_id": envelope["request_id"], "proposal_digest": proposal_digest, "status": "accepted",
                       "result_ref": ref(result), "local_ref_map": mapping, "state_version": seq, "error": None}
            self.db.execute("INSERT INTO receipts VALUES(?,?,?,?)", (run_id, endpoint, envelope["request_id"], encoded(receipt).decode()))
        return receipt

    def status(self, run_id):
        run = self.get(run_id, run_id=run_id)
        records = self.records(run_id)
        for record in records:
            if record["kind"] == "evidence":
                try:
                    self.evidence_bytes(ref(record), run_id)
                except KarstError:
                    record["data"]["availability"] = "unavailable"
        product = run["data"]["spec"]["runtime_profile"]["support_matrix_ref"] == "support:product-v1"
        findings = []
        if product:
            from karst.product import findings as project_findings, usable_capability
            findings = project_findings(self, run_id)
            stale = set()
            for record in records:
                if record["kind"] == "capability":
                    try:
                        usable_capability(self, run_id, ref(record))
                    except KarstError as exc:
                        record["data"].update(status="stale", invalidated_reason=str(exc))
                        stale.add(record["id"])
            for record in records:
                if record["kind"] == "path_edge" and any(r["id"] in stale for r in record["data"]["input_capability_refs"]+record["data"]["output_capability_refs"]):
                    record["data"]["status"] = "stale"
        return {"run_id": run_id, "record_schema": "karst-design/1", "run": run["data"], "records": records,
                "receipts": [json.loads(r[0]) for r in self.db.execute("SELECT data FROM receipts WHERE run_id=? ORDER BY rowid", (run_id,))],
                "usage": self.usage(run_id), "audit": self.audits(run_id), "findings": findings,
                "capability_status": ("Registered JSON object-read boundary verification; see coverage and limitations" if product else "Method-guided multi-task research; no capability or vulnerability verification"
                                      if run["data"]["spec"]["runtime_profile"]["support_matrix_ref"] == "support:research-v1"
                                      else "I0 normal-business model/HTTP integration; no vulnerability evaluation")}
