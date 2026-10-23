"""Explicit clean task-boundary checkpoints; interrupted actions are never replayed."""

from collections import Counter
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import math
from pathlib import Path
import time

from karst.config import KarstError
from karst.research_store import ref
from karst.store import encoded, new_id

VERSION = "task-boundary-checkpoint-v1"


def sha(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def bindings(launch, gateway, secrets, run_id):
    root = Path(__file__).parent
    return {"launch": sha({"spec": launch.spec, "briefing": launch.briefing, "execution": launch.execution,
                           "identities": [vars(i) for i in launch.transport.identities]}),
            "gateway": sha(gateway),
            "runtime": {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
                        for p in sorted([*root.glob("*.py"), *root.glob("methods/*.json")])},
            "credentials": {k: sha([run_id, k, v]) for k, v in secrets.items()}}


def state_digest(store, run_id, before_sequence=None):
    """Seal retained state and prior audit, without exporting private bindings."""
    h = hashlib.sha256()
    for table, order in (("records", "id,version"), ("changes", "sequence"), ("receipts", "endpoint,request_id"),
                         ("calls", "attempt_id,call_id"), ("reservations", "key"), ("audit", "sequence")):
        query = "SELECT * FROM "+table+" WHERE run_id=?"
        args = [run_id]
        if table == "audit" and before_sequence is not None:
            query += " AND sequence<?"
            args.append(before_sequence)
        for row in store.db.execute(query+" ORDER BY "+order, args):
            h.update(encoded([table, dict(row)]))
            h.update(b"\n")
    return h.hexdigest()


def clean_boundary(store, run_id, task_id, attempt_id):
    task, attempt = (store.get(i, run_id=run_id) for i in (task_id, attempt_id))
    if task["data"]["state"] != "delivered" or attempt["data"]["state"] != "delivered" or attempt["data"]["task_ref"]["id"] != task_id:
        raise KarstError("resume_requires_delivered_task_boundary")
    for record in store.records(run_id):
        d = record["data"]
        if ((record["kind"] == "operation" and d["execution_state"] in ("planned", "running", "unknown"))
                or (record["kind"] == "attempt" and d["state"] in ("running", "unknown"))
                or (record["kind"] == "task" and d["state"] == "running")):
            raise KarstError("resume_unknown_or_active_execution")
        if record["kind"] == "session" and (d["generation"] != 1 or d["auth_status"] in ("expired", "revoked")):
            raise KarstError("resume_stale_session")
        if record["kind"] == "evidence":
            store.evidence_bytes(ref(record), run_id)
    if store.db.execute("SELECT 1 FROM calls WHERE run_id=? AND state!='done'", (run_id,)).fetchone():
        raise KarstError("resume_unknown_or_active_call")
    audit = store.audits(run_id)
    if Counter(a["request_id"] for a in audit if a["kind"] == "model_start") != Counter(a["request_id"] for a in audit if a["kind"] == "model_end"):
        raise KarstError("resume_incomplete_model_request")


def checkpoint(h, gateway):
    store = h.store
    with store.atomic():
        clean_boundary(store, h.run_id, h.task_id, h.attempt_id)
        h.finish("task_boundary_pause", "Paused after delivered task; resume starts a fresh task and model session")
        private = bindings(h.launch, gateway, h.secrets, h.run_id)
        state_hash = state_digest(store, h.run_id)
        active = h.active_seconds+math.ceil(time.monotonic()-h.invocation_started)
        point = {
            "checkpoint_version": VERSION, "task_ref": ref(store.get(h.task_id)),
            "attempt_ref": ref(store.get(h.attempt_id)), "active_wall_seconds": active,
            "private_bindings": private, "state_sha256": state_hash}
        store.audit(h.run_id, "task_boundary_checkpoint", dict(point, checkpoint_sha256=sha(point)))


def restore(launch, store, secrets, gateway, run_id):
    from karst.research import Host, TransportBridge
    run = store.get(run_id, run_id=run_id)
    reason = run["data"].get("stop_reason") or {}
    if run["data"]["state"] != "paused" or reason.get("code") != "task_boundary_pause":
        raise KarstError("resume_requires_clean_task_boundary_checkpoint")
    audit = store.audits(run_id)
    point = audit[-1] if audit else {}
    if point.get("kind") != "task_boundary_checkpoint" or point.get("checkpoint_version") != VERSION:
        raise KarstError("resume_checkpoint_unavailable")
    payload = {k: v for k, v in point.items() if k not in ("schema_version", "sequence", "at", "kind", "checkpoint_sha256")}
    if point.get("checkpoint_sha256") != sha(payload):
        raise KarstError("resume_checkpoint_integrity_failed")
    if point["private_bindings"] != bindings(launch, gateway, secrets, run_id):
        raise KarstError("resume_configuration_runtime_or_credentials_changed")
    if point["state_sha256"] != state_digest(store, run_id, point["sequence"]):
        raise KarstError("resume_checkpoint_state_changed")
    clean_boundary(store, run_id, point["task_ref"]["id"], point["attempt_ref"]["id"])
    for key in ("task_ref", "attempt_ref"):
        store.resolve(point[key], run_id, current=True)
    active = point["active_wall_seconds"]
    if type(active) is not int or active < 0 or active >= launch.spec["budget"]["wall_seconds"]:
        raise KarstError("budget_exhausted")
    h = Host.__new__(Host)
    h.configure(launch, store, secrets, active_seconds=active)
    h.run_id, h.task_id, h.attempt_id = run_id, point["task_ref"]["id"], point["attempt_ref"]["id"]
    h.owner = new_id("host")
    h.identity_by_label = {r["data"]["label"]: r for r in store.records(run_id, "identity")}
    h.session_by_identity = {r["data"]["identity_ref"]["id"]: r for r in store.records(run_id, "session")}
    h.context = deepcopy(next(a["context"] for a in reversed(audit) if a["kind"] == "context"))
    h.bridge = TransportBridge(h)
    # Preserve the provider quiet interval even when the previous Host process
    # has exited. Paused time counts toward pacing, not the Run's active time.
    if gateway.get("min_request_interval_seconds"):
        from karst.gateway import Gateway
        last = next((a for a in reversed(audit) if a["kind"] == "model_end"), None)
        if last:
            elapsed = max(0, (datetime.now(timezone.utc)-datetime.fromisoformat(last["at"].replace("Z", "+00:00"))).total_seconds())
            key = gateway["api_base"], gateway["model"]
            Gateway._last_response_at[key] = max(Gateway._last_response_at.get(key, float("-inf")), time.monotonic()-elapsed)
    with store.atomic():
        run = store.update(run, state="running", stop_reason=None)
        h.context["run_ref"] = ref(run)
        store.audit(run_id, "task_boundary_resumed", {"checkpoint_sequence": point["sequence"],
                    "active_wall_seconds": active, "previous_task_ref": point["task_ref"]})
    return h
