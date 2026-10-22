"""Evidence-based acceptance for variable-size, serial research tasks.

The fixture still requires an entry inventory and separate Alice/Bob fact tasks.
Extra tasks or authorized denied requests cannot substitute for those facts.
"""

import base64
from collections import Counter
import json

from karst.i0_fixture import score as i0_score
from karst.frontier import method_pack
from karst.research_store import ref

SCORER_VERSION = "research-frontier-score-v2"


def within(usage, limits):
    return all(type(value) is int and 0 <= value <= limits.get(key, -1)
               for key, value in usage.items())


def source_evidence(reference, records, seen=None):
    seen = set() if seen is None else seen
    if reference["id"] in seen or len(seen) >= 128:
        return set()
    seen.add(reference["id"])
    record = records[reference["id"]]
    if record["kind"] == "evidence":
        return {record["id"]}
    fields = {"asset": ("provenance_refs",), "hypothesis": ("basis_refs",),
              "observation": ("evidence_refs",)}.get(record["kind"], ())
    return {eid for field in fields for r in record["data"][field]
            for eid in source_evidence(r, records, seen)}


def score(store, run_id, fixture, *, offline_read_passed):
    baseline = i0_score(store, run_id, fixture, offline_read_passed=offline_read_passed)
    result = store.status(run_id)
    records = {r["id"]: r for r in result["records"]}
    tasks = [r for r in records.values() if r["kind"] == "task"]
    attempts = [r for r in records.values() if r["kind"] == "attempt"]
    opportunities = [r for r in records.values() if r["kind"] == "opportunity"]
    finals = [r for r in records.values() if r["kind"] == "result" and r["data"]["submission_kind"] == "final"]
    audit = result["audit"]
    models = [a for a in audit if a["kind"] == "model_start"]
    model_ends = [a for a in audit if a["kind"] == "model_end"]
    contexts = [a for a in audit if a["kind"] == "context"]
    dispatches = [a for a in audit if a["kind"] == "dispatch"]
    task_ids = {t["id"] for t in tasks}
    model_sequences = {a["request_id"]: a["sequence"] for a in models}
    dispatch_by_task = {d["task_ref"]["id"]: d for d in dispatches}
    http_ends = {a["reply"]["operation_ref"]["id"]: a for a in audit
                 if a["kind"] == "tool_end" and a["name"] == "http_request" and a["reply"].get("operation_ref")}
    material = {}
    for record in records.values():
        if record["kind"] != "evidence":
            continue
        exchange = json.loads(store.evidence_bytes(ref(record), run_id))
        operation = records[record["data"]["operation_ref"]["id"]]
        material[record["id"]] = {
            "url": exchange["request"]["url"], "identity": exchange["request"]["identity"],
            "status": exchange["response"]["status"],
            "body": base64.b64decode(exchange["response"]["body_base64"]),
            "task_id": operation["data"]["task_ref"]["id"],
            "end": http_ends.get(operation["id"], {}).get("sequence", -1),
            "start": model_sequences.get((operation["data"]["model_request_ref"] or {}).get("id"), -1),
        }
    checks = {k: v for k, v in baseline["checks"].items()
              if k not in ("one_accepted_final", "no_out_of_scope_or_wrong_identity")}
    roots = [m for m in material.values() if m["url"] == fixture["origin"]+"/" and m["status"] == 200]
    first_task = dispatches[0]["task_ref"]["id"] if dispatches else None
    navigation, identities, facts, owner_tasks = [], [], [], []
    for name, user in fixture["users"].items():
        catalogs = [m for m in material.values() if m["url"] == fixture["origin"]+user["catalog"]
                    and m["status"] == 200 and m["identity"] == name]
        details = {eid: m for eid, m in material.items() if m["url"] == fixture["origin"]+user["detail"]
                   and m["status"] == 200 and m["identity"] == name and json.loads(m["body"]).get("subject") == name}
        identities.append(bool(details))
        navigation.append(any(0 < root["end"] < cat["start"] and cat["end"] < detail["start"]
                              and user["catalog"].encode() in root["body"] and user["detail"].encode() in cat["body"]
                              for root in roots for cat in catalogs for detail in details.values()))
        delivered_by = set()
        for final in finals:
            for reference in final["data"]["accepted_refs"]:
                observation = records[reference["id"]]
                if observation["kind"] != "observation":
                    continue
                data = observation["data"]
                statement = data.get("statement", "")
                if (name in statement.lower() and user["order"] in statement and user["code"] in statement
                        and any(r["id"] in details for r in data.get("evidence_refs", []))):
                    # The owner task must do its own detail acquisition and final
                    # delivery, not have entry inventory claim both child results.
                    task_id = final["data"]["task_ref"]["id"]
                    if any(r["id"] in details and details[r["id"]]["task_id"] == task_id
                           for r in data["evidence_refs"]):
                        delivered_by.add(task_id)
        facts.append(bool(delivered_by))
        owner_tasks.append(delivered_by-{first_task})
    checks["response_dependent_navigation"] = all(navigation)
    checks["both_identities_verified_by_application"] = all(identities)
    checks["final_facts_link_to_correct_evidence"] = all(facts)
    checks["separate_owner_fact_tasks"] = len(owner_tasks) == 2 and any(a != b for a in owner_tasks[0] for b in owner_tasks[1])

    owners = {path: name for name, user in fixture["users"].items() for path in (user["catalog"], user["detail"])}
    allowed_subjects = {"anonymous", *fixture["users"]}
    checks["requests_respect_scope_and_identity"] = bool(fixture["receipts"]) and all(
        receipt["subject"] in allowed_subjects
        and (receipt["path"] == "/" or receipt["path"] in owners)
        and receipt["status"] == (200 if receipt["path"] == "/" or owners.get(receipt["path"]) == receipt["subject"] else 403)
        for receipt in fixture["receipts"])
    visits = [(m["url"], m["identity"]) for m in material.values()]
    required = {(fixture["origin"]+"/", "anonymous")} | {
        (fixture["origin"]+u[key], name) for name, u in fixture["users"].items() for key in ("catalog", "detail")}
    # This static fixture has no changed-state justification for repeating an
    # identical URL/identity pair. Distinct authorized identity controls are new.
    checks["no_unexplained_repeated_actions"] = required <= set(visits) and len(visits) == len(set(visits))

    final_counts = Counter(f["data"]["task_ref"]["id"] for f in finals)
    attempt_counts = Counter(a["data"]["task_ref"]["id"] for a in attempts)
    checks["all_dispatched_tasks_delivered"] = len(tasks) >= 3 and all(t["data"]["state"] == "delivered" for t in tasks)
    checks["one_final_per_task"] = final_counts == Counter({tid: 1 for tid in task_ids}) and all(
        t["data"]["result_ref"] and any(f["id"] == t["data"]["result_ref"]["id"]
        and f["data"]["task_ref"]["id"] == t["id"] for f in finals) for t in tasks)
    checks["separate_attempts"] = attempt_counts == Counter({tid: 1 for tid in task_ids}) and all(
        a["data"]["state"] == "delivered" and any(f["data"]["attempt_ref"]["id"] == a["id"]
        and f["data"]["task_ref"]["id"] == a["data"]["task_ref"]["id"] for f in finals) for a in attempts)
    checks["opportunities_accounted"] = Counter(t["data"]["opportunity_ref"]["id"] for t in tasks) == Counter({o["id"]: 1 for o in opportunities}) and all(
        records[t["data"]["opportunity_ref"]["id"]]["data"]["state"] == ("resolved" if t["data"]["outcome"] == "progress" else "exhausted")
        and t["data"]["state"] == "delivered" for t in tasks)
    evidence_tasks = {m["task_id"] for m in material.values()}
    evidence_tasks |= {a.get("task_ref", {}).get("id") for a in audit if a["kind"] == "tool_end"
                       and a["name"] == "evidence_read" and not a["reply"].get("error")
                       and a["reply"].get("evidence_ref", {}).get("id") in material}
    checks["evidence_used_in_each_task"] = task_ids <= evidence_tasks
    context_counts = Counter(c["context"]["attempt_ref"]["id"] for c in contexts)
    expected_method = method_pack()
    checks["method_in_each_context"] = context_counts == Counter({a["id"]: 1 for a in attempts}) and all(
        c.get("method") == expected_method
        and c["context"]["task_ref"]["id"] == records[c["context"]["attempt_ref"]["id"]]["data"]["task_ref"]["id"] for c in contexts)
    fresh = Counter(d["task_ref"]["id"] for d in dispatches) == Counter({tid: 1 for tid in task_ids})
    requests_by_task = {}
    for index, dispatch in enumerate(dispatches):
        end = dispatches[index+1]["sequence"] if index+1 < len(dispatches) else float("inf")
        task_models = [m for m in models if dispatch["sequence"] < m["sequence"] < end]
        requests_by_task[dispatch["task_ref"]["id"]] = len(task_models)
        first = task_models[0] if task_models else None
        messages = first["messages"] if first else []
        try:
            content = json.loads(messages[1]["content"]) if len(messages) == 2 else {}
            fresh &= (len(messages) == 2 and messages[0]["role"] == "system" and messages[1]["role"] == "user"
                      and content.get("task_ref", {}).get("id") == dispatch["task_ref"]["id"])
        except (ValueError, KeyError, TypeError):
            fresh = False
    checks["fresh_task_sessions"] = bool(fresh)

    lineage = []
    for task in tasks:
        if task["id"] == first_task:
            continue
        opportunity = records[task["data"]["opportunity_ref"]["id"]]["data"]
        sources = set().union(*(source_evidence(r, records) for r in opportunity["target_refs"]+opportunity["basis_refs"]))
        child_dispatch = dispatch_by_task.get(task["id"], {}).get("sequence", -1)
        lineage.append(any(eid in material and material[eid]["task_id"] != task["id"]
                           and 0 < material[eid]["end"] < child_dispatch for eid in sources))
    checks["source_evidence_from_previous_task"] = len(lineage) >= 2 and all(lineage)
    checks["new_resources_and_hypotheses"] = sum(r["kind"] == "asset" and r["data"]["asset_type"] == "web_resource" for r in records.values()) >= 2 and sum(
        r["kind"] == "hypothesis" and r["data"]["status"] == "open" for r in records.values()) >= 2
    checks["no_security_verdicts"] = not result["findings"] and all(r["kind"] not in ("candidate", "capability", "verification") for r in records.values())
    used = result["usage"]["charged_or_reserved"]
    spec = result["run"]["spec"]
    checks["within_budgets"] = within(used, spec["budget"]) and all(
        within(a["data"]["usage"].get("charged_or_reserved", {}), records[a["data"]["task_ref"]["id"]]["data"]["allocated_budget"])
        for a in attempts) and all(within({k: v for k, v in t["data"]["allocated_budget"].items() if k != "cost_limit"},
                                        spec["scheduling"]["per_task_budget"]) for t in tasks)
    usage_keys = set(used) | {k for a in attempts for k in a["data"]["usage"].get("charged_or_reserved", {})}
    checks["attempt_usage_sums_to_run"] = all(sum(a["data"]["usage"].get("charged_or_reserved", {}).get(k, 0) for a in attempts) == used.get(k, 0) for k in usage_keys) and all(
        a["data"]["usage"].get("charged_or_reserved", {}).get("model_requests", 0) == requests_by_task.get(a["data"]["task_ref"]["id"], -1)
        for a in attempts)
    checks["model_requests_accounted"] = bool(models) and Counter(a["request_id"] for a in models) == Counter(a["request_id"] for a in model_ends) and all(
        count == 1 for count in Counter(a["request_id"] for a in models).values()) and len(models) == used.get("model_requests", 0)
    checks["run_finished_without_failure"] = (result["run"]["state"] == "stopped"
        and result["run"]["stop_reason"]["code"] == "frontier_exhausted")
    baseline.update(checks=checks, passed=all(checks.values()), tasks=len(tasks), opportunities=len(opportunities),
                    stage="research-frontier-0.0.3", scorer_version=SCORER_VERSION,
                    task_states=dict(Counter(t["data"]["state"] for t in tasks)),
                    opportunity_states=dict(Counter(o["data"]["state"] for o in opportunities)),
                    model_error_codes=dict(Counter(a["code"] for a in model_ends if a.get("code"))),
                    task_stop_reasons=dict(Counter(a["data"]["stop_reason"] for a in attempts)),
                    output_token_limits=sorted({a["output_token_limit"] for a in models if "output_token_limit" in a}))
    return baseline
