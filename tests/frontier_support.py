"""Deterministic development model; uses only model-visible tool replies."""

import json

from karst.frontier import METHOD
from tests.i0_support import observation, tool_reply


def opportunity(question, target, basis, *, lane="deepen", prerequisites=None):
    return {"question": question, "lane": lane, "target_refs": [target], "basis_refs": basis,
            "prerequisite_conditions": prerequisites or [], "expected_outcomes": ["Observed facts with their evidence and explicit limitations"],
            "method_family": METHOD, "priority": "normal", "reason": "Follow up the observed resource", "revisit_condition": None}


def frontier_model(payload):
    context = json.loads(payload["messages"][1]["content"])
    identities = {i["label"]: i["identity_ref"] for i in context["identities"]}
    replies = {m["tool_call_id"]: json.loads(m["content"]) for m in payload["messages"] if m["role"] == "tool"}
    targets = [r for r in context["read_set"] if r["kind"] == "asset" and r["data"]["asset_type"] == "web_resource"]
    origin = context["entrypoints"][0].rstrip("/")
    if not targets:
        if "read" not in replies:
            return tool_reply([("read", "http_request", {"url": origin+"/", "identity_ref": None, "query": []})])
        evidence = replies["read"]["evidence_refs"]
        root = json.loads(replies["read"]["preview"]["body_text"])
        if "publish" not in replies:
            proposed = observation("Entry navigation lists user catalogs", evidence)
            for name, path in root["catalogs"].items():
                proposed["proposed_records"] += [
                    {"local_ref": name, "kind": "asset", "data": {"asset_type": "web_resource", "locator": {"url": origin+path},
                        "parent_refs": context["opportunity"]["data"]["target_refs"], "provenance_refs": evidence}},
                    {"local_ref": "question-"+name, "kind": "hypothesis", "data": {"question": "What order and sharing context does "+name+" see?",
                        "basis_refs": [{"local_ref": name}], "alternative_explanations": ["Sharing or incomplete context"],
                        "missing_conditions": ["Actual order details"]}}]
                proposed["suggested_opportunities"].append(opportunity(
                    "Inspect "+name+" order and report actual user, order, reconciliation_code and limitations",
                    {"local_ref": name}, [{"local_ref": "question-"+name}],
                    prerequisites=[{"type": "task_delivered", "refs": [context["task_ref"]],
                                    "expected": {"state": "delivered"}, "rationale": "Finish entry inventory before separate order research"}]))
            return tool_reply([("publish", "publish_research", proposed)])
        if replies["publish"].get("status") != "accepted":
            raise AssertionError(replies["publish"])
        final = observation("Entry inventory published with separate order research opportunities", evidence)
        # A legal final can contain the same record kinds as an incremental
        # publication. Exercise mixed records in every development batch.
        for name, path in root["catalogs"].items():
            final["proposed_records"] += [
                {"local_ref": name, "kind": "asset", "data": {"asset_type": "web_resource", "locator": {"url": origin+path},
                    "parent_refs": context["opportunity"]["data"]["target_refs"], "provenance_refs": evidence}},
                {"local_ref": "question-"+name, "kind": "hypothesis", "data": {"question": "What sharing rules apply to "+name+"?",
                    "basis_refs": [{"local_ref": name}], "alternative_explanations": ["Sharing or incomplete context"],
                    "missing_conditions": ["Verified sharing rules"]}}]
        return tool_reply([("final", "submit_result", final)])
    target = targets[0]
    name = next(n for n in identities if n in context["briefing"].lower())
    if "read" not in replies:
        return tool_reply([("read", "http_request", {"url": target["data"]["locator"]["url"], "identity_ref": identities[name], "query": []})])
    if "detail" not in replies:
        body = json.loads(replies["read"]["preview"]["body_text"])
        return tool_reply([("detail", "http_request", {"url": origin+body["detail"], "identity_ref": identities[name], "query": []})])
    if "evidence" not in replies:
        return tool_reply([("evidence", "evidence_read", {"evidence_ref": replies["detail"]["evidence_refs"][0], "offset": 0, "length": 8192})])
    body = json.loads(replies["evidence"]["body_text"])
    return tool_reply([("final", "submit_result", observation(
        body["subject"]+" order="+body["order"]+" reconciliation_code="+body["reconciliation_code"]+"; sharing rules remain unknown",
        replies["detail"]["evidence_refs"]))])
