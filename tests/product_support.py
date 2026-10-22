"""Deterministic model uses exclusively the same visible context and tool replies."""

import json

from karst.frontier import METHOD
from tests.i0_support import observation, tool_reply


def product_model(payload, *, false_candidate=False):
    context = json.loads(payload["messages"][1]["content"])
    replies = {m["tool_call_id"]: json.loads(m["content"]) for m in payload["messages"] if m["role"] == "tool"}
    identities = {i["label"]: i["identity_ref"] for i in context["identities"]}
    origin = context["entrypoints"][0].rstrip("/")
    def get(key, url, identity=None):
        return key, "http_request", {"url": url, "identity_ref": identity, "query": []}
    if context["role"] == "verify":
        candidate = next(r for r in context["read_set"] if r["kind"] == "candidate")
        rule = next(r for r in context["read_set"] if r["kind"] == "security_rule")
        sources = context["evidence_sources"]
        if "original-0" not in replies:
            return tool_reply([("original-"+str(i), "evidence_read", {"evidence_ref": row["evidence_ref"], "offset": 0, "length": 8192}) for i, row in enumerate(sources)])
        policy_index = next(i for i, row in enumerate(sources) if "access_policy" in json.loads(replies["original-"+str(i)]["body_text"]))
        policy = json.loads(replies["original-"+str(policy_index)]["body_text"])["access_policy"]
        target = next(r for r in context["read_set"] if r["kind"] == "asset")["data"]["locator"]["url"]
        subject = next(r for r in context["read_set"] if r["kind"] == "identity")
        if "fresh-policy" not in replies:
            return tool_reply([get("fresh-policy", sources[policy_index]["url"]),
                               get("fresh-owner", target, identities[policy["owner"]]),
                               get("fresh-reader", target, {k: subject[k] for k in ("kind", "id", "version")})])
        current = json.loads(replies["fresh-policy"]["preview"]["body_text"])
        verdict = "inconclusive"
        if current.get("access_policy") == policy:
            verdict = "ruled_out" if subject["data"]["label"] in policy["readers"] or replies["fresh-reader"]["preview"]["http_status"] == 403 else "supported"
        data = {"candidate_ref": {k: candidate[k] for k in ("kind", "id", "version")},
                "candidate_claim_revision": candidate["data"]["claim_revision"],
                "evidence_refs": [replies[key]["evidence_refs"][0] for key in ("fresh-policy", "fresh-owner", "fresh-reader")],
                "counterevidence_refs": [], "verdict": verdict, "reproduction_status": "reproduced",
                "impact_boundary": "The observed subject and protected purchase object only; no broader privilege claim",
                "remaining_questions": ["Policy changed"] if verdict == "inconclusive" else []}
        return tool_reply([("final", "submit_result", {"summary": verdict, "outcome": "progress", "proposed_records": [{"local_ref": "review", "kind": "verification", "data": data}], "suggested_opportunities": []})])
    targets = [r for r in context["read_set"] if r["kind"] == "asset" and r["data"]["asset_type"] == "web_resource"]
    if targets:
        capability = next(r for r in context["read_set"] if r["kind"] == "capability")
        if "follow" not in replies:
            return tool_reply([get("follow", targets[0]["data"]["locator"]["url"], capability["data"]["subject_ref"])])
        return tool_reply([("final", "submit_result", observation("Actual dependent resource read", replies["follow"]["evidence_refs"]))])
    if "entry" not in replies:
        return tool_reply([get("entry", origin+"/")])
    navigation = json.loads(replies["entry"]["preview"]["body_text"])["resources"][0]
    if "policy" not in replies:
        return tool_reply([get("policy", origin+navigation["policy_url"]), get("owner", origin+navigation["url"], identities["alice"]), get("reader", origin+navigation["url"], identities["bob"])])
    if "publish" not in replies:
        root_evidence = replies["entry"]["evidence_refs"]
        proposal = observation("Compared owner and managed reader with the published policy", replies["owner"]["evidence_refs"]+replies["reader"]["evidence_refs"])
        proposal["proposed_records"].append({"local_ref": "resource", "kind": "asset", "data": {"asset_type": "web_resource",
            "locator": {"url": origin+navigation["url"]}, "parent_refs": [], "provenance_refs": root_evidence}})
        policy = json.loads(replies["policy"]["preview"]["body_text"])
        if "access_policy" in policy:
            proposal["proposed_records"].append({"local_ref": "rule", "kind": "security_rule", "data": {"statement": "Published explicit object read policy",
                "applies_to_refs": [{"local_ref": "resource"}], "source_refs": replies["policy"]["evidence_refs"], "source_type": "target_document"}})
            if "bob" not in policy["access_policy"]["readers"] or false_candidate:
                proposal["proposed_records"].append({"local_ref": "candidate", "kind": "candidate", "data": {
                    "claim": {"type": "object_read_boundary", "protected_fields": ["private_value"]}, "affected_refs": [{"local_ref": "resource"}, identities["bob"]],
                    "rule_refs": [{"local_ref": "rule"}], "supporting_refs": replies["owner"]["evidence_refs"]+replies["reader"]["evidence_refs"],
                    "counterevidence_refs": [], "required_conditions": [], "alternative_explanations": ["Explicit sharing may permit access"], "missing_conditions": []}})
        else:
            proposal["proposed_records"].append({"local_ref": "unknown", "kind": "hypothesis", "data": {"question": "What sharing policy applies?",
                "basis_refs": replies["policy"]["evidence_refs"], "alternative_explanations": ["Access may be permitted or denied"], "missing_conditions": ["Explicit policy"]}})
        reader = json.loads(replies["reader"]["preview"]["body_text"])
        links = reader.get("links", [])
        if links:
            capability = replies["reader"]["capability_ref"]
            proposal["proposed_records"].append({"local_ref": "next", "kind": "asset", "data": {"asset_type": "web_resource",
                "locator": {"url": origin+links[0]}, "parent_refs": [{"local_ref": "resource"}], "provenance_refs": replies["reader"]["evidence_refs"]}})
            proposal["suggested_opportunities"].append({"question": "Investigate the newly exposed dependent resource with the acquired reader capability", "lane": "deepen",
                "target_refs": [{"local_ref": "next"}], "basis_refs": [capability], "prerequisite_conditions": [{"type": "capability_verified", "refs": [capability],
                    "expected": {"actions": ["read"]}, "rationale": "The original object response supplied this resource"}],
                "expected_outcomes": ["Actual subsequent object contents with evidence"], "method_family": METHOD, "priority": "normal", "reason": "Actual new input", "revisit_condition": None})
        return tool_reply([("publish", "publish_research", proposal)])
    if replies["publish"].get("status") != "accepted":
        raise AssertionError(replies["publish"])
    return tool_reply([("final", "submit_result", observation("Object-read investigation delivered with recorded limitations", replies["owner"]["evidence_refs"]+replies["reader"]["evidence_refs"]))])
