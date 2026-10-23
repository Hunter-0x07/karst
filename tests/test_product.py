"""Product checks cross real HTTP, versioned state, separate reviews and reports."""

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT/"src"), str(ROOT)]

from karst import product, research
from karst.application import credential_values
from karst.config import KarstError
from karst.product_fixture import BRIEFING, application_fixture, score
from karst.protocol import ToolCall
from karst.research_config import parse_launch, product_template, research_template
from karst.research_store import ResearchStore, ref
from tests.i0_support import model_server
from tests.product_support import product_model


class ProductTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        env = patch.dict(os.environ, {})
        env.start()
        self.addCleanup(env.stop)

    def save(self, name, value):
        path = self.root/name
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def run_model(self, scenario="P1", responder=product_model):
        with application_fixture(scenario) as fixture, model_server(responder) as (gateway, requests):
            for name, token in fixture["tokens"].items():
                os.environ["KARST_I0_"+name.upper()] = token
            result = research.run(self.save("launch.json", product_template(fixture["origin"], BRIEFING, mode="mock")),
                                  self.save("gateway.json", gateway), self.root/"data", allow_mock=True)
        exported = research.export(self.root/"data", result["run_id"], self.root/"export")
        with ResearchStore(self.root/"data", readonly=True) as store:
            scored = score(store, result["run_id"], fixture, offline_passed=True)
        return result, fixture, requests, scored, exported

    def test_positive_independent_review_and_report(self):
        result, fixture, requests, scored, exported = self.run_model()
        self.assertTrue(scored["passed"], scored)
        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual(scored["tasks"], 2)
        verification = next(r for r in result["records"] if r["kind"] == "verification")
        self.assertNotEqual(verification["data"]["independence"]["discovery_task_ref"]["id"], verification["data"]["task_ref"]["id"])
        self.assertEqual(len([r for r in requests if len(r["messages"]) == 2]), 2)
        expected = {"run.json", "manifest.json", "report.md", "findings.json", "coverage.json", "operations.jsonl", "evidence-index.json"}
        self.assertEqual(set(exported["files"]), expected)
        manifest = json.loads((self.root/"export/manifest.json").read_text(encoding="utf-8"))
        for name, digest in manifest["files_sha256"].items():
            self.assertEqual(hashlib.sha256((self.root/"export"/name).read_bytes()).hexdigest(), digest)

    def test_encoded_arrays_are_rejected_then_corrected_without_partial_writes(self):
        def corrected(payload):
            response = product_model(payload)
            context = json.loads(payload["messages"][1]["content"])
            replies = {m["tool_call_id"]: json.loads(m["content"]) for m in payload["messages"] if m["role"] == "tool"}
            if context["role"] == "research":
                for call in response["choices"][0]["message"].get("tool_calls", []):
                    name = call["function"]["name"]
                    field = {"publish_research": "proposed_records", "submit_result": "suggested_opportunities"}.get(name)
                    bad_id = "bad-"+name
                    if field and bad_id not in replies:
                        data = json.loads(call["function"]["arguments"])
                        data[field] = '[{"malformed": '
                        call["id"] = bad_id
                        call["function"]["arguments"] = json.dumps(data)
            return response
        result, _, _, scored, _ = self.run_model(responder=corrected)
        self.assertTrue(scored["passed"], scored)
        self.assertEqual(scored["target_requests"], 7)
        with ResearchStore(self.root/"data", readonly=True) as store:
            rejected = [a for a in store.audits(result["run_id"]) if a["kind"] == "proposal_rejected"]
            self.assertEqual(len(rejected), 2)
            for item, field in zip(rejected, ("proposed_records", "suggested_opportunities")):
                self.assertIn(field+" must be a native JSON array", item["receipt"]["error"]["message"])
                self.assertEqual(item["receipt"]["local_ref_map"], {})
            self.assertEqual(len(store.records(result["run_id"], "candidate")), 1)
            self.assertEqual(len(store.records(result["run_id"], "verification")), 1)

    def test_opportunity_target_error_identifies_required_resource_ref(self):
        def corrected(payload):
            response = product_model(payload)
            replies = {m["tool_call_id"]: json.loads(m["content"]) for m in payload["messages"] if m["role"] == "tool"}
            for call in response["choices"][0]["message"].get("tool_calls", []):
                if call["function"]["name"] == "publish_research" and "bad-target" not in replies:
                    data = json.loads(call["function"]["arguments"])
                    data["suggested_opportunities"][0]["target_refs"] = [{"local_ref": "obs"}]
                    call["id"] = "bad-target"
                    call["function"]["arguments"] = json.dumps(data)
            return response
        result, _, _, scored, _ = self.run_model("P2", corrected)
        self.assertTrue(scored["passed"], scored)
        rejected = next(a for a in result["audit"] if a["kind"] == "proposal_rejected")
        self.assertIn("suggested_opportunities.target_refs requires asset Refs", rejected["receipt"]["error"]["message"])

    def test_scope_uses_runspec_and_critical_navigation_requires_prior_response(self):
        from tests.i0_support import tool_reply
        def corrected_probe(payload):
            context = json.loads(payload["messages"][1]["content"])
            replies = {m["tool_call_id"] for m in payload["messages"] if m["role"] == "tool"}
            if context["role"] == "research" and "entry" in replies and "probe" not in replies:
                return tool_reply([("probe", "http_request", {"url": context["entrypoints"][0].rstrip("/")+"/typo-recovered", "identity_ref": None, "query": []})])
            return product_model(payload)
        result, fixture, _, scored, _ = self.run_model(responder=corrected_probe)
        self.assertTrue(scored["passed"], scored)
        self.assertTrue(any(r["status"] == 404 for r in fixture["receipts"]))
        with ResearchStore(self.root/"data", readonly=True) as store:
            original = product.material
            def outside(*args):
                e, op, exchange, body = original(*args)
                exchange["request"]["url"] = "http://example.invalid"+fixture["detail"]
                return e, op, exchange, body
            with patch.object(product, "material", side_effect=outside):
                self.assertFalse(score(store, result["run_id"], fixture, offline_passed=True)["checks"]["scope_and_identity"])
            snapshot = store.status(result["run_id"])
            entry = next(a for a in snapshot["audit"] if a["kind"] == "tool_end" and a.get("call_id") == "entry")
            entry["sequence"] = 10**9
            with patch.object(store, "status", return_value=snapshot):
                self.assertFalse(score(store, result["run_id"], fixture, offline_passed=True)["checks"]["response_dependent_navigation"])

    def test_low_budget_reminder_preserves_final_delivery(self):
        from tests.i0_support import tool_reply
        def delayed(payload):
            context = json.loads(payload["messages"][1]["content"])
            replies = {m["tool_call_id"] for m in payload["messages"] if m["role"] == "tool"}
            if context["role"] == "research":
                for index in range(6):
                    call_id = "inspect-"+str(index)
                    if call_id not in replies:
                        return tool_reply([(call_id, "session_inspect", {})])
            return product_model(payload)
        _, _, requests, scored, _ = self.run_model(responder=delayed)
        self.assertTrue(scored["passed"], scored)
        self.assertTrue(any("Runtime budget: at most 3 model requests remain" in m.get("content", "")
                            for r in requests for m in r["messages"] if m["role"] == "user"))

    def test_dependent_capability_is_used_in_real_followup(self):
        result, fixture, _, scored, _ = self.run_model("P2")
        self.assertTrue(scored["passed"], scored)
        self.assertEqual(scored["tasks"], 3)
        self.assertTrue(any(r["kind"] == "path_edge" and r["data"]["status"] == "proven" for r in result["records"]))
        self.assertTrue(any(r["path"] == fixture["followup"] and r["subject"] == "bob" and r["status"] == 200 for r in fixture["receipts"]))

    def test_shared_and_missing_policy_do_not_generate_findings(self):
        for scenario in ("P3", "P4"):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as folder:
                self.root = Path(folder)
                result, _, _, scored, _ = self.run_model(scenario)
                self.assertTrue(scored["passed"], scored)
                self.assertFalse(result["findings"])

    def test_wrong_candidate_is_independently_ruled_out(self):
        result, _, _, scored, _ = self.run_model("P3", lambda p: product_model(p, false_candidate=True))
        self.assertTrue(scored["passed"], scored)
        self.assertEqual(scored["candidate_states"], {"ruled_out": 1})
        self.assertFalse(result["findings"])

    def test_rule_and_candidate_sources_trace_observations_and_resources(self):
        def sourced(payload):
            response = product_model(payload)
            for call in response["choices"][0]["message"].get("tool_calls", []):
                if call["function"]["name"] != "publish_research":
                    continue
                proposal = json.loads(call["function"]["arguments"])
                context = json.loads(payload["messages"][1]["content"])
                replies = {m["tool_call_id"]: json.loads(m["content"]) for m in payload["messages"] if m["role"] == "tool"}
                nav = json.loads(replies["entry"]["preview"]["body_text"])["resources"][0]
                proposal["proposed_records"].extend([
                    {"local_ref": "policy-source", "kind": "asset", "data": {"asset_type": "web_resource", "locator": {"url": context["entrypoints"][0].rstrip("/")+nav["policy_url"]}, "parent_refs": [], "provenance_refs": replies["entry"]["evidence_refs"]}},
                    {"local_ref": "policy-observation", "kind": "observation", "data": {"statement": "Published policy document", "evidence_refs": replies["policy"]["evidence_refs"], "subject_refs": [], "conditions": [], "provenance": "agent_interpreted", "contradicts_refs": []}}])
                for record in proposal["proposed_records"]:
                    if record["kind"] == "security_rule":
                        record["data"]["source_refs"] = [{"local_ref": "policy-source"}, {"local_ref": "policy-observation"}]
                    if record["kind"] == "candidate":
                        record["data"]["supporting_refs"] = [{"local_ref": "obs"}]
                call["function"]["arguments"] = json.dumps(proposal)
            return response
        result, _, _, scored, _ = self.run_model(responder=sourced)
        self.assertTrue(scored["passed"], scored)
        with ResearchStore(self.root/"data", readonly=True) as store:
            candidate = store.records(result["run_id"], "candidate")[0]
            self.assertTrue(any(r["kind"] == "observation" for r in candidate["data"]["supporting_refs"]))
            self.assertEqual(len(product.evidence_sources(store, result["run_id"], candidate["data"]["supporting_refs"])), 2)

    def test_within_task_link_use_is_bound_to_actual_parent_operation(self):
        def immediate(payload):
            context = json.loads(payload["messages"][1]["content"])
            replies = {m["tool_call_id"]: json.loads(m["content"]) for m in payload["messages"] if m["role"] == "tool"}
            if context["role"] == "research" and "reader" in replies and "immediate" not in replies:
                body = json.loads(replies["reader"]["preview"]["body_text"])
                if body.get("links"):
                    identity = next(i["identity_ref"] for i in context["identities"] if i["label"] == "bob")
                    from tests.i0_support import tool_reply
                    return tool_reply([("immediate", "http_request", {"url": context["entrypoints"][0].rstrip("/")+body["links"][0], "identity_ref": identity, "query": []})])
            response = product_model(payload)
            for call in response["choices"][0]["message"].get("tool_calls", []):
                if call["function"]["name"] == "publish_research":
                    proposal = json.loads(call["function"]["arguments"])
                    proposal["suggested_opportunities"] = []
                    proposal["proposed_records"].append({"local_ref": "immediate-rule", "kind": "hypothesis", "data": {
                        "question": "Which rule applies to the resource just read through the parent link?",
                        "basis_refs": replies["immediate"]["evidence_refs"],
                        "alternative_explanations": ["The parent policy may not apply to this resource"],
                        "missing_conditions": ["Explicit read policy for the newly read resource"]}})
                    call["function"]["arguments"] = json.dumps(proposal)
            return response
        result, _, _, scored, _ = self.run_model("P2", immediate)
        self.assertTrue(scored["passed"], scored)
        self.assertEqual(scored["tasks"], 2)
        with ResearchStore(self.root/"data", readonly=True) as store:
            edge = store.records(result["run_id"], "path_edge")[0]
            operation = store.resolve(edge["data"]["operation_refs"][0], result["run_id"])
            parent = store.resolve(operation["data"]["parent_operation_ref"], result["run_id"])
            self.assertEqual(parent["data"]["task_ref"]["id"], operation["data"]["task_ref"]["id"])

    def test_opportunity_only_publication_uses_existing_evidence(self):
        def queue_only(payload):
            context = json.loads(payload["messages"][1]["content"])
            replies = {m["tool_call_id"]: json.loads(m["content"]) for m in payload["messages"] if m["role"] == "tool"}
            if context["role"] == "research" and "publish" in replies and "queue" not in replies:
                from tests.frontier_support import opportunity
                from tests.i0_support import tool_reply
                capability = replies["reader"]["capability_ref"]
                target = replies["publish"]["local_ref_map"]["next"]
                op = opportunity("Read the actual newly linked object", target, [capability], prerequisites=[{"type": "capability_verified", "refs": [capability], "expected": {"actions": ["read"]}, "rationale": "Actual acquired input"}])
                return tool_reply([("queue", "publish_research", {"summary": "Queue a distinct question", "outcome": "progress", "proposed_records": [], "suggested_opportunities": [op]})])
            response = product_model(payload)
            for call in response["choices"][0]["message"].get("tool_calls", []):
                if call["function"]["name"] == "publish_research":
                    proposal = json.loads(call["function"]["arguments"])
                    proposal["suggested_opportunities"] = []
                    call["function"]["arguments"] = json.dumps(proposal)
            return response
        result, _, _, scored, _ = self.run_model("P2", queue_only)
        self.assertTrue(scored["passed"], scored)
        self.assertTrue(any(r["kind"] == "result" and r["data"]["submission_kind"] == "publish" and not r["data"]["accepted_refs"] for r in result["records"]))

    def test_stale_input_is_blocked_before_target_and_repeats_do_not_prove_new_paths(self):
        with application_fixture("P2") as fixture:
            for name, token in fixture["tokens"].items():
                os.environ["KARST_I0_"+name.upper()] = token
            launch = parse_launch(product_template(fixture["origin"], BRIEFING, mode="mock"))
            with ResearchStore(self.root/"direct") as store:
                host = research.Host(launch, store, credential_values(launch.transport))
                identity = ref(host.identity_by_label["bob"])
                def request(key, path):
                    args = {"url": fixture["origin"]+path, "identity_ref": identity, "query": []}
                    return host.execute(ToolCall(key, "http_request", args, json.dumps(args)))
                initial = request("first", fixture["detail"])
                capability = store.resolve(initial["capability_ref"], host.run_id)
                store.update(capability, status="stale", invalidated_reason="test changed input")
                before = len(fixture["receipts"])
                blocked = request("blocked", fixture["followup"])
                self.assertIn("error", blocked)
                self.assertEqual(len(fixture["receipts"]), before)
                refreshed = request("refresh-input", fixture["detail"])
                self.assertNotEqual(refreshed["capability_ref"]["id"], capability["id"])
                follow = request("follow", fixture["followup"])
                self.assertFalse(follow.get("error"))
                self.assertEqual(len(store.records(host.run_id, "path_edge")), 1)
                again = request("repeat", fixture["followup"])
                self.assertEqual(len(store.records(host.run_id, "path_edge")), 1)
                self.assertIsNone(store.resolve(again["operation_ref"], host.run_id)["data"]["parent_operation_ref"])

    def test_hypothesis_or_contradicted_observation_cannot_become_proof(self):
        result, _, _, _, _ = self.run_model()
        with ResearchStore(self.root/"data") as store:
            observation = store.records(result["run_id"], "observation")[0]
            hypothesis = store.put("hypothesis", result["run_id"], {"question": "A guess", "basis_refs": observation["data"]["evidence_refs"], "alternative_explanations": [], "missing_conditions": [], "status": "open"})
            with self.assertRaises(KarstError):
                product.evidence_sources(store, result["run_id"], [ref(hypothesis)])
            store.put("observation", result["run_id"], dict(observation["data"], statement="Counterevidence", contradicts_refs=[ref(observation)]))
            with self.assertRaisesRegex(KarstError, "contradicted_observation"):
                product.evidence_sources(store, result["run_id"], [ref(observation)])

    def test_missing_material_and_changed_claim_remove_current_finding(self):
        result, _, _, scored, _ = self.run_model()
        self.assertTrue(scored["passed"])
        with ResearchStore(self.root/"data") as store:
            candidate = store.records(result["run_id"], "candidate")[0]
            store.update(candidate, claim_revision=2)
            self.assertFalse(store.status(result["run_id"])["findings"])
            candidate = store.get(candidate["id"])
            store.update(candidate, claim_revision=1)
            self.assertTrue(store.status(result["run_id"])["findings"])
        reference = result["findings"][0]["evidence_refs"][0]
        (self.root/"data/evidence"/(reference["id"]+".json")).write_bytes(b"tampered")
        self.assertFalse(research.status(self.root/"data", result["run_id"])["findings"])

    def test_session_generation_invalidates_capabilities_and_findings(self):
        result, _, _, _, _ = self.run_model()
        with ResearchStore(self.root/"data") as store:
            capability = next(c for c in store.records(result["run_id"], "capability") if c["data"]["origin"] == "acquired")
            session = store.get(capability["data"]["session_ref"]["id"])
            store.update(session, generation=2, auth_status="expired")
            with self.assertRaises(KarstError):
                product.usable_capability(store, result["run_id"], ref(capability))
            self.assertFalse(store.status(result["run_id"])["findings"])
            self.assertTrue(any(r["kind"] == "capability" and r["data"]["status"] == "stale" for r in store.status(result["run_id"])["records"]))

    def test_fabricated_positive_review_cannot_override_legal_sharing(self):
        def incorrect(payload):
            reply = product_model(payload, false_candidate=True)
            context = json.loads(payload["messages"][1]["content"])
            for call in reply["choices"][0]["message"].get("tool_calls", []):
                if context["role"] == "verify" and call["function"]["name"] == "submit_result":
                    data = json.loads(call["function"]["arguments"])
                    data["proposed_records"][0]["data"]["verdict"] = "supported"
                    call["function"]["arguments"] = json.dumps(data)
            return reply
        result, _, _, scored, _ = self.run_model("P3", incorrect)
        self.assertFalse(result["findings"])
        self.assertFalse(scored["checks"]["all_tasks_delivered"])
        self.assertEqual(scored["candidate_states"], {"inconclusive": 1})

    def test_review_without_original_reads_or_with_wrong_revision_is_rejected(self):
        result, _, _, _, _ = self.run_model()
        with ResearchStore(self.root/"data") as store:
            run = store.get(result["run_id"])
            candidate = store.update(store.records(run["id"], "candidate")[0], state="verifying")
            task = next(t for t in store.records(run["id"], "task") if t["data"]["role"] == "verify")
            task = store.update(task, state="running", read_set=[ref(candidate) if r["kind"] == "candidate" else r for r in task["data"]["read_set"]])
            attempt = next(a for a in store.records(run["id"], "attempt") if a["data"]["task_ref"]["id"] == task["id"])
            payload = deepcopy(next(r["data"]["payload"] for r in store.records(run["id"], "result") if r["data"]["task_ref"]["id"] == task["id"]))
            data = payload["proposed_records"][0]["data"]
            data["candidate_ref"] = ref(candidate)
            original = store.audits(run["id"])
            with patch.object(store, "audits", return_value=[a for a in original if a.get("name") != "evidence_read"]):
                with self.assertRaisesRegex(KarstError, "review_must_read"):
                    product.accept_verification(store, run, task, attempt, payload, "final")
            data["candidate_claim_revision"] += 1
            with self.assertRaisesRegex(KarstError, "stale_or_unassigned"):
                product.accept_verification(store, run, task, attempt, payload, "final")

    def test_unknown_predicate_result_cannot_be_submitted_as_supported(self):
        result, _, _, _, _ = self.run_model()
        with ResearchStore(self.root/"data") as store:
            candidate = store.records(result["run_id"], "candidate")[0]
            verdict, reason = product.assessment(store, result["run_id"], candidate, candidate["data"]["supporting_refs"], "task_"+"0"*32)
            self.assertEqual(verdict, "inconclusive")
            self.assertTrue(reason)

    def test_review_capacity_is_reserved_and_candidate_states_cannot_be_forged(self):
        result, _, _, _, _ = self.run_model()
        with ResearchStore(self.root/"data") as store:
            run = store.get(result["run_id"])
            task = next(t for t in store.records(run["id"], "task") if t["data"]["role"] == "research")
            data = deepcopy(store.records(run["id"], "candidate")[0]["data"])
            for key in ("claim_revision", "state"):
                data.pop(key)
            data["affected_refs"] = [r for r in data["affected_refs"] if r["kind"] == "asset"]+[ref(next(i for i in store.records(run["id"], "identity") if i["data"]["label"] == "alice"))]
            limited = deepcopy(run)
            limited["data"]["spec"]["budget"]["model_requests"] = 1
            with self.assertRaisesRegex(KarstError, "reserved_verification_budget"):
                product.prepare(store, limited, task, "candidate", data)
            data["state"] = "supported"
            with self.assertRaises(KarstError):
                product.prepare(store, run, task, "candidate", data)

    def test_roles_stale_claim_and_fabricated_verdict_are_rejected(self):
        result, _, _, _, _ = self.run_model()
        with ResearchStore(self.root/"data") as store:
            run = store.get(result["run_id"])
            candidate = store.records(run["id"], "candidate")[0]
            with self.assertRaisesRegex(KarstError, "ownership"):
                store.put("candidate", run["id"], candidate["data"], record_id="candidate_wrong_"+"0"*32)
            task = next(t for t in store.records(result["run_id"], "task") if t["data"]["role"] == "verify")
            attempt = next(a for a in store.records(result["run_id"], "attempt") if a["data"]["task_ref"]["id"] == task["id"])
            payload = deepcopy(next(r["data"]["payload"] for r in store.records(result["run_id"], "result") if r["data"]["task_ref"]["id"] == task["id"]))
            with self.assertRaises(KarstError):
                product.accept_verification(store, run, task, attempt, payload, "final")
            with self.assertRaises(KarstError):
                product.prepare(store, run, task, "security_rule", {})
            with self.assertRaises(KarstError):
                product.accept_verification(store, run, task, attempt, payload, "publish")

    def test_legacy_profile_cannot_enable_product_objectives(self):
        launch = research_template("http://127.0.0.1:1", "normal")
        launch["spec"]["objectives"]["discover_security_issues"] = True
        with self.assertRaises(KarstError):
            parse_launch(launch)
        profile = parse_launch(product_template("http://127.0.0.1:1", "product"))
        self.assertTrue(profile.product)
        self.assertEqual(profile.spec["budget"]["model_requests"], 72)


if __name__ == "__main__":
    unittest.main()
