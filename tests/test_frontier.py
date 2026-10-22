"""Research proposal, scheduling, isolation and actual multi-task HTTP regressions."""

from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/"src"))
from karst import frontier, research
from karst.config import KarstError
from karst.protocol import ToolCall, ModelRequest, validate_request
from karst.research_config import parse_launch, research_template, template
from karst.research_fixture import BRIEFING, application_fixture, score
from karst.research_store import ResearchStore, ref
from tests.frontier_support import frontier_model, opportunity
from tests.i0_support import model_server, observation, tool_reply


class FrontierTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.env = patch.dict(os.environ, {"KARST_I0_ALICE": "alice-token", "KARST_I0_BOB": "bob-token"})
        self.env.start()
        self.addCleanup(self.env.stop)

    def save(self, name, value):
        path = self.root/name
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def host(self, origin):
        store = ResearchStore(self.root/"data")
        self.addCleanup(store.db.close)
        return research.Host(parse_launch(research_template(origin, BRIEFING, mode="mock")), store,
                             {"alice": "alice-token", "bob": "bob-token"})

    def call(self, name, arguments, cid):
        return ToolCall(cid, name, arguments, json.dumps(arguments))

    def entry(self, h, origin):
        reply = h.execute(self.call("http_request", {"url": origin+"/", "identity_ref": None, "query": []}, "entry"))
        return reply["evidence_refs"]

    def publish(self, h, payload, cid="publish", final=False):
        return h.execute(self.call("submit_result" if final else "publish_research", payload, cid))

    def test_multi_task_http_fresh_sessions_offline_export_and_accounting(self):
        with application_fixture() as fixture, model_server(frontier_model) as (gateway, requests):
            for name, values in fixture["users"].items():
                os.environ["KARST_I0_"+name.upper()] = values["token"]
            result = research.run(self.save("launch.json", research_template(fixture["origin"], BRIEFING, mode="mock")),
                                  self.save("gateway.json", gateway), self.root/"data", allow_mock=True)
        exported = research.export(self.root/"data", result["run_id"], self.root/"export")
        with ResearchStore(self.root/"data", readonly=True) as store:
            scored = score(store, result["run_id"], fixture, offline_read_passed=Path(exported["output"], "run.json").is_file())
        self.assertTrue(scored["passed"], {k: v for k, v in scored["checks"].items() if not v})
        self.assertEqual(scored["model_requests"], 11)
        self.assertEqual(scored["target_requests"], 5)
        self.assertEqual(len(result["receipts"]), 4)
        self.assertEqual(len({r["request_id"] for r in result["receipts"]}), 4)
        for payload in requests:
            validate_request(ModelRequest(payload["messages"]))
        self.assertEqual(sum(len(p["messages"]) == 2 for p in requests), 3)
        self.assertTrue(all(r["data"]["status"] == "open" for r in result["records"] if r["kind"] == "hypothesis"))
        records = {r["id"]: r for r in result["records"]}
        finals = [r for r in records.values() if r["kind"] == "result" and r["data"]["submission_kind"] == "final"]
        self.assertTrue(any({records[r["id"]]["kind"] for r in f["data"]["accepted_refs"]}
                            == {"observation", "asset", "hypothesis"} for f in finals))
        child = subprocess.run([sys.executable, str(ROOT/"scripts/karst.py"), "status", "--data-dir", str(self.root/"data"),
                                "--run-id", result["run_id"]], capture_output=True, timeout=10)
        self.assertEqual(child.returncode, 0, child.stderr)

    def test_mixed_finals_do_not_credit_hypotheses_or_wrong_evidence(self):
        for case in ("hypothesis_only", "wrong_evidence", "missing_facts"):
            with self.subTest(case=case):
                def responder(payload):
                    reply = frontier_model(payload)
                    context = json.loads(payload["messages"][1]["content"])
                    if "Inspect alice" not in context["briefing"]:
                        return reply
                    for call in reply["choices"][0]["message"].get("tool_calls", []):
                        if call["function"]["name"] != "submit_result":
                            continue
                        proposed = json.loads(call["function"]["arguments"])
                        record = proposed["proposed_records"][0]
                        if case == "hypothesis_only":
                            record["kind"] = "hypothesis"
                            record["data"] = {"question": record["data"]["statement"],
                                              "basis_refs": record["data"]["evidence_refs"],
                                              "alternative_explanations": ["Unverified interpretation"],
                                              "missing_conditions": ["Confirmed facts"]}
                        elif case == "wrong_evidence":
                            replies = {m["tool_call_id"]: json.loads(m["content"]) for m in payload["messages"] if m["role"] == "tool"}
                            record["data"]["evidence_refs"] = replies["read"]["evidence_refs"]
                        else:
                            record["data"]["statement"] = "Order details remain incomplete"
                        call["function"]["arguments"] = json.dumps(proposed)
                    return reply

                with application_fixture() as fixture, model_server(responder) as (gateway, _):
                    for name, values in fixture["users"].items():
                        os.environ["KARST_I0_"+name.upper()] = values["token"]
                    result = research.run(self.save(case+"-launch.json", research_template(fixture["origin"], BRIEFING, mode="mock")),
                                          self.save(case+"-gateway.json", gateway), self.root/case, allow_mock=True)
                exported = research.export(self.root/case, result["run_id"], self.root/(case+"-export"))
                with ResearchStore(self.root/case, readonly=True) as store:
                    scored = score(store, result["run_id"], fixture, offline_read_passed=Path(exported["output"], "run.json").is_file())
                self.assertFalse(scored["passed"])
                self.assertEqual({k for k, v in scored["checks"].items() if not v},
                                 {"final_facts_link_to_correct_evidence", "separate_owner_fact_tasks"})
                self.assertEqual(scored["model_requests"], 11)
                self.assertEqual(scored["target_requests"], 5)

    def test_local_references_atomic_rollback_and_state_permissions(self):
        with application_fixture() as fixture:
            h = self.host(fixture["origin"])
            evidence = self.entry(h, fixture["origin"])
            payload = observation("Observed entry", evidence)
            payload["proposed_records"].insert(0, {"local_ref": "hyp", "kind": "hypothesis", "data": {
                "question": "Unknown ownership?", "basis_refs": [{"local_ref": "obs"}],
                "alternative_explanations": ["Shared resource"], "missing_conditions": ["Sharing rule"]}})
            receipt = self.publish(h, payload)
            self.assertEqual(receipt["status"], "accepted", receipt)
            hypothesis = h.store.resolve(receipt["local_ref_map"]["hyp"], h.run_id)
            self.assertEqual(hypothesis["data"]["basis_refs"], [receipt["local_ref_map"]["obs"]])
            before = len(h.store.records(h.run_id))
            for index, mutation in enumerate(("cycle", "forged_status", "forged_evidence", "unsupported_condition")):
                bad = deepcopy(payload)
                if mutation == "cycle":
                    bad["proposed_records"][0]["data"]["basis_refs"] = [{"local_ref": "hyp"}]
                elif mutation == "forged_status":
                    bad["proposed_records"][0]["data"]["status"] = "supported"
                elif mutation == "forged_evidence":
                    bad["proposed_records"][1]["data"]["evidence_refs"] = [{"local_ref": "hyp"}]
                else:
                    asset = h.store.records(h.run_id, "asset")[0]
                    bad["suggested_opportunities"] = [opportunity("Later", ref(asset), evidence, prerequisites=[
                        {"type": "capability_verified", "refs": evidence, "expected": {}, "rationale": "Not implemented"}])]
                rejected = self.publish(h, bad, "bad-"+str(index))
                self.assertEqual(rejected["status"], "rejected", (mutation, rejected))
                self.assertEqual(len(h.store.records(h.run_id)), before)

    def test_dedup_waiting_and_delivery_recheck(self):
        with application_fixture() as fixture:
            h = self.host(fixture["origin"])
            evidence = self.entry(h, fixture["origin"])
            asset = h.store.records(h.run_id, "asset")[0]
            p = observation("Entry", evidence)
            p["suggested_opportunities"] = [opportunity("New research question", ref(asset), evidence, prerequisites=[
                {"type": "task_delivered", "refs": [ref(h.store.get(h.task_id))],
                 "expected": {"state": "delivered"}, "rationale": "Wait for initial delivery"}])]
            first = self.publish(h, p)
            self.assertEqual(first["status"], "accepted")
            self.assertEqual(self.publish(h, p), first)  # tool-call idempotent replay
            self.assertEqual(self.publish(h, p, "publish-again")["status"], "accepted")
            self.assertEqual(len(h.store.records(h.run_id, "opportunity")), 2)
            self.assertIsNone(frontier.select(h))
            self.assertEqual(h.store.records(h.run_id, "opportunity")[1]["data"]["state"], "waiting")
            self.assertEqual(self.publish(h, observation("Done", evidence), "final", final=True)["status"], "accepted")
            self.assertTrue(h.next_task())
            self.assertEqual(h.store.records(h.run_id, "opportunity")[1]["data"]["state"], "running")
            self.assertEqual(len(h.messages()), 2)
            self.assertEqual(h.messages()[0]["content"], frontier.SYSTEM)

    def test_source_tamper_blocks_dispatch_and_active_execution(self):
        with application_fixture() as fixture:
            h = self.host(fixture["origin"])
            evidence = self.entry(h, fixture["origin"])
            asset = h.store.records(h.run_id, "asset")[0]
            p = observation("Entry", evidence)
            p["suggested_opportunities"] = [opportunity("New question", ref(asset), evidence)]
            self.assertEqual(self.publish(h, p, "final", final=True)["status"], "accepted")
            self.assertTrue(h.next_task())
            evidence_path = h.store.root/"evidence"/(evidence[0]["id"]+".json")
            original = evidence_path.read_bytes()
            evidence_path.write_bytes(b"tampered")
            with self.assertRaisesRegex(KarstError, "evidence_integrity_failed"):
                h.execute(self.call("http_request", {"url": fixture["origin"]+"/", "identity_ref": None, "query": []}, "read"))
            self.assertEqual(len(fixture["receipts"]), 1)
            evidence_path.write_bytes(original)
            h.guard()

    def test_aging_rotates_lane_and_capacity_is_bounded(self):
        with application_fixture() as fixture:
            h = self.host(fixture["origin"])
            evidence = self.entry(h, fixture["origin"])
            asset = ref(h.store.records(h.run_id, "asset")[0])
            schedule = h.launch.spec["scheduling"]
            schedule.update(max_same_lane=1, aging_rounds=1, max_ready=1)
            old = frontier.propose(h.store, h.run_id, opportunity("Older deepen", asset, evidence, lane="deepen"))
            h.store.audit(h.run_id, "dispatch", {"task_ref": ref(h.store.get(h.task_id)),
                          "opportunity_ref": h.store.get(h.task_id)["data"]["opportunity_ref"], "lane": "expand", "round": 2})
            p = opportunity("High priority expand", asset, evidence, lane="expand")
            p["priority"] = "high"
            frontier.propose(h.store, h.run_id, p)
            self.assertEqual(frontier.select(h)["id"], old["id"])
            self.assertEqual(sum(o["data"]["state"] == "ready" for o in h.store.records(h.run_id, "opportunity")), 1)
            self.assertEqual(sum(o["data"]["state"] == "deferred" for o in h.store.records(h.run_id, "opportunity")), 1)

    def test_run_budget_is_not_reset_at_task_switch(self):
        with application_fixture() as fixture, model_server(frontier_model) as (gateway, requests):
            for name, values in fixture["users"].items():
                os.environ["KARST_I0_"+name.upper()] = values["token"]
            launch = research_template(fixture["origin"], BRIEFING, mode="mock")
            launch["spec"]["budget"]["model_requests"] = 7
            launch["spec"]["scheduling"]["per_task_budget"]["model_requests"] = 7
            result = research.run(self.save("launch.json", launch), self.save("gateway.json", gateway),
                                  self.root/"data", allow_mock=True)
        self.assertEqual(len(requests), 7)
        self.assertEqual(result["usage"]["charged_or_reserved"]["model_requests"], 7)
        self.assertEqual(result["run"]["stop_reason"]["code"], "budget_exhausted")
        self.assertTrue(result["run"]["stop_reason"]["blocking_refs"])
        self.assertFalse(any(o["data"]["state"] == "running" for o in result["records"] if o["kind"] == "opportunity"))

    def test_local_correction_failure_continues_other_opportunity(self):
        def responder(payload):
            context = json.loads(payload["messages"][1]["content"])
            if "Inspect alice" in context["briefing"]:
                return tool_reply(content="incomplete")
            return frontier_model(payload)
        with application_fixture() as fixture, model_server(responder) as (gateway, requests):
            for name, values in fixture["users"].items():
                os.environ["KARST_I0_"+name.upper()] = values["token"]
            result = research.run(self.save("launch.json", research_template(fixture["origin"], BRIEFING, mode="mock")),
                                  self.save("gateway.json", gateway), self.root/"data", allow_mock=True)
        tasks = [r for r in result["records"] if r["kind"] == "task"]
        self.assertEqual(len(tasks), 3)
        self.assertEqual(sum(t["data"]["state"] == "delivered" for t in tasks), 2)
        self.assertEqual(sum(t["data"]["state"] == "failed" for t in tasks), 1)
        self.assertTrue(any("bob order=" in r["data"]["statement"] for r in result["records"] if r["kind"] == "observation"))
        self.assertEqual(result["findings"], [])

    def test_profile_limits_and_legacy_proposals_remain_separate(self):
        value = research_template("http://127.0.0.1:12345", "Research", mode="mock")
        self.assertTrue(parse_launch(value).research)
        for key, val in (("max_workers", 2), ("max_attempts_per_fingerprint", 2), ("max_ready", 0)):
            bad = deepcopy(value)
            bad["spec"]["scheduling"][key] = val
            with self.assertRaises(KarstError):
                parse_launch(bad)
        self.assertFalse(parse_launch(template("http://127.0.0.1:12345", "I0", mode="mock")).research)
        self.assertIn("experiments", frontier.method_pack()["guidance"])

    def test_contradictory_observation_blocks_dependent_opportunity(self):
        with application_fixture() as fixture:
            h = self.host(fixture["origin"])
            evidence = self.entry(h, fixture["origin"])
            receipt = self.publish(h, observation("Initial interpretation", evidence))
            original = receipt["local_ref_map"]["obs"]
            asset = ref(h.store.records(h.run_id, "asset")[0])
            frontier.propose(h.store, h.run_id, opportunity("Depends on initial interpretation", asset, [original]))
            contrary = observation("Different interpretation requires investigation", evidence)
            contrary["proposed_records"][0]["data"]["contradicts_refs"] = [original]
            self.assertEqual(self.publish(h, contrary, "contrary")["status"], "accepted")
            self.assertIsNone(frontier.select(h))
            pending = h.store.records(h.run_id, "opportunity")[1]
            self.assertEqual(pending["data"]["wait_reason"], "contradicted_observation")

    def test_unknown_execution_cannot_be_bypassed_as_local_correction_failure(self):
        real_loop = research.run_task
        turns = []
        def injected(h, gateway):
            turns.append(h.task_id)
            if len(turns) > 1:
                h.fatal = "unknown_execution_or_save_failure"
                raise KarstError("correction_limit")
            real_loop(h, gateway)
        with application_fixture() as fixture, model_server(frontier_model) as (gateway, requests), patch.object(research, "run_task", injected):
            for name, values in fixture["users"].items():
                os.environ["KARST_I0_"+name.upper()] = values["token"]
            result = research.run(self.save("launch.json", research_template(fixture["origin"], BRIEFING, mode="mock")),
                                  self.save("gateway.json", gateway), self.root/"data", allow_mock=True)
        self.assertEqual(len(turns), 2)
        self.assertEqual(result["run"]["state"], "failed")
        self.assertEqual(len(fixture["receipts"]), 1)

    def test_reconcile_closes_running_opportunity_without_target_io(self):
        with application_fixture() as fixture:
            h = self.host(fixture["origin"])
            self.entry(h, fixture["origin"])
            h.store.db.close()
            result = research.reconcile(self.root/"data", h.run_id)
            self.assertEqual(len(fixture["receipts"]), 1)
        self.assertEqual(result["run"]["state"], "stopped")
        self.assertTrue(all(o["data"]["state"] == "exhausted" for o in result["records"] if o["kind"] == "opportunity"))
