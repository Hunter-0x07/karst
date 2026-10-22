"""Real local I/O regressions for the failures exposed by RESEARCH-T002."""

from copy import deepcopy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT/"src"), str(ROOT/"scripts")]
from karst import research
from karst.config import KarstError
from karst.errors import ProtocolError
from karst.gateway import Gateway, default_gateway_path, load_gateway
from karst.research_config import parse_launch, research_template
from karst.research_fixture import BRIEFING, application_fixture, score
from karst.research_store import ResearchStore
from run_i0_batch import batch
from tests.frontier_support import frontier_model, opportunity
from tests.i0_support import model_server, observation, tool_reply


def extended_model(payload):
    """Four tasks, denied controls and a task reading previous-task evidence."""
    context = json.loads(payload["messages"][1]["content"])
    replies = {m["tool_call_id"]: json.loads(m["content"]) for m in payload["messages"] if m["role"] == "tool"}
    if context["briefing"] == "Review saved alice evidence":
        previous = next(r for r in context["read_set"] if r["kind"] == "observation")
        evidence = previous["data"]["evidence_refs"]
        if "saved" not in replies:
            return tool_reply([("saved", "evidence_read", {"evidence_ref": evidence[0], "offset": 0, "length": 8192})])
        return tool_reply([("final", "submit_result", observation("Saved details reviewed; no additional question", evidence))])
    targets = [r for r in context["read_set"] if r["kind"] == "asset" and r["data"]["asset_type"] == "web_resource"]
    if targets:
        identities = {i["label"]: i["identity_ref"] for i in context["identities"]}
        name = next(n for n in identities if n in context["briefing"].lower())
        if "anonymous-control" not in replies:
            return tool_reply([("anonymous-control", "http_request", {
                "url": targets[0]["data"]["locator"]["url"], "identity_ref": None, "query": []})])
        if "read" in replies and "other-control" not in replies:
            detail = json.loads(replies["read"]["preview"]["body_text"])["detail"]
            other = next(n for n in identities if n != name)
            return tool_reply([("other-control", "http_request", {
                "url": context["entrypoints"][0].rstrip("/")+detail, "identity_ref": identities[other], "query": []})])
    reply = frontier_model(payload)
    if "Inspect alice" in context["briefing"]:
        for call in reply["choices"][0]["message"].get("tool_calls", []):
            if call["function"]["name"] == "submit_result":
                proposal = json.loads(call["function"]["arguments"])
                proposal["suggested_opportunities"] = [opportunity(
                    "Review saved alice evidence", {k: targets[0][k] for k in ("kind", "id", "version")},
                    [{"local_ref": "obs"}], prerequisites=[{"type": "task_delivered", "refs": [context["task_ref"]],
                    "expected": {"state": "delivered"}, "rationale": "Review the completed evidence"}])]
                call["function"]["arguments"] = json.dumps(proposal)
    return reply


class ResearchAcceptanceTests(unittest.TestCase):
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

    def run_model(self, responder, name="data"):
        with application_fixture() as fixture, model_server(responder) as (config, requests):
            for user, data in fixture["users"].items():
                os.environ["KARST_I0_"+user.upper()] = data["token"]
            result = research.run(self.save(name+"-launch.json", research_template(fixture["origin"], BRIEFING, mode="mock")),
                                  self.save(name+"-gateway.json", config), self.root/name, allow_mock=True)
        research.export(self.root/name, result["run_id"], self.root/(name+"-export"))
        return result, fixture, requests

    def test_variable_tasks_denied_controls_and_cross_task_evidence(self):
        result, fixture, requests = self.run_model(extended_model)
        with ResearchStore(self.root/"data", readonly=True) as store:
            scored = score(store, result["run_id"], fixture, offline_read_passed=True)
        self.assertTrue(scored["passed"], {k: v for k, v in scored["checks"].items() if not v})
        self.assertEqual(scored["tasks"], 4)
        self.assertEqual(scored["model_requests"], 17)
        self.assertEqual(scored["target_requests"], 9)
        self.assertEqual(sum(r["status"] == 403 for r in fixture["receipts"]), 4)
        self.assertGreater(scored["model_requests"], result["run"]["spec"]["scheduling"]["per_task_budget"]["model_requests"])
        starts = [json.loads(r["messages"][1]["content"]) for r in requests if len(r["messages"]) == 2]
        self.assertEqual(len(starts), 4)
        self.assertEqual([len(c["research_history"]["recent_tasks"]) for c in starts], [0, 1, 2, 3])
        self.assertTrue(all(c["run_briefing"] == BRIEFING for c in starts))

    def test_scorer_rejects_broken_lifecycle_budget_and_session_evidence(self):
        result, fixture, _ = self.run_model(extended_model)
        cases = {"run_budget": "within_budgets", "task_budget": "within_budgets",
                 "failed_task": "all_dispatched_tasks_delivered", "duplicate_final": "one_final_per_task",
                 "duplicate_context": "method_in_each_context", "stale_session": "fresh_task_sessions",
                 "wrong_method": "method_in_each_context", "balanced_wrong_accounting": "attempt_usage_sums_to_run",
                 "missing_accounting": "attempt_usage_sums_to_run", "budget_stop": "run_finished_without_failure"}
        with ResearchStore(self.root/"data", readonly=True) as store:
            original = store.status(result["run_id"])
            for case, failed_check in cases.items():
                with self.subTest(case=case):
                    value = deepcopy(original)
                    tasks = [r for r in value["records"] if r["kind"] == "task"]
                    attempts = [r for r in value["records"] if r["kind"] == "attempt"]
                    if case == "run_budget":
                        value["run"]["spec"]["budget"]["model_requests"] = 16
                    elif case == "task_budget":
                        tasks[1]["data"]["allocated_budget"]["model_requests"] = 1
                    elif case == "failed_task":
                        tasks[-1]["data"]["state"] = "failed"
                    elif case == "duplicate_final":
                        duplicate = deepcopy(next(r for r in value["records"] if r["kind"] == "result" and r["data"]["submission_kind"] == "final"))
                        duplicate["id"] = "result_"+"f"*32
                        value["records"].append(duplicate)
                    elif case == "duplicate_context":
                        value["audit"].append(deepcopy(next(a for a in value["audit"] if a["kind"] == "context")))
                    elif case == "stale_session":
                        start = next(a for a in value["audit"] if a["kind"] == "model_start" and len(a["messages"]) == 2)
                        start["messages"].append({"role": "user", "content": "old conversation"})
                    elif case == "missing_accounting":
                        attempts[0]["data"]["usage"]["charged_or_reserved"]["model_requests"] -= 1
                    elif case == "balanced_wrong_accounting":
                        attempts[0]["data"]["usage"]["charged_or_reserved"]["model_requests"] += 1
                        attempts[1]["data"]["usage"]["charged_or_reserved"]["model_requests"] -= 1
                    elif case == "wrong_method":
                        next(a for a in value["audit"] if a["kind"] == "context")["method"]["sha256"] = "0"*64
                    else:
                        value["run"]["stop_reason"]["code"] = "budget_exhausted"
                    with patch.object(store, "status", return_value=value):
                        scored = score(store, result["run_id"], fixture, offline_read_passed=True)
                    self.assertFalse(scored["passed"])
                    self.assertFalse(scored["checks"][failed_check])
            denied = deepcopy(fixture)
            next(r for r in denied["receipts"] if r["status"] == 403)["status"] = 200
            scored = score(store, result["run_id"], denied, offline_read_passed=True)
            self.assertFalse(scored["checks"]["requests_respect_scope_and_identity"])
            self.assertFalse(scored["checks"]["target_receipts_match_evidence"])

    def test_repeated_identical_request_is_not_hidden_by_allowed_controls(self):
        def responder(payload):
            context = json.loads(payload["messages"][1]["content"])
            replies = {m["tool_call_id"]: json.loads(m["content"]) for m in payload["messages"] if m["role"] == "tool"}
            if not context["research_history"]["recent_tasks"] and "read" in replies and "repeat" not in replies:
                return tool_reply([("repeat", "http_request", {"url": context["entrypoints"][0], "identity_ref": None, "query": []})])
            return frontier_model(payload)
        result, fixture, _ = self.run_model(responder)
        with ResearchStore(self.root/"data", readonly=True) as store:
            scored = score(store, result["run_id"], fixture, offline_read_passed=True)
        self.assertEqual({k for k, v in scored["checks"].items() if not v}, {"no_unexplained_repeated_actions"})

    def test_truncation_recovers_without_executing_partial_calls_and_fails_boundedly(self):
        for always in (False, True):
            calls = []
            def responder(payload):
                calls.append(payload)
                if always or len(calls) == 1:
                    return tool_reply([("partial", "http_request", {"url": "must-never-execute"})], finish="length")
                return frontier_model(payload)
            name = "truncated-"+str(always)
            result, fixture, requests = self.run_model(responder, name)
            with ResearchStore(self.root/name, readonly=True) as store:
                scored = score(store, result["run_id"], fixture, offline_read_passed=True)
            self.assertFalse(any(a["kind"] == "tool_start" and a["call_id"] == "partial" for a in result["audit"]))
            self.assertIn("one small complete call", requests[1]["messages"][-1]["content"])
            self.assertFalse(result["usage"]["unsettled"])
            if always:
                self.assertFalse(scored["passed"])
                self.assertEqual(len(requests), 3)
                self.assertEqual(fixture["receipts"], [])
                self.assertEqual(scored["task_states"], {"failed": 1})
                self.assertEqual(scored["model_error_codes"], {"TRUNCATED_TOOL_CALLS": 3})
                self.assertTrue(all(r["data"]["wait_reason"] == "correction_limit" for r in result["records"] if r["kind"] == "opportunity"))
            else:
                self.assertTrue(scored["passed"], scored["checks"])
                self.assertEqual(scored["model_requests"], 12)
                self.assertEqual(scored["target_requests"], 5)

    def test_gateway_accounts_invalid_content_and_uses_remaining_output(self):
        with ResearchStore(self.root/"gateway") as store:
            h = research.Host(parse_launch(research_template("http://127.0.0.1:1", "Gateway test", mode="mock")), store, {})
            for index, finish in enumerate(("length", "invalid")):
                def responder(payload):
                    return tool_reply(content="partial", finish=finish)
                with model_server(responder) as (config, _):
                    gateway = Gateway(config, store, h.run_id, h.budget, h.deadline, check=h.guard)
                    with self.assertRaises(ProtocolError):
                        gateway.generate([{"role": "user", "content": "test"}])
                self.assertEqual(store.usage(h.run_id)["charged_or_reserved"]["output_tokens"], (index+1)*50)
                self.assertFalse(store.usage(h.run_id)["unsettled"])
            with model_server(lambda payload: tool_reply(content="done")) as (config, requests):
                config["max_tokens"] = 16384
                h.budget["output_tokens"] = 170
                gateway = Gateway(config, store, h.run_id, h.budget, h.deadline, check=h.guard)
                gateway.generate([{"role": "user", "content": "test"}])
                self.assertEqual(requests[0]["max_tokens"], 70)

    def test_gateway_retry_respects_reduced_remaining_output(self):
        with ResearchStore(self.root/"retry") as store:
            h = research.Host(parse_launch(research_template("http://127.0.0.1:1", "Retry", mode="mock")), store, {})
            def responder(payload):
                return (503, {}) if len(requests) == 1 else tool_reply(content="done")
            with model_server(responder) as (config, requests):
                config["max_tokens"] = 16384
                h.budget["output_tokens"] = 17000
                gateway = Gateway(config, store, h.run_id, h.budget, h.deadline, check=h.guard)
                gateway.generate([{"role": "user", "content": "test"}])
            self.assertEqual([r["max_tokens"] for r in requests], [16384, 616])
            self.assertEqual(store.usage(h.run_id)["charged_or_reserved"]["output_tokens"], 16434)
            self.assertEqual(len(store.usage(h.run_id)["unsettled"]), 1)

    def test_gateway_pacing_covers_retry_and_adapter_recreation(self):
        import time
        with ResearchStore(self.root/"pace") as store:
            h = research.Host(parse_launch(research_template("http://127.0.0.1:1", "Pacing", mode="mock")), store, {})
            received = []
            def responder(payload):
                received.append(time.monotonic())
                return (429, {}) if len(received) == 1 else tool_reply(content="done")
            with model_server(responder) as (config, requests):
                config["min_request_interval_seconds"] = 1
                Gateway(config, store, h.run_id, h.budget, h.deadline, check=h.guard).generate([{"role": "user", "content": "test"}])
                Gateway(config, store, h.run_id, h.budget, h.deadline, check=h.guard).generate([{"role": "user", "content": "test"}])
            self.assertEqual(len(requests), 3)
            self.assertTrue(all(b-a >= 1 for a, b in zip(received, received[1:])), received)
            self.assertEqual(store.usage(h.run_id)["charged_or_reserved"]["model_requests"], 3)
            self.assertEqual(len(store.usage(h.run_id)["unsettled"]), 1)

    def test_pacing_deadline_and_cancellation_do_not_start_or_charge_requests(self):
        import time
        with ResearchStore(self.root/"pace-deadline") as store:
            h = research.Host(parse_launch(research_template("http://127.0.0.1:1", "Pacing deadline", mode="mock")), store, {})
            with model_server(lambda p: tool_reply(content="unused")) as (config, requests):
                config["min_request_interval_seconds"] = 1
                key = (config["api_base"], config["model"])
                Gateway._last_response_at[key] = time.monotonic()
                gateway = Gateway(config, store, h.run_id, h.budget, time.monotonic()+0.1, check=h.guard)
                with self.assertRaisesRegex(KarstError, "budget_exhausted"):
                    gateway.generate([{"role": "user", "content": "test"}])
                count = 0
                def cancel():
                    nonlocal count
                    count += 1
                    if count == 3:
                        raise KeyboardInterrupt()
                gateway = Gateway(config, store, h.run_id, h.budget, h.deadline, check=cancel)
                with self.assertRaises(KeyboardInterrupt):
                    gateway.generate([{"role": "user", "content": "test"}])
            self.assertEqual(requests, [])
            self.assertEqual(store.usage(h.run_id)["charged_or_reserved"], {})
            self.assertFalse(any(a["kind"] == "model_start" for a in store.audits(h.run_id)))

    def test_pacing_config_is_explicit_bounded_and_optional_for_old_profiles(self):
        config = load_gateway(ROOT/default_gateway_path())
        self.assertEqual(config["min_request_interval_seconds"], 0)
        self.assertEqual(load_gateway(ROOT/default_gateway_path(research=True))["min_request_interval_seconds"], 15)
        for value in (-1, 61, True, 0.5, "15"):
            with self.subTest(value=value):
                config["min_request_interval_seconds"] = value
                with self.assertRaises(KarstError):
                    load_gateway(self.save("invalid-pace.json", config))

    def test_scorer_exception_is_retained_for_all_three_resets(self):
        with model_server(frontier_model) as (config, _), patch("karst.research_fixture.score", side_effect=KeyError("statement")):
            summary = batch(self.save("gateway.json", config), self.root/"batch", mock=True, stage="research")
        self.assertFalse(summary["technical_pass"])
        self.assertEqual(len(summary["runs"]), 3)
        self.assertTrue(all(r["failed_stage"] == "scoring" and r["error"] == "KeyError" for r in summary["runs"]))
        self.assertTrue(all((self.root/"batch"/("reset-"+str(i))/"failure-traceback.txt").is_file() for i in (1, 2, 3)))

    def test_research_output_default_preserves_i0_configuration(self):
        self.assertEqual(load_gateway(ROOT/default_gateway_path())["max_tokens"], 4096)
        self.assertEqual(load_gateway(ROOT/default_gateway_path(research=True))["max_tokens"], 16384)
