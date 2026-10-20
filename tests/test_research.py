"""I0 contract, actual loopback I/O, protocol and failure-path regression."""

import base64
from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/"src"))
from karst import research
from karst.config import KarstError
from karst.gateway import Gateway
from karst.i0_fixture import BRIEFING, application_fixture, score
from karst.protocol import ToolCall, parse_reply, ModelRequest, validate_request
from karst.errors import ProtocolError, RequestError, GatewayError
from karst.research_config import parse_launch, template
from karst.research_store import ResearchStore, ref
from karst.store import host_lock
from tests.i0_support import business_model, model_server, observation, tool_reply
from tests.support import server as legacy_server


class ResearchTests(unittest.TestCase):
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

    def host(self, origin="http://127.0.0.1:12345"):
        launch = parse_launch(template(origin, BRIEFING, mode="mock"))
        store = ResearchStore(self.root/"data")
        self.addCleanup(store.db.close)
        return research.Host(launch, store, {"alice": "alice-token", "bob": "bob-token"})

    def call(self, name, args, cid="call"):
        return ToolCall(cid, name, args, json.dumps(args))

    def evidence(self, host):
        # Program-created evidence for receiver contract tests, not capability evidence.
        op = host.bridge.put("operation", "operation_"+"a"*32, host.run_id,
            {"execution_state": "not_executed", "identity": "anonymous", "arguments_digest": "b"*64,
             "error": {"code": "fixture", "retry_policy": "never"}, "started_at": "2026-01-01T00:00:00Z",
             "ended_at": "2026-01-01T00:00:00Z", "evidence_refs": [], "response_bytes": 0, "http_status": None})
        op = host.store.get(op["id"])
        return host.store.save_evidence(host.run_id, op, {"response": {"status": 200, "body_base64": base64.b64encode(b'fixture material').decode()}}, partial=False)

    def envelope(self, host, payload, request_id="publish-one"):
        run, task, attempt = (host.store.get(i) for i in (host.run_id, host.task_id, host.attempt_id))
        return {"schema_version": "karst-design/1", "request_id": request_id, "run_ref": ref(run), "task_ref": ref(task),
                "attempt_ref": ref(attempt), "expected_versions": [ref(run), ref(task), ref(attempt)], "payload": payload}

    def test_three_resets_continuous_loop_offline_export_and_cli(self):
        resets = set()
        with model_server() as (gateway, requests):
            gateway_path = self.save("gateway.json", gateway)
            for index in range(3):
                with application_fixture() as fixture:
                    resets.add(fixture["reset_id"])
                    for name, values in fixture["users"].items():
                        os.environ["KARST_I0_"+name.upper()] = values["token"]
                    launch = template(fixture["origin"], BRIEFING, mode="mock")
                    config_path = self.save("launch.json", launch)
                    data_dir = self.root/("run-"+str(index))
                    result = research.run(config_path, gateway_path, data_dir, allow_mock=True)
                report = research.export(data_dir, result["run_id"], self.root/("export-"+str(index)))
                child = subprocess.run([sys.executable, str(ROOT/"scripts/karst.py"), "status", "--data-dir", str(data_dir), "--run-id", result["run_id"]], capture_output=True, timeout=10)
                self.assertEqual(child.returncode, 0, child.stderr)
                with ResearchStore(data_dir, readonly=True) as store:
                    scored = score(store, result["run_id"], fixture, offline_read_passed=Path(report["output"], "run.json").is_file())
                self.assertTrue(scored["passed"], (scored, result["run"]["stop_reason"]))
                self.assertFalse(scored["inference_tested"])
                self.assertEqual(scored["model_requests"], 9)
                self.assertEqual(scored["target_requests"], 5)
                self.assertEqual(scored["evidence_reads"], 2)
                self.assertEqual(result["run"]["state"], "stopped")
                self.assertNotIn("reasoning_content", json.dumps(result))
                # The checkpoint receipt is read in a later model turn, before
                # any Bob HTTP request, not just dispatched earlier in one batch.
                audit = result["audit"]
                published = next(a for a in audit if a["kind"] == "tool_end" and a.get("call_id") == "publish")
                bob = next(a for a in audit if a["kind"] == "tool_start" and a.get("call_id") == "catalog-bob")
                self.assertLess(published["sequence"], bob["sequence"])
                bob_request = next(p for p in requests if any(m.get("tool_call_id") == "publish" for m in p["messages"]))
                receipt = next(json.loads(m["content"]) for m in bob_request["messages"] if m.get("tool_call_id") == "publish")
                self.assertEqual(receipt["status"], "accepted")
                for payload in requests:
                    validate_request(ModelRequest(payload["messages"]))
            self.assertEqual(len(resets), 3)

    def test_late_publish_still_fails_with_complete_correct_final_evidence(self):
        with application_fixture() as fixture, model_server(lambda p: business_model(p, publish_late=True)) as (gateway, requests):
            for name, values in fixture["users"].items():
                os.environ["KARST_I0_"+name.upper()] = values["token"]
            data_dir = self.root/"late-publish"
            result = research.run(self.save("launch.json", template(fixture["origin"], BRIEFING, mode="mock")),
                                  self.save("gateway.json", gateway), data_dir, allow_mock=True)
        exported = research.export(data_dir, result["run_id"], self.root/"late-export")
        with ResearchStore(data_dir, readonly=True) as store:
            scored = score(store, result["run_id"], fixture, offline_read_passed=Path(exported["output"], "run.json").is_file())
        self.assertEqual([k for k, v in scored["checks"].items() if not v], ["publish_then_continue_http"])
        self.assertFalse(scored["passed"])
        self.assertEqual(scored["target_requests"], 5)
        self.assertEqual(result["run"]["state"], "stopped")

    def test_checkpoint_facts_do_not_replace_complete_final_evidence(self):
        # Reproduce I0-T002 reset-2 using ordinary tool messages. The Host may
        # accept a valid partial proposal, but the acceptance scorer must fail it.
        # Also ensure copying the correct text with Bob's evidence is insufficient.
        for failure in ("omit_published", "summary_only", "wrong_evidence"):
            with self.subTest(failure=failure):
                def responder(payload):
                    reply = business_model(payload)
                    call = reply["choices"][0]["message"].get("tool_calls", [])[0]
                    if call["function"]["name"] == "submit_result":
                        final = json.loads(call["function"]["arguments"])
                        alice, bob = final["proposed_records"]
                        if failure == "wrong_evidence":
                            alice["data"]["evidence_refs"] = deepcopy(bob["data"]["evidence_refs"])
                        else:
                            final["proposed_records"] = [bob]
                            if failure == "summary_only":
                                final["summary"] += " " + alice["data"]["statement"]
                        call["function"]["arguments"] = json.dumps(final)
                    return reply

                with application_fixture() as fixture, model_server(responder) as (gateway, requests):
                    for name, values in fixture["users"].items():
                        os.environ["KARST_I0_"+name.upper()] = values["token"]
                    data_dir = self.root/failure
                    result = research.run(
                        self.save("launch.json", template(fixture["origin"], BRIEFING, mode="mock")),
                        self.save("gateway.json", gateway), data_dir, allow_mock=True)
                exported = research.export(data_dir, result["run_id"], self.root/(failure+"-export"))
                with ResearchStore(data_dir, readonly=True) as store:
                    scored = score(store, result["run_id"], fixture,
                                   offline_read_passed=Path(exported["output"], "run.json").is_file())
                    checkpoint = next(r for r in store.records(result["run_id"], "result")
                                      if r["data"]["submission_kind"] == "publish")
                    published = store.get(checkpoint["data"]["accepted_refs"][0]["id"])
                    self.assertIn(fixture["users"]["alice"]["code"], published["data"]["statement"])
                self.assertEqual([k for k, v in scored["checks"].items() if not v],
                                 ["final_facts_link_to_correct_evidence"])
                self.assertFalse(scored["passed"])
                self.assertEqual(scored["target_requests"], 5)
                self.assertEqual(scored["model_requests"], 9)

    def test_publish_final_duplicate_conflict_and_atomic_rollback(self):
        h = self.host()
        er = ref(self.evidence(h))
        payload = observation("fixture observed", [er])
        env = self.envelope(h, payload)
        receipt = h.store.receive("publish", env, owner=h.owner, generation=1)
        self.assertEqual(h.store.get(h.task_id)["data"]["state"], "running")
        self.assertEqual(h.store.receive("publish", env, owner=h.owner, generation=1)["status"], "duplicate")
        conflict = deepcopy(env)
        conflict["payload"]["summary"] = "different"
        with self.assertRaisesRegex(KarstError, "IDEMPOTENCY_CONFLICT"):
            h.store.receive("publish", conflict, owner=h.owner, generation=1)
        final_env = self.envelope(h, payload, "final-one")
        final = h.store.receive("final", final_env, owner=h.owner, generation=1)
        duplicate = h.store.receive("final", final_env, owner=h.owner, generation=1)
        self.assertEqual(duplicate["state_version"], final["state_version"])
        self.assertEqual(h.store.get(h.task_id)["data"]["result_ref"], final["result_ref"])
        self.assertNotEqual(receipt["result_ref"], final["result_ref"])
        with self.assertRaises(KarstError):
            h.store.receive("final", self.envelope(h, payload, "late-final"), owner=h.owner, generation=1)

    def test_receiving_failure_rolls_back_records_and_receipt(self):
        h = self.host()
        er = ref(self.evidence(h))
        env = self.envelope(h, observation("fixture", [er]))
        count = len(h.store.records(h.run_id))
        original = h.store.put
        def fail(kind, *args, **kwargs):
            if kind == "result":
                raise KarstError("injected result failure")
            return original(kind, *args, **kwargs)
        with patch.object(h.store, "put", side_effect=fail), self.assertRaises(KarstError):
            h.store.receive("publish", env, owner=h.owner, generation=1)
        self.assertEqual(len(h.store.records(h.run_id)), count)
        self.assertEqual(h.store.db.execute("SELECT COUNT(*) FROM receipts").fetchone()[0], 0)

    def test_invalid_references_authority_and_stale_attempt_are_rejected(self):
        h = self.host()
        er = ref(self.evidence(h))
        payload = observation("fixture", [er])
        for change in ("foreign", "state", "kind", "generation", "version", "schema", "float"):
            env = self.envelope(h, deepcopy(payload), change)
            generation = 1
            if change == "foreign":
                env["payload"]["proposed_records"][0]["data"]["evidence_refs"][0]["id"] = "evidence_"+"0"*32
            elif change == "state":
                env["payload"]["proposed_records"][0]["data"]["state"] = "supported"
            elif change == "kind":
                env["payload"]["proposed_records"][0]["kind"] = "candidate"
            elif change == "generation":
                generation = 2
            elif change == "version":
                env["expected_versions"][0]["version"] = 1
            elif change == "schema":
                env["schema_version"] = "wrong"
            else:
                env["payload"]["extra"] = 1.2
            with self.subTest(change=change), self.assertRaises(KarstError):
                h.store.receive("publish", env, owner=h.owner, generation=generation)
        self.assertEqual(h.store.records(h.run_id, "observation"), [])

    def test_replay_http_and_evidence_reads_do_not_revisit_target(self):
        with application_fixture() as fixture:
            h = self.host(fixture["origin"])
            call = self.call("http_request", {"url": fixture["origin"]+"/", "identity_ref": None, "query": []})
            first = h.execute(call)
            self.assertEqual(first, h.execute(call))
            self.assertEqual(len(fixture["receipts"]), 1)
            read = h.execute(self.call("evidence_read", {"evidence_ref": first["evidence_refs"][0], "offset": 0, "length": 128}, "read"))
            self.assertEqual(read["target_requests"], 0)
            self.assertEqual(len(fixture["receipts"]), 1)
            call = self.call("http_request", {"url": fixture["origin"]+"/different", "identity_ref": None, "query": []})
            self.assertEqual(h.execute(call)["error"]["code"], "IDEMPOTENCY_CONFLICT")

    def test_grant_expiry_config_change_session_generation_and_scope(self):
        h = self.host()
        call = self.call("http_request", {"url": "http://127.0.0.1:9999/", "identity_ref": None, "query": []})
        self.assertEqual(h.execute(call)["error"]["code"], "scope_denied")
        session = next(iter(h.session_by_identity.values()))
        h.store.update(session, generation=2)
        denied = h.execute(self.call("http_request", {"url": "http://127.0.0.1:12345/", "identity_ref": session["data"]["identity_ref"], "query": []}, "stale"))
        self.assertEqual(denied["error"]["code"], "stale_session")
        h.context["grant"]["valid_until"] = "2000-01-01T00:00:00Z"
        with self.assertRaisesRegex(KarstError, "budget_exhausted"):
            h.guard()
        h.context["grant"]["valid_until"] = "2099-01-01T00:00:00Z"
        h.store.update(h.store.get(h.run_id), config_version=2)
        with self.assertRaisesRegex(KarstError, "changed configuration"):
            h.guard()

    def test_evidence_integrity_failure_stops_run(self):
        h = self.host()
        er = ref(self.evidence(h))
        (h.store.root/"evidence"/(er["id"]+".json")).write_bytes(b'changed')
        result = h.execute(self.call("evidence_read", {"evidence_ref": er, "offset": 0, "length": 10}))
        self.assertEqual(result["error"]["code"], "evidence_integrity_failed")
        self.assertEqual(h.fatal, "evidence_integrity_failed")
        self.assertEqual(h.store.status(h.run_id)["records"][-1]["data"]["availability"], "unavailable")

    def test_save_failure_keeps_execution_and_stops_further_requests(self):
        with application_fixture() as fixture:
            h = self.host(fixture["origin"])
            with patch.object(h.store, "save_evidence", side_effect=KarstError("evidence_save_failed")):
                reply = h.execute(self.call("http_request", {"url": fixture["origin"]+"/", "identity_ref": None, "query": []}))
            self.assertEqual(reply["execution_state"], "succeeded")
            self.assertEqual(reply["error"]["code"], "evidence_save_failed")
            self.assertEqual(len(fixture["receipts"]), 1)
            with self.assertRaises(KarstError):
                h.execute(self.call("session_inspect", {}, "later"))

    def test_model_protocol_rejects_invalid_truncated_duplicate_and_missing_results(self):
        valid = tool_reply([("x", "session_inspect", {})])
        cases = []
        for raw in ('{"x":1,"x":2}', '{', '{"x":NaN}'):
            bad = deepcopy(valid)
            bad["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"] = raw
            cases.append(bad)
        truncated = deepcopy(valid)
        truncated["choices"][0]["finish_reason"] = "length"
        cases.append(truncated)
        dup = deepcopy(valid)
        dup["choices"][0]["message"]["tool_calls"] *= 2
        cases.append(dup)
        for payload in cases:
            with self.assertRaises(ProtocolError):
                parse_reply(payload, request_id="test", model="fixture", attempts=1, elapsed_seconds=0)
        with self.assertRaises(RequestError):
            validate_request(ModelRequest([valid["choices"][0]["message"]]))

    def test_model_retries_and_unknown_usage_charge_real_requests(self):
        h = self.host()
        def responder(payload):
            return (503, {}) if len(requests) == 1 else tool_reply(content="ok", usage=False)
        with model_server(responder) as (config, requests):
            gateway = Gateway(config, h.store, h.run_id, h.budget, h.deadline, check=h.guard)
            reply = gateway.generate([{"role": "user", "content": "test"}])
            self.assertEqual(len(requests), 2)
            self.assertIsNone(reply.usage)
            usage = h.store.usage(h.run_id)
            self.assertEqual(usage["charged_or_reserved"]["model_requests"], 2)
            self.assertEqual(len(usage["unsettled"]), 2)
            h.budget["model_requests"] = 2
            with self.assertRaisesRegex(KarstError, "budget_exhausted"):
                gateway.generate([{"role": "user", "content": "test again"}])
            self.assertEqual(len(requests), 2)

    def test_unknown_tool_text_only_and_exclusive_submit_are_bounded(self):
        responses = [tool_reply([("bad", "not_a_tool", {})]),
                     tool_reply([("final", "submit_result", {}), ("other", "session_inspect", {})]),
                     tool_reply(content="done"), tool_reply(content="done")]
        with application_fixture() as fixture, model_server(lambda _: responses.pop(0)) as (gateway, requests):
            result = research.run(self.save("launch.json", template(fixture["origin"], BRIEFING, mode="mock")),
                                  self.save("gateway.json", gateway), self.root/"loop", allow_mock=True)
            self.assertEqual(result["run"]["state"], "failed")
            self.assertEqual(result["run"]["stop_reason"]["message"], "correction_limit")
            self.assertEqual(fixture["receipts"], [])
            self.assertEqual(len(requests), 3)

    def test_cancel_and_reconcile_never_replay_io(self):
        h = self.host()
        h.cancelled = True
        with self.assertRaisesRegex(KarstError, "cancelled"):
            h.execute(self.call("session_inspect", {}))
        h.cancelled = False
        h.store.db.execute("INSERT INTO calls VALUES(?,?,?,?,?,NULL)", (h.run_id, h.attempt_id, "pending", "digest", "running"))
        h.store.db.commit()
        result = research.reconcile(h.store.root, h.run_id)
        self.assertEqual(result["run"]["state"], "stopped")
        self.assertEqual(result["usage"]["charged_or_reserved"], {})
        self.assertEqual(h.store.get(h.attempt_id)["data"]["state"], "unknown")

    def test_config_rejects_unimplemented_authority_and_oversized_budget(self):
        value = template("http://127.0.0.1:12345", BRIEFING)
        for change in ("scope", "goal", "profile", "budget", "workers", "cost", "grant"):
            bad = deepcopy(value)
            if change == "scope": bad["spec"]["scope"]["default_action"] = "allow"
            if change == "goal": bad["spec"]["objectives"]["discover_security_issues"] = True
            if change == "profile": bad["spec"]["runtime_profile"]["model_config_ref"] = "arbitrary-file"
            if change == "budget": bad["spec"]["scheduling"]["per_task_budget"]["http_requests"] = 31
            if change == "workers": bad["spec"]["scheduling"]["max_workers"] = 2
            if change == "cost": bad["spec"]["budget"]["cost_limit"] = {"currency": "USD", "amount": "1"}
            if change == "grant": bad["spec"]["grant"] = {}
            with self.subTest(change=change), self.assertRaises(KarstError):
                parse_launch(bad)

    def test_gateway_text_single_and_same_response_multi_tool_roundtrips(self):
        from karst.gateway_checks import run_gateway_checks
        import re
        def responder(payload):
            first = payload["messages"][0]["content"]
            values = re.findall(r"\b[0-9a-f]{16}\b", first)
            results = [json.loads(m["content"])["receipt"] for m in payload["messages"] if m["role"] == "tool"]
            if results:
                return tool_reply(content=" ".join(results))
            if payload.get("tools"):
                # Reproduce the runtime provider: required returns one call,
                # while auto can return both requested calls in one response.
                if payload.get("tool_choice") == "required":
                    values = values[:1]
                return tool_reply([("echo-"+str(i), "protocol_echo", {"value": value}) for i, value in enumerate(values)])
            return tool_reply(content=values[0])
        with model_server(responder) as (config, requests):
            result = run_gateway_checks(self.save("gateway.json", config), self.root/"gateway-checks", mode="mock")
            self.assertTrue(result["passed"], result)
            self.assertEqual(result["model_requests"], 5)
            self.assertFalse(result["inference_tested"])
            for request in requests:
                validate_request(ModelRequest(request["messages"]))

    def test_auto_multi_tool_still_rejects_missing_wrong_or_unreplayed_calls(self):
        from karst.gateway_checks import run_gateway_checks
        import re
        for case in ("one_call", "wrong_value", "non_string", "wrong_tool", "missing_receipt"):
            def responder(payload):
                values = re.findall(r"\b[0-9a-f]{16}\b", payload["messages"][0]["content"])
                results = [json.loads(m["content"])["receipt"] for m in payload["messages"] if m["role"] == "tool"]
                if results:
                    return tool_reply(content=" ".join(results[:1] if len(values) == 2 and case == "missing_receipt" else results))
                if not payload.get("tools"):
                    return tool_reply(content=values[0])
                calls = [("echo-"+str(i), "protocol_echo", {"value": v}) for i, v in enumerate(values)]
                if len(calls) == 2:
                    if case == "one_call": calls = calls[:1]
                    if case == "wrong_value": calls[1][2]["value"] = "wrong"
                    if case == "non_string": calls[1][2]["value"] = 42
                    if case == "wrong_tool": calls[1] = (calls[1][0], "other_echo", calls[1][2])
                return tool_reply(calls)
            with self.subTest(case=case), model_server(responder) as (config, requests):
                result = run_gateway_checks(self.save("gateway.json", config), self.root/case, mode="mock")
                self.assertEqual(result["checks"], {"text": True, "single_tool": True, "multi_tool": False})
                self.assertFalse(result["passed"])
                self.assertEqual(result["model_requests"], 5 if case == "missing_receipt" else 4)

    def test_gateway_deadline_redirect_and_provider_usage_overage(self):
        h = self.host()
        for name in ("timeout", "redirect", "overage"):
            def responder(payload):
                if name == "timeout":
                    time.sleep(1.5)
                if name == "redirect":
                    return 302, {}
                result = tool_reply(content="done")
                if name == "overage":
                    result["usage"]["prompt_tokens"] = 2000000
                return result
            with model_server(responder) as (config, requests):
                config["timeout_seconds"] = 1
                config["max_retries"] = 0
                gateway = Gateway(config, h.store, h.run_id, h.budget, h.deadline, check=h.guard)
                begin = time.monotonic()
                with self.subTest(name=name), self.assertRaises(GatewayError):
                    gateway.generate([{"role": "user", "content": "bounded check"}])
                self.assertLess(time.monotonic()-begin, 2.5)
                self.assertEqual(len(requests), 1)

    def test_formal_transport_redirect_network_deny_budget_and_unknown(self):
        for case in ("redirect", "network", "budget", "unknown"):
            with self.subTest(case=case), legacy_server() as (target, origin):
                launch = template(origin, BRIEFING, mode="mock")
                if case == "network":
                    launch["spec"]["scope"]["denied_targets"] = [{"selector_type": "cidr", "value": "127.0.0.1/32", "reason": "fixture denial"}]
                if case == "budget":
                    launch["spec"]["scheduling"]["per_task_budget"]["network_bytes"] = 65536
                with ResearchStore(self.root/case) as store:
                    host = research.Host(parse_launch(launch), store, {"alice": "alice-token", "bob": "bob-token"})
                    path = "/outside" if case == "redirect" else "/drop" if case == "unknown" else "/"
                    reply = host.execute(self.call("http_request", {"url": origin+path, "identity_ref": None, "query": []}))
                    self.assertTrue(reply["error"], reply)
                    self.assertEqual(len(target.seen), 1 if case in ("redirect", "unknown") else 0)
                    if case == "unknown":
                        self.assertEqual(reply["execution_state"], "unknown")
                        self.assertIsNotNone(host.fatal)

    def test_query_references_and_fragment_cannot_bypass_validation(self):
        h = self.host()
        for name, args in [("state_query", {"kind": None, "cursor": 0, "limit": 10}),
                           ("state_query", {"kind": "finding", "cursor": 0, "limit": 10}),
                           ("http_request", {"url": "http://127.0.0.1:12345/#fragment", "identity_ref": None, "query": [["x", "y"]]})]:
            self.assertIn("error", h.execute(self.call(name, args, str(args))))
        with self.assertRaisesRegex(KarstError, "unsupported formal state"):
            h.store.update(h.store.get(h.task_id), state="supported")

    def test_budget_stop_returns_every_tool_result_without_extra_io(self):
        def responder(payload):
            return tool_reply([("one", "session_inspect", {}), ("two", "session_inspect", {}), ("three", "session_inspect", {})])
        with model_server(responder) as (gateway, requests):
            launch = template("http://127.0.0.1:12345", BRIEFING, mode="mock")
            launch["spec"]["scheduling"]["per_task_budget"]["tool_starts"] = 1
            result = research.run(self.save("launch.json", launch), self.save("gateway.json", gateway), self.root/"limited", allow_mock=True)
            self.assertEqual(result["run"]["stop_reason"]["code"], "budget_exhausted")
            ends = [a for a in result["audit"] if a["kind"] == "tool_end"]
            self.assertEqual({a["call_id"] for a in ends}, {"one", "two", "three"})
            self.assertEqual(len(requests), 1)


if __name__ == "__main__":
    unittest.main()
