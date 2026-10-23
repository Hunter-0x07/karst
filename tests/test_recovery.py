"""Recovery continues retained research using fresh tasks and the original ledger."""

from copy import deepcopy
import json
import math
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

import tests.test_product  # Establish the repository source path for unittest.
from tests.i0_support import model_server
from tests.product_support import product_model
from karst import research, recovery
from karst.gateway import Gateway
from karst.config import KarstError
from karst.product_fixture import application_fixture, BRIEFING, score
from karst.research_config import product_template
from karst.research_store import ResearchStore


class RecoveryTests(unittest.TestCase):
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

    def paused(self, fixture, gateway, **options):
        for name, token in fixture["tokens"].items():
            os.environ["KARST_I0_"+name.upper()] = token
        self.launch = self.save("launch.json", product_template(fixture["origin"], BRIEFING, mode="mock"))
        self.gateway = self.save("gateway.json", gateway)
        return research.run(self.launch, self.gateway, self.root/"data", allow_mock=True, pause_after_tasks=1, **options)

    def resume(self, run_id, **options):
        return research.resume(self.launch, self.gateway, self.root/"data", run_id, allow_mock=True, **options)

    def test_two_resumes_preserve_ledger_and_fresh_verification_and_capability(self):
        with application_fixture("P2") as fixture, model_server(product_model) as (gateway, requests):
            first = self.paused(fixture, gateway)
            self.assertEqual(first["run"]["state"], "paused", first["run"])
            self.assertEqual(len(first["findings"]), 0)
            before = deepcopy(first["usage"]["charged_or_reserved"])
            point = first["audit"][-1]
            self.assertEqual(point["kind"], "task_boundary_checkpoint")
            reconciled = research.reconcile(self.root/"data", first["run_id"])
            self.assertEqual(reconciled, first)
            second = self.resume(first["run_id"], pause_after_tasks=1)
            self.assertEqual(second["run"]["state"], "paused", second["run"])
            self.assertEqual(len(second["findings"]), 1)
            self.assertGreater(second["usage"]["charged_or_reserved"]["model_requests"], before["model_requests"])
            self.assertGreaterEqual(second["audit"][-1]["active_wall_seconds"], point["active_wall_seconds"])
            final = self.resume(first["run_id"])
            self.assertEqual(final["run"]["stop_reason"]["code"], "frontier_exhausted", final["run"])
            self.assertEqual(len([r for r in requests if len(r["messages"]) == 2]), 3)
            tasks = [r for r in final["records"] if r["kind"] == "task"]
            self.assertEqual(len(tasks), 3)
            self.assertTrue(all(t["data"]["state"] == "delivered" for t in tasks))
            old = next(r for r in first["records"] if r["kind"] == "task")
            self.assertEqual(old, next(r for r in final["records"] if r["id"] == old["id"]))
            with ResearchStore(self.root/"data", readonly=True) as store:
                scored = score(store, first["run_id"], fixture, offline_passed=True)
                self.assertTrue(scored["passed"], scored)
            count = len(requests), len(fixture["receipts"])
            with self.assertRaisesRegex(KarstError, "clean_task_boundary"):
                self.resume(first["run_id"])
            self.assertEqual(count, (len(requests), len(fixture["receipts"])))
        research.export(self.root/"data", final["run_id"], self.root/"report")
        exported = (self.root/"report/run.json").read_text(encoding="utf-8")
        self.assertNotIn("private_bindings", exported)
        self.assertNotIn(point["private_bindings"]["credentials"]["alice"], exported)

    def test_changed_bindings_state_and_evidence_refuse_before_io(self):
        with application_fixture("P1") as fixture, model_server(product_model) as (gateway, requests):
            first = self.paused(fixture, gateway)
            count = len(requests), len(fixture["receipts"])
            with patch.dict(os.environ, {"KARST_I0_BOB": "changed"}):
                with self.assertRaisesRegex(KarstError, "credentials_changed"):
                    self.resume(first["run_id"])
            original = self.gateway.read_bytes()
            self.save("gateway.json", dict(gateway, max_tokens=gateway["max_tokens"]+1))
            with self.assertRaisesRegex(KarstError, "credentials_changed"):
                self.resume(first["run_id"])
            self.gateway.write_bytes(original)
            with patch.object(recovery, "bindings", return_value={}):
                with self.assertRaisesRegex(KarstError, "runtime_or_credentials_changed"):
                    self.resume(first["run_id"])
            with ResearchStore(self.root/"data") as store:
                session = store.records(first["run_id"], "session")[0]
                store.update(session, auth_status="revoked")
            with self.assertRaisesRegex(KarstError, "checkpoint_state_changed"):
                self.resume(first["run_id"])
            self.assertEqual(count, (len(requests), len(fixture["receipts"])))

    def test_damaged_blob_refuses_before_io(self):
        with application_fixture("P1") as fixture, model_server(product_model) as (gateway, requests):
            first = self.paused(fixture, gateway)
            count = len(requests), len(fixture["receipts"])
            evidence = next((self.root/"data/evidence").iterdir())
            evidence.write_bytes(b"damaged")
            with self.assertRaisesRegex(KarstError, "evidence_integrity_failed"):
                self.resume(first["run_id"])
            self.assertEqual(count, (len(requests), len(fixture["receipts"])))

    def test_pause_validation_precedes_any_run(self):
        for value in (0, -1, True, 1.5):
            with self.subTest(value=value), self.assertRaisesRegex(KarstError, "pause_after_tasks"):
                research.run("missing", "missing", self.root/"unused", pause_after_tasks=value)
        self.assertFalse((self.root/"unused").exists())

    def test_unknown_actions_calls_and_model_requests_cannot_form_checkpoint(self):
        with application_fixture("P1") as fixture, model_server(product_model) as (gateway, requests):
            first = self.paused(fixture, gateway)
            point = first["audit"][-1]
            count = len(requests), len(fixture["receipts"])
            with ResearchStore(self.root/"data") as store:
                for failure in ("operation", "call", "model", "session"):
                    store.db.execute("BEGIN IMMEDIATE")
                    try:
                        if failure == "operation":
                            store.update(store.records(first["run_id"], "operation")[0], execution_state="unknown")
                        elif failure == "call":
                            store.db.execute("UPDATE calls SET state='unknown' WHERE run_id=?", (first["run_id"],))
                        elif failure == "model":
                            store.audit(first["run_id"], "model_start", {"request_id": "incomplete"})
                        else:
                            store.update(store.records(first["run_id"], "session")[0], generation=2)
                        with self.subTest(failure=failure), self.assertRaises(KarstError):
                            recovery.clean_boundary(store, first["run_id"], point["task_ref"]["id"], point["attempt_ref"]["id"])
                    finally:
                        store.db.rollback()
            self.assertEqual(count, (len(requests), len(fixture["receipts"])))

    def test_active_wall_time_is_carried_into_new_task(self):
        def factory(*args, **kwargs):
            h = kwargs["check"].__self__
            if not getattr(h, "simulated_elapsed", False):
                h.invocation_started -= 3000
                h.simulated_elapsed = True
            return Gateway(*args, **kwargs)
        with application_fixture("P1") as fixture, model_server(product_model) as (gateway, _):
            for name, token in fixture["tokens"].items():
                os.environ["KARST_I0_"+name.upper()] = token
            self.launch = self.save("launch.json", product_template(fixture["origin"], BRIEFING, mode="mock"))
            self.gateway = self.save("gateway.json", gateway)
            first = research.run(self.launch, self.gateway, self.root/"data", allow_mock=True, pause_after_tasks=1, gateway_factory=factory)
            self.assertGreaterEqual(first["audit"][-1]["active_wall_seconds"], 3000)
            final = self.resume(first["run_id"])
            self.assertEqual(final["run"]["stop_reason"]["code"], "frontier_exhausted", final["run"])
            task = next(r for r in final["records"] if r["kind"] == "task" and r["data"]["role"] == "verify")
            self.assertLessEqual(task["data"]["allocated_budget"]["wall_seconds"], 600)
            self.assertGreater(final["usage"]["charged_or_reserved"]["model_requests"], first["usage"]["charged_or_reserved"]["model_requests"])

    def test_checkpoint_hashing_time_is_charged_before_pause(self):
        hosts, expected = [], {}
        original = recovery.bindings
        def factory(*args, **kwargs):
            hosts.append(kwargs["check"].__self__)
            return Gateway(*args, **kwargs)
        def slow_binding(*args):
            h = hosts[-1]
            expected["minimum"] = math.ceil(time.monotonic()-h.invocation_started)+10
            h.invocation_started -= 10  # Simulate expensive local checkpoint work without sleeping.
            return original(*args)
        with application_fixture("P1") as fixture, model_server(product_model) as (gateway, _):
            with patch.object(recovery, "bindings", side_effect=slow_binding):
                result = self.paused(fixture, gateway, gateway_factory=factory)
            self.assertEqual(result["run"]["state"], "paused", result["run"])
            self.assertGreaterEqual(result["audit"][-1]["active_wall_seconds"], expected["minimum"])
