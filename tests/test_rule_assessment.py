"""Final delivery must retain evidence-grounded unknowns, not just prose."""
import json
import os
import tempfile
import unittest
from unittest.mock import patch

import tests.test_product
from karst import research
from karst.application import credential_values
from karst.product_fixture import application_fixture, BRIEFING
from karst.protocol import ToolCall
from karst.research_config import parse_launch, product_template
from karst.research_store import ResearchStore
from tests.i0_support import observation


class RuleAssessmentTests(unittest.TestCase):
    def exercise(self, scenario, check):
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, {}), application_fixture(scenario) as fixture:
            for name, token in fixture["tokens"].items():
                os.environ["KARST_I0_"+name.upper()] = token
            launch = parse_launch(product_template(fixture["origin"], BRIEFING, mode="mock"))
            with ResearchStore(folder) as store:
                host = research.Host(launch, store, credential_values(launch.transport))
                def call(key, name, args):
                    return host.execute(ToolCall(key, name, args, json.dumps(args)))
                def get(key, path, identity=None):
                    return call(key, "http_request", {"url": fixture["origin"]+path, "identity_ref": identity, "query": []})
                check(host, store, call, get, fixture)

    def test_missing_assessment_rejects_atomically_until_model_explicitly_records_unknown(self):
        def check(host, store, call, get, fixture):
            owner = get("owner", fixture["detail"], host.context["identity_refs"][0])
            final = observation("Read observed; policy remains unestablished", owner["evidence_refs"])
            before = len(store.records(host.run_id))
            rejected = call("final-missing", "submit_result", final)
            self.assertEqual(rejected["status"], "rejected")
            self.assertEqual(rejected["error"]["message"], "object_read_rule_assessment_missing")
            self.assertEqual(len(store.records(host.run_id)), before)
            self.assertEqual(store.get(host.task_id)["data"]["state"], "running")
            self.assertFalse(store.records(host.run_id, "hypothesis"))
            guidance = rejected["guidance"]
            self.assertEqual(guidance["unassessed_count"], 1)
            gap = guidance["resources"][0]
            self.assertEqual(gap["resource_url"], owner["request_url"])
            final["proposed_records"].append(gap["draft_hypothesis"])
            accepted = call("final-explicit", "submit_result", final)
            self.assertEqual(accepted["status"], "accepted", accepted)
            self.assertEqual(store.get(host.task_id)["data"]["state"], "delivered")
            self.assertEqual(len(store.records(host.run_id, "hypothesis")), 1)
            self.assertFalse(store.status(host.run_id)["findings"])
            self.assertEqual(len(fixture["receipts"]), 1)
        self.exercise("P4", check)

    def test_unrelated_hypothesis_cannot_cover_observed_resource(self):
        def check(host, store, call, get, fixture):
            entry = get("entry", "/")
            owner = get("owner", fixture["detail"], host.context["identity_refs"][0])
            hypothesis = {"local_ref": "unrelated", "kind": "hypothesis", "data": {
                "question": "What does this entry page describe?", "basis_refs": entry["evidence_refs"],
                "alternative_explanations": ["More context is needed"], "missing_conditions": ["Description"]}}
            receipt = call("publish", "publish_research", {"summary": "Entry question", "outcome": "progress", "proposed_records": [hypothesis], "suggested_opportunities": []})
            self.assertEqual(receipt["status"], "accepted", receipt)
            self.assertEqual(receipt["rule_assessment_gaps"]["unassessed_count"], 1)
            rejected = call("final", "submit_result", observation("Object read", owner["evidence_refs"]))
            self.assertEqual(rejected["error"]["message"], "object_read_rule_assessment_missing")
            self.assertEqual(store.get(host.task_id)["data"]["state"], "running")
        self.exercise("P4", check)

    def test_valid_supported_rule_does_not_require_an_invented_unknown(self):
        def check(host, store, call, get, fixture):
            owner = get("owner", fixture["detail"], host.context["identity_refs"][0])
            policy = get("policy", fixture["policy_url"])
            proposal = {"summary": "Explicit rule", "outcome": "progress", "suggested_opportunities": [], "proposed_records": [
                {"local_ref": "resource", "kind": "asset", "data": {"asset_type": "web_resource", "locator": {"url": owner["request_url"]}, "parent_refs": [], "provenance_refs": owner["evidence_refs"]}},
                {"local_ref": "rule", "kind": "security_rule", "data": {"statement": "Explicit read policy", "applies_to_refs": [{"local_ref": "resource"}], "source_refs": policy["evidence_refs"], "source_type": "target_document"}}]}
            receipt = call("publish", "publish_research", proposal)
            self.assertEqual(receipt["record_states"][0]["status"], "supported")
            self.assertEqual(receipt["rule_assessment_gaps"]["unassessed_count"], 0)
            final = call("final", "submit_result", observation("Owner read under explicit policy", owner["evidence_refs"]))
            self.assertEqual(final["status"], "accepted", final)
            self.assertFalse(store.records(host.run_id, "hypothesis"))
        self.exercise("P1", check)
