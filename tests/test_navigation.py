"""Static parsing does not grant access or execute target content."""

import unittest
from copy import deepcopy
import json
import os
from pathlib import Path
import tempfile
from unittest.mock import patch

import tests.test_product  # Establish the repository source path for unittest.
from karst.config import KarstError
from karst.navigation import inspect
from karst import research
from karst.product_fixture import application_fixture, BRIEFING, score_html
from karst.research_config import product_template
from karst.research_store import ResearchStore
from karst.application import credential_values
from karst.research_config import parse_launch
from karst.protocol import ToolCall
from tests.i0_support import model_server
from tests.product_support import product_model


class NavigationTests(unittest.TestCase):
    def parse(self, html):
        def scope(url):
            if not url.startswith("http://127.0.0.1:8000/"):
                raise KarstError("out_of_scope")
        return inspect(html.encode(), "http://127.0.0.1:8000/start?q=old", scope)

    def test_relative_base_entities_fragments_and_inert_scripts(self):
        parsed = self.parse('''<base href="/catalog/"><base href="https://evil.invalid/">
            <a href="../policy?a=1&amp;b=2#part">policy</a><a href="javascript:fetch('/wrong')">x</a>
            <script>"<a href='/wrong'>"</script><template><a href='/wrong'></a></template>
            <a href="https://outside.invalid/item">outside</a><a href="http://user:password@localhost/a">x</a>''')
        self.assertEqual([x["url"] for x in parsed["links"]], ["http://127.0.0.1:8000/policy?a=1&b=2", "https://outside.invalid/item"])
        self.assertTrue(parsed["links"][0]["in_scope"])
        self.assertFalse(parsed["links"][1]["in_scope"])
        self.assertEqual(parsed["target_requests"], 0)

    def test_get_forms_keep_repeated_controls_and_replace_action_query(self):
        parsed = self.parse('''<form action="/read?discard=yes"><input name="k" value="a&amp;b">
            <input name="k" value="two"><input type="checkbox" name="yes" checked>
            <input type="checkbox" name="no"><input name="off" disabled></form>
            <form method="POST" action="/write"><input name="x" value="y"></form>
            <form><select name="choice"><option value="a">a</option></select></form>''')
        first, post, choice = parsed["forms"]
        self.assertEqual(first["url"], "http://127.0.0.1:8000/read")
        self.assertEqual(first["query"], [["k", "a&b"], ["k", "two"], ["yes", "on"]])
        self.assertEqual(first["request_url"], "http://127.0.0.1:8000/read?k=a%26b&k=two&yes=on")
        self.assertTrue(first["supported"])
        self.assertFalse(post["supported"])
        self.assertFalse(choice["supported"])

    def test_item_limits_are_explicit(self):
        parsed = self.parse('<a href="/item">x</a>'*70)
        self.assertEqual(len(parsed["links"]), 64)
        self.assertTrue(parsed["truncated"])

    def test_evidence_parser_keeps_provenance_and_read_budget_without_new_http(self):
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, {}), application_fixture("P1", navigation="form") as fixture:
            for name, token in fixture["tokens"].items():
                os.environ["KARST_I0_"+name.upper()] = token
            launch = parse_launch(product_template(fixture["origin"], BRIEFING, mode="mock"))
            with ResearchStore(folder) as store:
                h = research.Host(launch, store, credential_values(launch.transport))
                args = {"url": fixture["origin"]+"/", "identity_ref": None, "query": []}
                reply = h.execute(ToolCall("entry", "http_request", args, json.dumps(args)))
                self.assertIsNone(reply["capability_ref"])
                reference = reply["evidence_refs"][0]
                args = {"evidence_ref": reference}
                inspected = h.execute(ToolCall("inspect", "document_inspect", args, json.dumps(args)))
                self.assertEqual(inspected["evidence_ref"], reference)
                self.assertEqual(inspected["source_url"], fixture["origin"]+"/")
                self.assertEqual(reply["request_url"], fixture["origin"]+"/")
                self.assertEqual(inspected["forms"][0]["request_url"], fixture["origin"]+fixture["detail"])
                self.assertEqual(len(fixture["receipts"]), 1)
                self.assertEqual(h.read_bytes, inspected["read_bytes"])
                h.read_bytes = launch.execution["max_total_read_bytes"]
                exhausted = h.execute(ToolCall("inspect-again", "document_inspect", args, json.dumps(args)))
                self.assertEqual(exhausted["error"]["code"], "budget_exhausted")
                self.assertEqual(len(fixture["receipts"]), 1)

    def test_redacted_controls_and_dom_association_are_not_executable(self):
        parsed = self.parse('''<input form="f" name="outside" value="x"><fieldset disabled>
            <form id="f"><input name="token" value="[REDACTED]"></form></fieldset>
            <a href="/read?token=[REDACTED]">redacted</a>''')
        self.assertFalse(parsed["forms"][0]["supported"])
        self.assertEqual(parsed["links"], [])

    def test_rule_feedback_distinguishes_saved_action_from_supported_resource(self):
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, {}), application_fixture("P1", navigation="form") as fixture:
            for name, token in fixture["tokens"].items():
                os.environ["KARST_I0_"+name.upper()] = token
            launch = parse_launch(product_template(fixture["origin"], BRIEFING, mode="mock"))
            with ResearchStore(folder) as store:
                h = research.Host(launch, store, credential_values(launch.transport))
                def call(key, name, args):
                    return h.execute(ToolCall(key, name, args, json.dumps(args)))
                entry = call("entry", "http_request", {"url": fixture["origin"]+"/", "identity_ref": None, "query": []})
                parsed = call("parse", "document_inspect", {"evidence_ref": entry["evidence_refs"][0]})
                form = parsed["forms"][0]
                policy = call("policy", "http_request", {"url": parsed["links"][0]["url"], "identity_ref": None, "query": []})
                owner = call("owner", "http_request", {"url": form["url"], "query": form["query"], "identity_ref": h.context["identity_refs"][0]})
                self.assertEqual(owner["request_url"], form["request_url"])
                self.assertNotEqual(owner["request_url"], form["url"])
                for index, url in enumerate((form["url"], owner["request_url"])):
                    proposal = {"summary": "Published rule binding", "outcome": "progress", "suggested_opportunities": [], "proposed_records": [
                        {"local_ref": "resource", "kind": "asset", "data": {"asset_type": "web_resource", "locator": {"url": url}, "parent_refs": [], "provenance_refs": entry["evidence_refs"]}},
                        {"local_ref": "rule", "kind": "security_rule", "data": {"statement": "Explicit purchase read policy", "applies_to_refs": [{"local_ref": "resource"}], "source_refs": policy["evidence_refs"], "source_type": "target_document"}}]}
                    receipt = call("publish-"+str(index), "publish_research", proposal)
                    self.assertEqual(receipt["status"], "accepted", receipt)
                    state = receipt["record_states"][0]
                    self.assertEqual(state["status"], "proposed" if index == 0 else "supported")
                    if index == 0:
                        self.assertEqual(state["resource_urls"], [form["url"]])
                        self.assertEqual(state["validation_error"], "missing_or_conflicting_explicit_policy")
                        self.assertIn("exact executed request_url", state["guidance"])
                        inline = deepcopy(proposal)
                        inline["proposed_records"].append({"local_ref": "candidate", "kind": "candidate", "data": {
                            "claim": {"type": "object_read_boundary", "protected_fields": ["private_value"]},
                            "affected_refs": [{"local_ref": "resource"}, h.context["identity_refs"][1]],
                            "rule_refs": [{"local_ref": "rule"}], "supporting_refs": owner["evidence_refs"],
                            "counterevidence_refs": [], "required_conditions": [],
                            "alternative_explanations": ["Explicit sharing may allow this subject"], "missing_conditions": []}})
                        before = len(store.records(h.run_id))
                        rejected = call("inline-candidate", "publish_research", inline)
                        self.assertEqual(rejected["status"], "rejected")
                        self.assertIn(form["url"], rejected["error"]["message"])
                        self.assertIn("exact executed request_url", rejected["error"]["message"])
                        self.assertIn("not saved", rejected["error"]["message"])
                        self.assertEqual(len(store.records(h.run_id)), before)
                    stored = store.status(h.run_id)["receipts"][-1]
                    self.assertNotIn("record_states", stored)
                self.assertEqual(len(fixture["receipts"]), 3)

    def test_html_links_and_get_forms_cross_real_http_and_independent_review(self):
        for scenario, variant in (("P1", "links"), ("P2", "form"), ("P3", "form"), ("P4", "links")):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, {}):
                root = Path(folder)
                with application_fixture(scenario, navigation=variant) as fixture, model_server(product_model) as (gateway, requests):
                    for name, token in fixture["tokens"].items():
                        os.environ["KARST_I0_"+name.upper()] = token
                    launch = root/"launch.json"
                    launch.write_text(json.dumps(product_template(fixture["origin"], BRIEFING, mode="mock")), encoding="utf-8")
                    config = root/"gateway.json"
                    config.write_text(json.dumps(gateway), encoding="utf-8")
                    paused = research.run(launch, config, root/"data", allow_mock=True, pause_after_tasks=1)
                    result = research.resume(launch, config, root/"data", paused["run_id"], allow_mock=True)
                research.export(root/"data", result["run_id"], root/"export")
                with ResearchStore(root/"data", readonly=True) as store:
                    scored = score_html(store, result["run_id"], fixture, offline_passed=True)
                self.assertTrue(scored["passed"], scored)
                inspect_calls = [a for a in result["audit"] if a["kind"] == "tool_end" and a.get("name") == "document_inspect"]
                self.assertEqual(len(inspect_calls), 1)
                self.assertEqual(inspect_calls[0]["reply"]["target_requests"], 0)
                self.assertGreater(inspect_calls[0]["reply"]["read_bytes"], 768)
                self.assertFalse(inspect_calls[0]["reply"]["truncated"])
