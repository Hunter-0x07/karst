import base64
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from karst import application
from karst.config import KarstError, load_config, parse_url, strict_json
from karst.store import Store, host_lock, new_id
from tests.support import config, server, write_config


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.data = self.root / "data"

    def tearDown(self):
        self.temp.cleanup()

    def probe(self, cfg):
        return application.probe(write_config(self.root, cfg), self.data)

    def test_rejects_ambiguous_json(self):
        for raw in ('{"a":1,"a":2}', '{"x":NaN}', '{"x":"\\ud800"}', '[' * 1100):
            with self.subTest(raw=raw[:25]), self.assertRaises(KarstError):
                strict_json(raw)

    def test_config_strict_limits_and_fields(self):
        for change in ({"extra": True}, {"profile": "karst-design/1"}):
            cfg = config("http://127.0.0.1")
            cfg.update(change)
            with self.assertRaises(KarstError):
                load_config(write_config(self.root, cfg))
        cfg = config("http://127.0.0.1")
        cfg["limits"]["max_requests"] = True
        with self.assertRaises(KarstError):
            load_config(write_config(self.root, cfg))

    def test_path_boundaries_and_ambiguous_urls(self):
        cfg = config("http://127.0.0.1", "/admin")
        cfg["origins"][0]["path_prefixes"] = ["/admin"]
        loaded = load_config(write_config(self.root, cfg))
        loaded.check_url("http://127.0.0.1/admin/item")
        for suffix in ("/admin-other", "/admin/../other", "/admin/%2e%2e/other", "/admin%2fother", "/admin/%252e", "/admin\\other"):
            with self.subTest(suffix=suffix), self.assertRaises(KarstError):
                loaded.check_url("http://127.0.0.1" + suffix)
        with self.assertRaises(KarstError):
            parse_url("http://user:secret@localhost/")

    def test_real_identity_isolation_persistence_and_evidence_read(self):
        with server() as (target, origin), patch.dict(os.environ, {"KARST_TEST_ALICE": "demo-alice", "KARST_TEST_BOB": "demo-bob"}):
            result = self.probe(config(origin, identities=True))
            self.assertEqual(target.seen, [("/", "anonymous"), ("/", "alice"), ("/", "bob")])
            self.assertEqual(result["requests"], 3)
            self.assertEqual(len(result["evidence"]), 3)
            for op in result["operations"]:
                raw = application.read_evidence(self.data, result["run_id"], op["evidence_refs"][0]["id"])
                exchange = json.loads(raw)
                subject = json.loads(base64.b64decode(exchange["response"]["body_base64"]))["subject"]
                self.assertEqual(subject, op["identity"])
                self.assertNotIn(b"demo-alice", raw)
                self.assertNotIn(b"demo-bob", raw)
            restored = application.status(self.data, result["run_id"])
            self.assertEqual(result, restored)
            self.assertEqual(len(target.seen), 3)  # Reading material did not request target again.
            self.assertEqual(restored["findings"], [])

    def test_http_error_is_captured_execution(self):
        with server() as (_, origin):
            result = self.probe(config(origin, "/error"))
            op = result["operations"][0]
            self.assertEqual(op["http_status"], 500)
            self.assertEqual(op["execution_state"], "succeeded")
            self.assertEqual(len(op["evidence_refs"]), 1)

    def test_scope_denies_redirect_before_other_server_receives(self):
        with server() as (outside, other), server() as (target, origin):
            target.outside = other + "/"
            result = self.probe(config(origin, "/outside"))
            self.assertEqual(outside.seen, [])
            self.assertEqual(result["requests"], 1)
            self.assertEqual(result["operations"][-1]["error"]["code"], "scope_denied")

    def test_redirects_count_against_request_budget(self):
        with server() as (target, origin):
            cfg = config(origin, "/redirect")
            cfg["limits"]["max_requests"] = 1
            result = self.probe(cfg)
            self.assertEqual(target.seen, [("/redirect", "anonymous")])
            self.assertEqual(result["stop_reason"], "budget_exhausted")

    def test_network_deny_wins(self):
        with server() as (target, origin):
            cfg = config(origin)
            cfg["denied_cidrs"] = ["127.0.0.0/8"]
            result = self.probe(cfg)
            self.assertEqual(result["requests"], 0)
            self.assertEqual(target.seen, [])

    def test_mixed_dns_results_fail_closed(self):
        with server() as (target, origin):
            named = origin.replace("127.0.0.1", "localhost")
            replies = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, target.server_port))
                       for ip in ("127.0.0.1", "192.0.2.1")]
            with patch("karst.execution.socket.getaddrinfo", return_value=replies):
                result = self.probe(config(named))
            self.assertEqual(target.seen, [])
            self.assertEqual(result["operations"][0]["error"]["code"], "network_scope_denied")

    def test_dns_address_is_pinned_for_connection(self):
        with server() as (target, origin):
            named = origin.replace("127.0.0.1", "localhost")
            replies = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", target.server_port))]
            with patch("karst.execution.socket.getaddrinfo", return_value=replies) as resolver:
                result = self.probe(config(named))
            self.assertEqual(resolver.call_count, 1)
            self.assertEqual(result["operations"][0]["connected_ip"], "127.0.0.1")
            self.assertEqual(len(target.seen), 1)

    def test_credentials_do_not_cross_origins_even_when_both_allowed(self):
        with server() as (outside, other), server() as (target, origin), patch.dict(os.environ, {"KARST_TEST_ALICE": "demo-alice", "KARST_TEST_BOB": "demo-bob"}):
            target.outside = other + "/"
            cfg = config(origin, "/outside", identities=True)
            cfg["origins"].append({"origin": other, "path_prefixes": ["/"]})
            result = self.probe(cfg)
            self.assertEqual(outside.seen, [("/", "anonymous")])
            self.assertEqual(sum(op["error"] is not None and op["error"]["code"] == "identity_origin_mismatch" for op in result["operations"]), 2)

    def test_capture_limit_marks_partial(self):
        with server() as (_, origin):
            cfg = config(origin, "/large")
            cfg["limits"]["max_response_bytes"] = 100
            result = self.probe(cfg)
            self.assertEqual(result["response_bytes"], 100)
            self.assertEqual(result["evidence"][0]["capture_state"], "partial")

    def test_total_body_budget_stops_next_request(self):
        with server() as (target, origin):
            cfg = config(origin, "/large")
            cfg["entrypoints"].append(origin + "/whoami")
            cfg["limits"]["max_response_bytes"] = 100
            cfg["limits"]["max_total_response_bytes"] = 100
            result = self.probe(cfg)
            self.assertEqual(result["response_bytes"], 100)
            self.assertEqual(len(target.seen), 1)
            self.assertEqual(result["stop_reason"], "budget_exhausted")

    def test_request_budget_includes_all_identities(self):
        with server() as (target, origin), patch.dict(os.environ, {"KARST_TEST_ALICE": "demo-alice", "KARST_TEST_BOB": "demo-bob"}):
            cfg = config(origin, identities=True)
            cfg["limits"]["max_requests"] = 2
            result = self.probe(cfg)
            self.assertEqual(target.seen, [("/", "anonymous"), ("/", "alice")])
            self.assertEqual(result["requests"], 2)

    def test_unknown_operation_stops_following_requests(self):
        with server() as (target, origin):
            cfg = config(origin, "/drop")
            cfg["entrypoints"].append(origin + "/whoami")
            result = self.probe(cfg)
            self.assertEqual(target.seen, [("/drop", "anonymous")])
            self.assertEqual(result["stop_reason"], "probe_incomplete")

    def test_truncated_content_length_not_marked_complete(self):
        with server() as (_, origin):
            result = self.probe(config(origin, "/partial"))
            self.assertEqual(result["evidence"][0]["capture_state"], "partial")

    def test_timeout_is_bounded_and_not_replayed(self):
        with server() as (target, origin):
            cfg = config(origin, "/slow")
            cfg["limits"]["timeout_seconds"] = 1
            start = time.monotonic()
            result = self.probe(cfg)
            self.assertLess(time.monotonic() - start, 3)
            self.assertEqual(len(target.seen), 1)
            self.assertEqual(result["operations"][0]["execution_state"], "unknown")
            self.assertEqual(result["operations"][0]["error"]["retry_policy"], "inspect_first")

    def test_connection_drop_is_unknown(self):
        with server() as (target, origin):
            result = self.probe(config(origin, "/drop"))
            self.assertEqual(len(target.seen), 1)
            self.assertEqual(result["operations"][0]["execution_state"], "unknown")

    def test_evidence_failure_does_not_undo_target_execution(self):
        with server() as (target, origin), patch.object(Store, "save_evidence", side_effect=KarstError("evidence_save_failed")):
            result = self.probe(config(origin))
            self.assertEqual(len(target.seen), 1)
            op = result["operations"][0]
            self.assertEqual(op["execution_state"], "succeeded")
            self.assertEqual(op["error"]["code"], "evidence_save_failed")
            self.assertEqual(op["evidence_refs"], [])

    def test_integrity_failure_changes_read_availability(self):
        with server() as (_, origin):
            result = self.probe(config(origin))
        evidence_id = result["evidence"][0]["id"]
        (self.data / "evidence" / f"{evidence_id}.json").write_bytes(b"tampered")
        with self.assertRaises(KarstError):
            application.read_evidence(self.data, result["run_id"], evidence_id)
        self.assertEqual(application.status(self.data, result["run_id"])["evidence"][0]["availability"], "unavailable")

    def test_missing_credentials_do_not_create_run(self):
        cfg = config("http://127.0.0.1", identities=True)
        with patch.dict(os.environ, {}, clear=True), self.assertRaises(KarstError):
            self.probe(cfg)
        self.assertFalse(self.data.exists())

    def test_store_versions_and_cross_run_references(self):
        with host_lock(self.data), Store(self.data) as store:
            first, other = new_id("run"), new_id("run")
            store.put("run", first, first, {"state": "running"})
            store.put("run", other, other, {"state": "running"})
            with self.assertRaises(KarstError):
                store.put("run", first, first, {"state": "stopped"}, expected_version=0)
            store.put("run", first, first, {"state": "stopped"}, expected_version=1)
            self.assertEqual(store.get(first, version=1)["data"]["state"], "running")
            with self.assertRaises(KarstError):
                store.get(first, run_id=other)

    def test_equal_timestamps_preserve_insertion_order(self):
        with host_lock(self.data), Store(self.data) as store, patch("karst.store.utcnow", return_value="2026-10-18T00:00:00Z"):
            run_id = new_id("run")
            store.put("run", run_id, run_id, {"state": "running"})
            ids = ["operation_" + "f" * 32, "operation_" + "a" * 32]
            for op_id in ids:
                store.put("operation", op_id, run_id, {"execution_state": "running"})
            store.put("operation", ids[0], run_id, {"execution_state": "succeeded"}, expected_version=1)
            self.assertEqual([r["id"] for r in store.records(run_id, "operation")], ids)

    def test_host_lock_blocks_other_process_and_releases(self):
        script = "from karst.store import host_lock; import sys;\nwith host_lock(sys.argv[1]): print('owned')"
        env = dict(os.environ, PYTHONPATH=str(ROOT / "src"))
        with host_lock(self.data):
            child = subprocess.run([sys.executable, "-c", script, str(self.data)], env=env, capture_output=True, timeout=15)
            self.assertNotEqual(child.returncode, 0)
        child = subprocess.run([sys.executable, "-c", script, str(self.data)], env=env, capture_output=True, timeout=15)
        self.assertEqual(child.returncode, 0)

    def test_reconcile_marks_interrupted_operation_unknown_without_requests(self):
        with host_lock(self.data), Store(self.data) as store:
            run_id = new_id("run")
            store.put("run", run_id, run_id, {"state": "running", "requests": 0, "response_bytes": 0})
            op_id = new_id("operation")
            store.put("operation", op_id, run_id, {"execution_state": "running", "response_bytes": 0, "evidence_refs": []})
        result = application.reconcile(self.data, run_id)
        self.assertEqual(result["operations"][0]["execution_state"], "unknown")
        self.assertEqual(result["requests"], 1)
        self.assertEqual(result["stop_reason"], "interrupted_requires_inspection")
        self.assertEqual(application.list_runs(self.data)["runs"][0]["run_id"], run_id)

    def test_export_and_cli_readonly_after_restart(self):
        with server() as (target, origin):
            result = self.probe(config(origin))
            out = self.root / "export"
            application.export(self.data, result["run_id"], out)
            with self.assertRaises(KarstError):
                application.export(self.data, result["run_id"], out)
            report = (out / "run.json").read_text(encoding="utf-8")
            self.assertNotIn("body_base64", report)
            cmd = [sys.executable, str(ROOT / "scripts" / "karst.py"), "status", "--data-dir", str(self.data), "--run-id", result["run_id"]]
            child = subprocess.run(cmd, capture_output=True, timeout=15)
            self.assertEqual(child.returncode, 0, child.stderr)
            self.assertEqual(json.loads(child.stdout)["run_id"], result["run_id"])
            self.assertEqual(len(target.seen), 1)

    def test_unimplemented_resume_fails_explicitly(self):
        child = subprocess.run([sys.executable, str(ROOT / "scripts" / "karst.py"), "resume"], capture_output=True, timeout=15)
        self.assertEqual(child.returncode, 2)
        self.assertIn(b"not implemented", child.stderr)

    def test_model_preflight_only_queries_listing(self):
        with server() as (target, origin):
            path = self.root / "gateway.json"
            path.write_text(json.dumps({"api_base": origin + "/v1", "model": "qwen3.8-27b"}), encoding="utf-8")
            env = {key: value for key, value in os.environ.items() if key != "TESTER_API_KEY"}
            child = subprocess.run([sys.executable, str(ROOT / "scripts" / "check_model.py"), "--config", str(path)], env=env, capture_output=True, timeout=15)
            self.assertEqual(child.returncode, 0, child.stderr)
            self.assertFalse(json.loads(child.stdout)["inference_tested"])
            self.assertEqual(target.seen, [("/v1/models", "anonymous")])

    def test_shipped_example_configs_parse(self):
        """仓库随附的示例配置必须能被当前代码解析。

        协议标识改名（answer-* -> karst-*）时最容易漏的是 config/examples/ 下的 JSON：
        单元测试从不读取这些文件，漏改不会让任何测试失败，却会让示例配置无法使用。
        """
        from karst.research_config import load_launch

        load_config(ROOT / "config" / "examples" / "http-probe.json")
        load_launch(ROOT / "config" / "examples" / "i0-run.json")


if __name__ == "__main__":
    unittest.main()
