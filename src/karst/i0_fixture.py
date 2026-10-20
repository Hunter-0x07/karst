"""Resettable, loopback-only normal-business application and evidence-based I0 scorer."""

import base64
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import secrets
import threading

from karst.research_store import ref
from karst.store import utcnow

BRIEFING_VERSION = "i0-business-checkpoint-v3"
BRIEFING = ("调查这个采购演示站。依据入口导航，分别以 Alice 和 Bob 身份查看各自目录和订单详情，"
            "整理实际用户、订单编号和 reconciliation_code。按以下检查点顺序执行：先取得 Alice 的目录、"
            "订单详情和所需证据内容；立即单独调用 publish_research 发布 Alice 已有证据支持的事实，"
            "等待接受回执。收到接受回执之后，再以 Bob 身份请求其目录和订单详情并读取所需证据。"
            "首次发布之前不要请求 Bob 的目录或订单，不要等两人的 HTTP 取证都结束后才发布；"
            "最终 submit_result 的 proposed_records 必须自行包含 Alice 和 Bob 两人的完整事实，"
            "即使 Alice 的事实已经在中途 publish_research 中被接受，也必须在最终提交中再次列出；"
            "中途发布的记录不会自动并入最终提交。每人至少一条 observation 的 statement 同时写明"
            "实际用户名、订单编号和完整 reconciliation_code，并在该条的 evidence_refs 中引用该身份的订单详情证据。"
            "仅在 summary 中汇总或只交付 Bob 不算完整交付。复用已保存的证据引用，无需重复 HTTP 取证。"
            "完整 reconciliation_code 位于长响应后段，请读取证据原件视图。"
            "这是正常业务核对，不是漏洞测试。")


@contextmanager
def application_fixture():
    reset_id = secrets.token_hex(16)
    users = {name: {"catalog": "/catalog/"+secrets.token_hex(12), "detail": "/orders/"+secrets.token_hex(12),
                    "order": secrets.token_hex(8), "code": "reconcile-"+secrets.token_hex(16), "token": secrets.token_hex(16)}
             for name in ("alice", "bob")}
    receipts = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            actual = next((name for name, values in users.items() if self.headers.get("Authorization") == "Bearer "+values["token"]), "anonymous")
            path = self.path
            status = 404
            body = {"error": "unknown resource"}
            if path == "/":
                status = 200
                body = {"description": "Normal purchase application. Each managed user may read their own catalog and order.",
                        "catalogs": {name: values["catalog"] for name, values in users.items()}}
            for name, values in users.items():
                if path in (values["catalog"], values["detail"]):
                    if actual != name:
                        status, body = 403, {"error": "this resource belongs to another user", "subject": actual}
                    elif path == values["catalog"]:
                        status, body = 200, {"subject": actual, "detail": values["detail"]}
                    else:
                        status, body = 200, {"subject": actual, "order": values["order"],
                            "notice": "The reconciliation_code follows the archived normal business notes. Read the saved body beyond its preview.",
                            "notes": "normal archived business data; "*120, "reconciliation_code": values["code"]}
            raw = json.dumps(body, ensure_ascii=False).encode("utf-8")
            receipts.append({"sequence": len(receipts)+1, "at": utcnow(), "path": path, "subject": actual, "status": status})
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            try:
                self.wfile.write(raw)
            except OSError:
                pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield {"origin": "http://127.0.0.1:"+str(server.server_port), "reset_id": reset_id, "users": users, "receipts": receipts}
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def score(store, run_id, fixture, *, offline_read_passed):
    """Answers exist only here/in private fixture state, never in a model prompt."""
    status = store.status(run_id)
    audit = status["audit"]
    records = {r["id"]: r for r in status["records"]}
    ends = [a for a in audit if a["kind"] == "tool_end"]
    starts = {a["call_id"]: a for a in audit if a["kind"] == "tool_start"}
    http = [a for a in ends if a["name"] == "http_request" and a["reply"].get("execution_state") == "succeeded"]
    reads = [a for a in ends if a["name"] == "evidence_read" and not a["reply"].get("error")]
    publish = [a for a in ends if a["name"] == "publish_research" and a["reply"].get("status") == "accepted"]
    finals = [r for r in records.values() if r["kind"] == "result" and r["data"]["submission_kind"] == "final"]
    final_observations = [records[r["id"]] for f in finals for r in f["data"]["accepted_refs"]]
    material = {}
    for a in http:
        for er in a["reply"]["evidence_refs"]:
            exchange = json.loads(store.evidence_bytes(er, run_id))
            body = base64.b64decode(exchange["response"]["body_base64"])
            material[er["id"]] = {"event": a, "exchange": exchange, "body": body}
    dynamic, identities, facts, read_hidden = [], [], [], []
    for name, user in fixture["users"].items():
        catalog = [m for m in material.values() if m["exchange"]["request"]["url"] == fixture["origin"]+user["catalog"]]
        details = [(eid, m) for eid, m in material.items() if m["exchange"]["request"]["url"] == fixture["origin"]+user["detail"]]
        roots = [m for m in material.values() if m["exchange"]["request"]["url"] == fixture["origin"]+"/"]
        valid_dependency = False
        for _, detail in details:
            for cat in catalog:
                for root in roots:
                    root_call, cat_call, detail_call = (starts[m["event"]["call_id"]] for m in (root, cat, detail))
                    if (root["event"]["sequence"] < cat_call["sequence"] and cat["event"]["sequence"] < detail_call["sequence"]
                            and root_call["model_request_id"] != cat_call["model_request_id"] != detail_call["model_request_id"]
                            and user["catalog"].encode() in root["body"] and user["detail"].encode() in cat["body"]):
                        valid_dependency = True
        dynamic.append(valid_dependency)
        identities.append(bool(details) and all(m["exchange"]["request"]["identity"] == name and json.loads(m["body"])["subject"] == name for _, m in details))
        facts.append(any(user["code"] in o["data"]["statement"] and user["order"] in o["data"]["statement"] and name in o["data"]["statement"].lower()
                         and any(er["id"] in {eid for eid, _ in details} for er in o["data"]["evidence_refs"]) for o in final_observations))
        read_hidden.append(any(r["reply"]["evidence_ref"]["id"] in {eid for eid, _ in details} and user["code"] in r["reply"]["body_text"]
                               and user["code"] not in material[r["reply"]["evidence_ref"]["id"]]["event"]["reply"]["preview"]["body_text"]
                               and r["reply"]["target_requests"] == 0 for r in reads))
    network_ops = [r for r in records.values() if r["kind"] == "operation"]
    target_matches = len(fixture["receipts"]) == sum(r["data"]["usage"]["http_requests"] for r in network_ops)
    allowed = {"/"} | {v[k] for v in fixture["users"].values() for k in ("catalog", "detail")}
    no_bad_requests = all(r["path"] in allowed and r["status"] == 200 for r in fixture["receipts"])
    expected_visits = {(fixture["origin"]+"/", "anonymous")}
    expected_visits |= {(fixture["origin"]+u[k], name) for name, u in fixture["users"].items() for k in ("catalog", "detail")}
    visits = [(m["exchange"]["request"]["url"], m["exchange"]["request"]["identity"]) for m in material.values()]
    exact_visits = len(visits) == len(expected_visits) and set(visits) == expected_visits
    actual_receipts = [(fixture["origin"]+r["path"], r["subject"], r["status"]) for r in fixture["receipts"]]
    captured_receipts = [(m["exchange"]["request"]["url"], m["exchange"]["request"]["identity"], m["exchange"]["response"]["status"]) for m in material.values()]
    actual_model = [a for a in audit if a["kind"] == "model_start"]
    model_ends = [a for a in audit if a["kind"] == "model_end"]
    mode = status["run"]["spec"]["runtime_profile"]["mode"]
    checks = {"response_dependent_navigation": all(dynamic), "both_identities_verified_by_application": all(identities),
              "final_facts_link_to_correct_evidence": all(facts), "read_beyond_preview": all(read_hidden),
              "publish_then_continue_http": any(p["sequence"] < h["sequence"] for p in publish for h in http),
              "one_accepted_final": len(finals) == 1 and sum(r["data"]["state"] == "delivered" for r in records.values() if r["kind"] == "task") == 1,
              "offline_read_export": offline_read_passed, "target_receipts_match_operations": target_matches,
              "target_receipts_match_evidence": actual_receipts == captured_receipts, "no_unexplained_repeated_actions": exact_visits,
              "no_out_of_scope_or_wrong_identity": no_bad_requests,
              "no_unknown_operations": all(r["data"]["execution_state"] == "succeeded" for r in network_ops),
              "all_evidence_readable": all(r["data"]["availability"] == "ready" for r in records.values() if r["kind"] == "evidence"),
              "model_requests_accounted": bool(actual_model) and len(actual_model) == len(model_ends),
              "within_budgets": all(v <= status["run"]["spec"]["scheduling"]["per_task_budget"][k] for k, v in status["usage"]["charged_or_reserved"].items())}
    return {"reset_id": fixture["reset_id"], "run_id": run_id, "checks": checks, "passed": all(checks.values()),
            "mode": mode, "inference_tested": mode == "live" and bool(actual_model), "capability_tests_executed": False,
            "model_requests": len(actual_model), "target_requests": len(fixture["receipts"]), "evidence_reads": len(reads),
            "usage": status["usage"], "operation_refs": [ref(r) for r in network_ops],
            "evidence_refs": [ref(r) for r in records.values() if r["kind"] == "evidence"],
            "receipts": status["receipts"], "unknown_usage_requests": [a["request_id"] for a in model_ends if a.get("usage") is None]}
