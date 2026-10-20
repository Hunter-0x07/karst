"""Explicit deterministic model substitute. Reads only ordinary model/tool messages."""

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading


def observation(statement, evidence, key="obs"):
    return {"summary": statement, "outcome": "progress", "proposed_records": [{"local_ref": key, "kind": "observation",
            "data": {"statement": statement, "evidence_refs": evidence, "subject_refs": [], "conditions": [],
                     "provenance": "agent_interpreted", "contradicts_refs": []}}], "suggested_opportunities": []}


def tool_reply(calls=None, content=None, *, finish=None, usage=True):
    message = {"role": "assistant", "content": content}
    if calls:
        message["tool_calls"] = [{"id": cid, "type": "function", "function": {"name": name, "arguments": json.dumps(args)}} for cid, name, args in calls]
    result = {"id": "test-provider-response", "model": "fixture-model", "choices": [{"message": message, "finish_reason": finish or ("tool_calls" if calls else "stop")}]}
    if usage:
        result["usage"] = {"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150}
    return result


def business_model(payload, *, publish_late=False):
    user = json.loads(payload["messages"][1]["content"])
    identities = {i["label"]: i["identity_ref"] for i in user["identities"]}
    origin = user["entrypoints"][0].rstrip("/")
    results = {m["tool_call_id"]: json.loads(m["content"]) for m in payload["messages"] if m["role"] == "tool"}
    if "entry" not in results:
        return tool_reply([("entry", "http_request", {"url": origin+"/", "identity_ref": None, "query": []})])
    entry = results["entry"]
    root = json.loads(entry["preview"]["body_text"])
    for name in ("alice", "bob"):
        if "catalog-"+name not in results:
            return tool_reply([("catalog-"+name, "http_request", {"url": origin+root["catalogs"][name], "identity_ref": identities[name], "query": []})])
        if "detail-"+name not in results:
            detail = json.loads(results["catalog-"+name]["preview"]["body_text"])["detail"]
            return tool_reply([("detail-"+name, "http_request", {"url": origin+detail, "identity_ref": identities[name], "query": []})])
        if "read-"+name not in results:
            return tool_reply([("read-"+name, "evidence_read", {"evidence_ref": results["detail-"+name]["evidence_refs"][0], "offset": 0, "length": 8192})])
        if "publish" not in results and (name == "bob" if publish_late else name == "alice"):
            body = json.loads(results["read-alice"]["body_text"])
            return tool_reply([("publish", "publish_research", observation(
                "alice order="+body["order"]+" reconciliation_code="+body["reconciliation_code"], results["detail-alice"]["evidence_refs"]))])
        if "publish" in results and results["publish"].get("status") != "accepted":
            raise AssertionError("The simulated model requires an accepted checkpoint before continuing")
    final = observation("Completed both user order checks.", entry["evidence_refs"])
    final["proposed_records"] = []
    for name in ("alice", "bob"):
        body = json.loads(results["read-"+name]["body_text"])
        final["proposed_records"] += observation(name+" order="+body["order"]+" reconciliation_code="+body["reconciliation_code"],
                                                   results["detail-"+name]["evidence_refs"], name)["proposed_records"]
    return tool_reply([("final", "submit_result", final)])


@contextmanager
def model_server(responder=business_model):
    requests = []
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass
        def do_GET(self):
            raw = b'{"data":[{"id":"fixture-model"}]}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
        def do_POST(self):
            payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            requests.append(payload)
            reply = responder(payload)
            status = 200
            if isinstance(reply, tuple):
                status, reply = reply
            raw = reply if isinstance(reply, bytes) else json.dumps(reply).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            try:
                self.wfile.write(raw)
            except OSError:
                pass
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield {"api_base": "http://127.0.0.1:"+str(server.server_port)+"/v1", "model": "fixture-model", "max_tokens": 4096,
               "max_tokens_field": "max_tokens", "timeout_seconds": 10, "connect_timeout_seconds": 2,
               "max_retries": 1, "retry_backoff_seconds": 1, "max_response_bytes": 2000000, "temperature": None, "trust_env": False}, requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
