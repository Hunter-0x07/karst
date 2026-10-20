"""Real text / single-tool / multi-tool round-trip checks, with separate accounting."""

import secrets

from karst.config import KarstError
from karst.errors import GatewayError
from karst.gateway import Gateway, load_gateway
from karst.protocol import append_tool_results
from karst.research import Host, obj
from karst.research_config import parse_launch, template
from karst.research_store import ResearchStore
from karst.store import host_lock

ECHO = [{"type": "function", "function": {"name": "protocol_echo", "description": "Protocol test only: return the specified value to the caller. No target access.",
           "parameters": obj({"value": {"type": "string"}})}}]
PROTOCOL_VERSION = "i0-gateway-check-v2"
TOOL_CHOICE_POLICY = {"single_tool": "required", "multi_tool": "auto", "result_replay": "none"}


def run_gateway_checks(config_path, data_dir, *, mode="live"):
    config = load_gateway(config_path)
    launch = parse_launch(template("http://127.0.0.1:1", "Gateway protocol checks only; no application requests.", mode=mode))
    with host_lock(data_dir), ResearchStore(data_dir) as store:
        if store.db.execute("SELECT 1 FROM records LIMIT 1").fetchone():
            raise KarstError("gateway checks require a new directory")
        h = Host(launch, store, {})
        gateway = Gateway(config, store, h.run_id, h.budget, h.deadline, check=h.guard)
        checks, error = {}, None
        try:
            nonce = secrets.token_hex(8)
            reply = gateway.generate([{"role": "user", "content": "Reply with this exact text and no other content: "+nonce}])
            checks["text"] = reply.text.strip() == nonce and not reply.tool_calls
            if not checks["text"]:
                raise KarstError("text protocol check failed")
            for count, name in ((1, "single_tool"), (2, "multi_tool")):
                values = [secrets.token_hex(8) for _ in range(count)]
                messages = [{"role": "user", "content": "In ONE response call protocol_echo exactly "+str(count)+
                             " time(s), once for EACH of these values: "+", ".join(values)+
                             ". After receiving the tool results, reply with every returned receipt string."}]
                # Check concurrent calls in the mode used by the research loop.
                # Some providers constrain `required` to a single call. `auto`
                # does not relax the exact count, values or receipt checks below.
                reply = gateway.generate(messages, ECHO, tool_choice=TOOL_CHOICE_POLICY[name])
                valid = (len(reply.tool_calls) == count and all(c.name == "protocol_echo" and set(c.arguments) == {"value"}
                         and isinstance(c.arguments["value"], str) for c in reply.tool_calls)
                         and sorted(c.arguments["value"] for c in reply.tool_calls) == sorted(values))
                if not valid:
                    checks[name] = False
                    raise KarstError(name+" call check failed")
                receipts = {c.id: {"receipt": "receipt-"+secrets.token_hex(12)} for c in reply.tool_calls}
                messages = append_tool_results(messages, reply, receipts)
                answer = gateway.generate(messages, ECHO, tool_choice=TOOL_CHOICE_POLICY["result_replay"])
                checks[name] = not answer.tool_calls and all(v["receipt"] in answer.text for v in receipts.values())
                if not checks[name]:
                    raise KarstError(name+" result replay check failed")
        except (KarstError, GatewayError, OSError) as exc:
            error = str(exc) if isinstance(exc, (KarstError, GatewayError)) else type(exc).__name__
        finally:
            h.finish("unrecoverable_error" if error else "frontier_exhausted", error or "gateway protocol checks completed")
        audit = store.audits(h.run_id)
        return {"run_id": h.run_id, "mode": mode, "protocol_version": PROTOCOL_VERSION,
                "tool_choice_policy": dict(TOOL_CHOICE_POLICY), "passed": checks == {"text": True, "single_tool": True, "multi_tool": True},
                "checks": checks, "error": error, "inference_tested": mode == "live" and any(a["kind"] == "model_end" and a["status"] == "succeeded" for a in audit),
                "model_requests": sum(a["kind"] == "model_start" for a in audit), "usage": store.usage(h.run_id),
                "capability_tests_executed": False}
