"""Frozen I0 launch bindings. Stored RunSpec uses karst-design/1 without additions."""

from copy import deepcopy
from dataclasses import dataclass
import ipaddress
from pathlib import Path
from urllib.parse import urlsplit

from karst.config import KarstError, exact, parse_config, parse_url, positive, strict_json

TOOLS = {"http_request": "http.request", "evidence_read": "evidence.read",
         "document_inspect": "document.inspect",
         "session_inspect": "session.inspect", "state_query": "state.query",
         "publish_research": "research.publish", "submit_result": "research.submit_result"}
BUDGET_KEYS = "model_requests input_tokens output_tokens http_requests network_connections network_bytes tool_starts wall_seconds cost_limit".split()
PROFILE = {"mode": "live", "model_config_ref": "config:i0-gateway-v1",
           "tool_profile_ref": "registry:i0-get-v1", "support_matrix_ref": "support:i0-v1",
           "dependency_lock_ref": "lock:stdlib-3.12-v1", "policy_version": "i0-v1"}
RESEARCH_PROFILE = dict(PROFILE, tool_profile_ref="registry:research-get-v1",
                        support_matrix_ref="support:research-v1", policy_version="research-v1")
PRODUCT_PROFILE = dict(RESEARCH_PROFILE, tool_profile_ref="registry:product-get-v5",
                       support_matrix_ref="support:product-v1", policy_version="product-v2", model_config_ref="config:product-gateway-v1")
EXECUTION = {"allowed_cidrs": ["127.0.0.1/32"], "denied_cidrs": [], "http_timeout_seconds": 10,
             "max_response_bytes": 65536, "max_redirects": 2, "preview_bytes": 768,
             "max_read_bytes": 8192, "max_total_read_bytes": 131072}


def text(value, maximum=8192):
    if not isinstance(value, str) or not value.strip() or len(value.encode("utf-8")) > maximum:
        raise KarstError("invalid bounded text")
    return value


def template(origin, briefing, *, mode="live"):
    """Runnable normal-business launch. The fixture supplies a fresh origin per reset."""
    host, port = parse_url(origin)[2:4]
    budget = dict(model_requests=12, input_tokens=1000000, output_tokens=49152, http_requests=30,
                  network_connections=30, network_bytes=268435456, tool_starts=60, wall_seconds=900, cost_limit=None)
    spec = {"entrypoints": [origin + "/"],
            "scope": {"web_origins": [{"origin": origin, "path_prefixes": ["/"]}],
                      "network_targets": [{"host": host, "ports": [port], "protocols": [urlsplit(origin).scheme],
                                           "vantage_keys": ["workstation"]}], "denied_targets": [], "default_action": "deny"},
            "identity_refs": [],
            "objectives": {"discover_security_issues": False, "investigate_further": False, "depth_goals": []},
            "policy": {"allowed_impacts": ["observe", "read_authorized_data"], "unknown_impact": "classify_or_deny",
                       "identity_policy": {"allowed_identity_refs": [], "auth_modes": ["managed", "anonymous"]},
                       "tool_profile_ref": PROFILE["tool_profile_ref"],
                       "network": {"egress_profile_ref": "egress:i0-launch-v1", "requests_per_second": 2, "max_connections": 1},
                       "mutation_policy": {"shared_writes": "exclusive", "test_resources_only": True},
                       "cleanup": {"enabled": False, "allowed_impacts": [], "reserved_seconds": 0, "reserved_tool_starts": 0}},
            "budget": budget,
            "scheduling": {"max_workers": 1, "max_ready": 1, "max_same_lane": 1, "aging_rounds": 1,
                           "max_attempts_per_fingerprint": 1, "max_corrections": 2, "per_task_budget": deepcopy(budget)},
            "stop_policy": {"stop_on_goal": False, "coverage_contract": None, "user_stop_conditions": []},
            "initial_context_refs": [], "runtime_profile": dict(PROFILE, mode=mode)}
    return {"schema_version": "karst-i0-launch/1", "briefing": briefing, "spec": spec,
            "identities": [{"name": n, "origin": origin, "bearer_env": "KARST_I0_" + n.upper()} for n in ("alice", "bob")],
            "execution": deepcopy(EXECUTION)}


@dataclass
class Launch:
    spec: dict
    briefing: str
    transport: object
    execution: dict
    research: bool = False
    product: bool = False


def research_template(origin, briefing, *, mode="live"):
    """Method-guided research with a bounded, serial opportunity frontier."""
    value = template(origin, briefing, mode=mode)
    value["schema_version"] = "karst-research-launch/1"
    spec = value["spec"]
    spec["runtime_profile"] = dict(RESEARCH_PROFILE, mode=mode)
    spec["policy"]["tool_profile_ref"] = RESEARCH_PROFILE["tool_profile_ref"]
    spec["objectives"]["investigate_further"] = True
    spec["scheduling"].update(max_ready=8, max_same_lane=3, aging_rounds=4)
    for key in BUDGET_KEYS[:-1]:
        spec["budget"][key] *= 3
    return value


def product_template(origin, briefing, *, mode="live"):
    value = research_template(origin, briefing, mode=mode)
    value["schema_version"] = "karst-product-launch/1"
    spec = value["spec"]
    spec["runtime_profile"] = dict(PRODUCT_PROFILE, mode=mode)
    spec["policy"]["tool_profile_ref"] = PRODUCT_PROFILE["tool_profile_ref"]
    spec["objectives"]["discover_security_issues"] = True
    # A separate, explicit product budget includes independent verification.
    for key in BUDGET_KEYS[:-1]:
        spec["budget"][key] = min(spec["budget"][key]*2, 3600 if key == "wall_seconds" else 2**31-1)
    return value


class ScopedTransport:
    def __init__(self, transport, scope):
        self.inner, self.scope = transport, scope

    def __getattr__(self, key):
        return getattr(self.inner, key)

    def check_url(self, url):
        parsed = self.inner.check_url(url)
        _, origin, host, port, path = parsed
        for item in self.scope["denied_targets"]:
            kind, value = item["selector_type"], item["value"]
            if ((kind == "origin" and origin == value) or (kind == "host" and host == value)
                    or (kind == "path_prefix" and origin == value["origin"]
                        and (value["path_prefix"] == "/" or path == value["path_prefix"] or path.startswith(value["path_prefix"] + "/")))):
                raise KarstError("scope_denied")
        if not any(item["host"] == host and port in item["ports"] and urlsplit(origin).scheme in item["protocols"]
                   for item in self.scope["network_targets"]):
            raise KarstError("network_target_denied")
        return parsed


def load_launch(path):
    return parse_launch(strict_json(Path(path).read_text(encoding="utf-8")))


def parse_launch(value):
    try:
        return _parse_launch(value)
    except (TypeError, ValueError, KeyError, UnicodeError) as exc:
        raise KarstError("invalid I0 launch structure or value") from exc


def _parse_launch(value):
    value = deepcopy(value)
    exact(value, ["schema_version", "briefing", "spec", "identities", "execution"])
    product = value["schema_version"] == "karst-product-launch/1"
    research = product or value["schema_version"] == "karst-research-launch/1"
    if value["schema_version"] not in ("karst-i0-launch/1", "karst-research-launch/1", "karst-product-launch/1"):
        raise KarstError("unsupported launch schema")
    briefing = text(value["briefing"])
    s, e = value["spec"], value["execution"]
    exact(s, ["entrypoints", "scope", "identity_refs", "objectives", "policy", "budget", "scheduling", "stop_policy", "initial_context_refs", "runtime_profile"])
    if s["identity_refs"] != [] or s["initial_context_refs"] != []:
        raise KarstError("I0 launch binds new identities internally; pre-existing references unsupported")
    if s["objectives"] != {"discover_security_issues": product, "investigate_further": research, "depth_goals": []}:
        raise KarstError("unsupported research/capability objectives in I0 normal-business slice")
    if s["stop_policy"] != {"stop_on_goal": False, "coverage_contract": None, "user_stop_conditions": []}:
        raise KarstError("unsupported goal/coverage stop contract")
    profile = s["runtime_profile"]
    exact(profile, PROFILE)
    registered = PRODUCT_PROFILE if product else RESEARCH_PROFILE if research else PROFILE
    if profile["mode"] not in ("live", "mock") or any(profile[k] != v for k, v in registered.items() if k != "mode"):
        raise KarstError("unregistered runtime profile")
    schedule = s["scheduling"]
    exact(schedule, ["max_workers", "max_ready", "max_same_lane", "aging_rounds", "max_attempts_per_fingerprint", "max_corrections", "per_task_budget"])
    for key in ("max_workers", "max_attempts_per_fingerprint") + (() if research else ("max_ready", "max_same_lane", "aging_rounds")):
        if type(schedule[key]) is not int or schedule[key] != 1:
            raise KarstError("I0 supports one task and one attempt; opportunity scheduling unsupported")
    for key in ("max_ready", "max_same_lane", "aging_rounds"):
        positive(schedule[key], 32)
    positive(schedule["max_corrections"], 5)
    for b in (s["budget"], schedule["per_task_budget"]):
        exact(b, BUDGET_KEYS)
        if b["cost_limit"] is not None:
            raise KarstError("priced cost ceilings unsupported; use explicit request/token/time ceilings")
        for k in BUDGET_KEYS[:-1]:
            positive(b[k], {"wall_seconds": 3600, "model_requests": 100, "http_requests": 1000,
                            "tool_starts": 1000}.get(k, 2**31 - 1))
            if b[k] > s["budget"][k]:
                raise KarstError("task allocation exceeds Run budget")
    p = s["policy"]
    exact(p, ["allowed_impacts", "unknown_impact", "identity_policy", "tool_profile_ref", "network", "mutation_policy", "cleanup"])
    if p["allowed_impacts"] != ["observe", "read_authorized_data"] or p["unknown_impact"] != "classify_or_deny":
        raise KarstError("unsupported impact policy")
    if p["identity_policy"] != {"allowed_identity_refs": [], "auth_modes": ["managed", "anonymous"]}:
        raise KarstError("unsupported identity policy")
    if p["tool_profile_ref"] != registered["tool_profile_ref"] or p["mutation_policy"] != {"shared_writes": "exclusive", "test_resources_only": True}:
        raise KarstError("unsupported tool/mutation policy")
    if p["cleanup"] != {"enabled": False, "allowed_impacts": [], "reserved_seconds": 0, "reserved_tool_starts": 0}:
        raise KarstError("cleanup actions unsupported")
    exact(p["network"], ["egress_profile_ref", "requests_per_second", "max_connections"])
    if p["network"]["egress_profile_ref"] != "egress:i0-launch-v1" or p["network"]["max_connections"] != 1:
        raise KarstError("unsupported egress or concurrency")
    positive(p["network"]["requests_per_second"], 10)
    scope = s["scope"]
    exact(scope, ["web_origins", "network_targets", "denied_targets", "default_action"])
    if scope["default_action"] != "deny" or not isinstance(scope["network_targets"], list) or not 1 <= len(scope["network_targets"]) <= 32:
        raise KarstError("invalid explicit network targets")
    for target in scope["network_targets"]:
        exact(target, ["host", "ports", "protocols", "vantage_keys"])
        text(target["host"], 255)
        if not isinstance(target["ports"], list) or not 1 <= len(target["ports"]) <= 32:
            raise KarstError("invalid network ports")
        for port in target["ports"]:
            positive(port, 65535)
        if target["protocols"] not in (["http"], ["https"], ["http", "https"]) or target["vantage_keys"] != ["workstation"]:
            raise KarstError("unsupported network protocol or vantage")
    if not isinstance(scope["denied_targets"], list) or len(scope["denied_targets"]) > 64:
        raise KarstError("invalid deny list")
    exact(e, EXECUTION)
    for k in ("preview_bytes", "max_read_bytes", "max_total_read_bytes"):
        positive(e[k], {"preview_bytes": 4096, "max_read_bytes": 16384, "max_total_read_bytes": 1048576}[k])
    if e["preview_bytes"] >= e["max_read_bytes"] or e["max_read_bytes"] > e["max_total_read_bytes"]:
        raise KarstError("invalid evidence read limits")
    denied = list(e["denied_cidrs"])
    for item in scope["denied_targets"]:
        exact(item, ["selector_type", "value", "reason"])
        text(item["reason"])
        k, v = item["selector_type"], item["value"]
        if k == "cidr":
            denied.append(str(ipaddress.ip_network(v, strict=True)))
        elif k == "path_prefix":
            exact(v, ["origin", "path_prefix"])
            if parse_url(v["origin"] + v["path_prefix"])[4] != v["path_prefix"]:
                raise KarstError("invalid denied path")
        elif k in ("origin", "host"):
            text(v)
        else:
            raise KarstError("unsupported deny selector")
    b = schedule["per_task_budget"]
    transport = parse_config({"profile": "karst-http-probe/1", "entrypoints": s["entrypoints"],
                              "origins": scope["web_origins"], "allowed_cidrs": e["allowed_cidrs"], "denied_cidrs": denied,
                              "identities": value["identities"], "limits": {
                                  "max_requests": min(b["http_requests"], b["network_connections"]),
                                  "max_response_bytes": e["max_response_bytes"], "max_total_response_bytes": min(64*1024*1024, b["network_bytes"]),
                                  "timeout_seconds": e["http_timeout_seconds"], "wall_seconds": b["wall_seconds"], "max_redirects": e["max_redirects"]}})
    transport = ScopedTransport(transport, scope)
    for url in s["entrypoints"]:
        transport.check_url(url)
    return Launch(s, briefing, transport, e, research, product)
