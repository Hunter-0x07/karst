"""Application services shared by the CLI and future adapters."""

import json
import os
from pathlib import Path
import re
import sqlite3

from karst import __version__
from karst.config import KarstError, load_config
from karst.execution import HttpExecutor
from karst.store import Store, host_lock, new_id, utcnow


def credential_values(config):
    result = {}
    for identity in config.identities:
        value = os.environ.get(identity.bearer_env, "")
        if not re.fullmatch(r"[A-Za-z0-9._~+/=-]{1,8192}", value):
            raise KarstError(f"missing or invalid credential environment variable: {identity.bearer_env}")
        result[identity.name] = value
    return result


def doctor(config_path):
    config = load_config(config_path)
    credential_values(config)
    return {"ready": True, "version": __version__, "profile": config.profile,
            "checks": ["strict_config", "entrypoint_scope", "identity_references"],
            "network_checked": False, "supported": ["HTTP GET probe", "persistent evidence"],
            "unsupported": ["autonomous research", "vulnerability verification", "browser", "scripts", "host permissions"],
            "notice": "Configuration readiness only; reachability and authentication are not yet verified."}


def probe(config_path, data_dir):
    config = load_config(config_path)
    secrets = credential_values(config)
    with host_lock(data_dir), Store(data_dir) as store:
        if store.unfinished():
            raise KarstError("unfinished run exists; use reconcile before starting a new probe")
        run_id = new_id("run")
        data = {"state": "running", "stop_reason": None, "started_at": utcnow(), "ended_at": None,
                "profile": config.profile, "config": config.snapshot(), "build_version": __version__,
                "requests": 0, "response_bytes": 0, "capability": "HTTP integration only"}
        run = store.put("run", run_id, run_id, data)
        executor = HttpExecutor(config, store, run_id, secrets)
        reason = "probe_finished"
        halt = False
        try:
            for url in config.entrypoints:
                origin = config.check_url(url)[1]
                identities = [None] + [i for i in config.identities if i.origin == origin]
                for identity in identities:
                    op = executor.request(url, identity)
                    error = op["data"]["error"]
                    if error:
                        reason = "probe_incomplete"
                        if error["code"] == "budget_exhausted":
                            reason = "budget_exhausted"
                            break
                        if op["data"]["execution_state"] == "unknown" or error["code"] == "evidence_save_failed":
                            halt = True
                            break
                if halt or reason == "budget_exhausted":
                    break
        except KeyboardInterrupt:
            reason = "user_pause"
        except (KarstError, OSError, sqlite3.Error):
            reason = "unrecoverable_error"
            raise
        finally:
            data.update(state="paused" if reason == "user_pause" else "stopped",
                        stop_reason=reason, ended_at=utcnow(), requests=executor.requests,
                        response_bytes=executor.response_bytes)
            store.put("run", run_id, run_id, data, expected_version=run["version"])
        return summary(store.status(run_id))


def summary(status):
    return {"run_id": status["run_id"], "state": status["run"]["state"],
            "stop_reason": status["run"]["stop_reason"], "requests": status["run"]["requests"],
            "response_bytes": status["run"]["response_bytes"],
            "operations": status["operations"], "evidence": status["evidence"],
            "findings": [], "capability_status": status["capability_status"]}


def status(data_dir, run_id):
    with Store(data_dir, readonly=True) as store:
        store.db.execute("BEGIN")
        return summary(store.status(run_id))


def read_evidence(data_dir, run_id, evidence_id):
    with Store(data_dir, readonly=True) as store:
        return store.evidence_bytes(evidence_id, run_id=run_id)


def list_runs(data_dir):
    with Store(data_dir, readonly=True) as store:
        return {"runs": [{"run_id": r["id"], "state": r["data"]["state"],
                          "stop_reason": r["data"].get("stop_reason"), "created_at": r["created_at"]}
                         for r in store.runs()]}


def reconcile(data_dir, run_id):
    """Conservatively account for interruptions; never replay target requests."""
    with host_lock(data_dir), Store(data_dir) as store:
        run = store.get(run_id, run_id=run_id)
        pending = store.records(run_id, "operation")
        if run["kind"] != "run" or (run["data"]["state"] not in ("running", "paused")
                                     and not any(op["data"]["execution_state"] == "running" for op in pending)):
            raise KarstError("run does not require reconciliation")
        for op in pending:
            if op["data"]["execution_state"] == "running":
                data = dict(op["data"])
                data.update(execution_state="unknown", ended_at=utcnow(),
                            error={"code": "interrupted_process", "retry_policy": "inspect_first"})
                store.put("operation", op["id"], run_id, data, expected_version=op["version"])
        data = dict(run["data"])
        operations = store.records(run_id, "operation")
        data.update(state="stopped", stop_reason="interrupted_requires_inspection", ended_at=utcnow(),
                    requests=sum(op["data"]["execution_state"] != "not_executed" for op in operations),
                    response_bytes=sum(op["data"]["response_bytes"] for op in operations))
        store.put("run", run_id, run_id, data, expected_version=run["version"])
        return summary(store.status(run_id))


def export(data_dir, run_id, output):
    result = status(data_dir, run_id)
    destination = Path(output).resolve()
    if destination == Path(data_dir).resolve() or destination in Path(data_dir).resolve().parents:
        raise KarstError("export destination must be a separate new directory")
    try:
        destination.mkdir(parents=True, exist_ok=False)
    except FileExistsError as exc:
        raise KarstError("export directory already exists; choose a new directory") from exc
    # No response bodies, request URLs, authorization values or config snapshots are exported.
    payload = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    (destination / "run.json").write_text(payload, encoding="utf-8")
    lines = ["# Karst HTTP 集成记录", "", f"Run: `{run_id}`", "",
             f"状态：{result['state']}；停止原因：{result['stop_reason']}。", "",
             "本次只执行明确配置入口的 HTTP GET 与身份隔离留证，不包含模型研究、漏洞核验或权限提升。",
             "没有 Findings 表示尚未进行漏洞研究，不能解释为目标安全。", "",
             f"请求次数：{result['requests']}；采集响应正文：{result['response_bytes']} bytes。", "",
             "| 操作 | 身份 | 执行状态 | HTTP | 证据条数 |", "|---|---|---|---|---|"]
    for op in result["operations"]:
        lines.append(f"| {op['id']} | {op['identity']} | {op['execution_state']} | {op['http_status']} | {len(op['evidence_refs'])} |")
    lines += ["", "响应原件保留在本地受控数据目录，导出只含元数据。", ""]
    (destination / "report.md").write_text("\n".join(lines), encoding="utf-8")
    return {"run_id": run_id, "output": str(destination), "files": ["run.json", "report.md"]}
