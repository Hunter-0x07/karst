"""Freeze a clean SHA, run development checks and live I0 acceptance, retain all failures."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/"src"))
from karst.config import KarstError
from karst.gateway import load_gateway
from karst.research import PROMPT_VERSION, SYSTEM, TOOL_DEFINITIONS
from karst.gateway_checks import PROTOCOL_VERSION, TOOL_CHOICE_POLICY
from karst.i0_fixture import BRIEFING, BRIEFING_VERSION
from karst.research_config import template
from karst.store import encoded


def now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--gateway", default="config/examples/gateway.json")
    parser.add_argument("--role", choices=("runtime", "development"), default="runtime")
    parser.add_argument("--git", default="git")
    args = parser.parse_args()
    if sys.version_info[:2] != (3, 12) or not re.fullmatch("[0-9a-f]{40}", args.expected_commit):
        parser.error("Python 3.12 and a full 40-character frozen SHA are required")

    def git(*parts):
        p = subprocess.run([args.git, "-c", "safe.directory="+ROOT.as_posix(), "-C", str(ROOT), *parts], capture_output=True, timeout=30)
        if p.returncode:
            raise KarstError("Git metadata unavailable")
        return p.stdout.decode("utf-8").strip()

    try:
        commit = git("rev-parse", "HEAD")
        if commit != args.expected_commit or git("status", "--porcelain"):
            raise KarstError("use a clean checkout of the exact delivered SHA")
        gateway = Path(args.gateway).resolve()
        cfg = load_gateway(gateway)
        output = Path(args.output).resolve()
        if output == ROOT or ROOT in output.parents:
            raise KarstError("output must be outside the checkout")
        output.mkdir(parents=True, exist_ok=False)
    except (KarstError, OSError, subprocess.SubprocessError) as exc:
        print(json.dumps({"error": str(exc) if isinstance(exc, KarstError) else type(exc).__name__}))
        return 2
    share, private = output/"feedback", output/"private"
    share.mkdir()
    private.mkdir()
    # Freeze the exact model settings once for listing, protocol checks and all resets.
    # Authentication remains an environment binding and is never copied into this file.
    gateway_bytes = gateway.read_bytes()
    gateway = private/"gateway-config.json"
    gateway.write_bytes(gateway_bytes)
    cfg = load_gateway(gateway)
    started = now()
    commands = []
    environment = dict(os.environ, PYTHONIOENCODING="utf-8")

    def clean(raw):
        value = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else raw
        replacements = [(str(ROOT), "<REPO>"), (str(output), "<OUTPUT>"), (str(gateway), "<GATEWAY_CONFIG>"),
                        (str(Path.home()), "<HOME>"), (tempfile.gettempdir(), "<TEMP>"), (sys.executable, "<PYTHON>")]
        for old, new in sorted(replacements, key=lambda p: len(p[0]), reverse=True):
            value = value.replace(json.dumps(old)[1:-1], new).replace(old, new).replace(old.replace("\\", "/"), new)
        key = os.environ.get("TESTER_API_KEY")
        if key:
            value = value.replace(key, "[REDACTED]")
        return value

    def save(name, value):
        (share/name).write_text(clean(json.dumps(value, ensure_ascii=False, indent=2))+"\n", encoding="utf-8", newline="\n")

    def execute(label, command, timeout):
        begin = time.monotonic()
        try:
            p = subprocess.run([sys.executable, *command], cwd=ROOT, capture_output=True, timeout=timeout, env=environment)
            code, stdout, stderr = p.returncode, p.stdout, p.stderr
        except subprocess.TimeoutExpired as exc:
            code, stdout, stderr = 124, exc.stdout or b"", exc.stderr or b""
        log = clean(stdout+stderr)
        (share/(label+".txt")).write_text(log, encoding="utf-8", newline="\n")
        info = {"stage": label, "command": ["<PYTHON>", *[clean(str(v)) for v in command]], "exit_code": code,
                "elapsed_seconds": round(time.monotonic()-begin, 3)}
        commands.append(info)
        return info, log

    result = {"technical_pass": False, "human_acceptance": "pending", "inference_tested": False,
              "capability_tests_executed": False, "gateway": None, "batch": None, "error": None}
    try:
        unit, unitlog = execute("unittest", ["-m", "unittest", "discover", "-s", "tests", "-t", ".", "-v"], 240)
        count = re.search(r"Ran (\d+) tests?", unitlog)
        unit.update(tests=int(count[1]) if count else None, passed=unit["exit_code"] == 0 and bool(count) and int(count[1]) > 0 and unitlog.rstrip().endswith("OK"))
        result["unit"] = unit
        if unit["passed"]:
            listing, _ = execute("model-list", ["scripts/check_model.py", "--config", str(gateway)], 30)
            if listing["exit_code"] == 0:
                protocol, log = execute("gateway", ["scripts/check_gateway.py", "--config", str(gateway), "--output", str(private/"gateway")], 930)
                try:
                    result["gateway"] = json.loads(log)
                except ValueError:
                    result["error"] = "gateway diagnostic did not produce valid summary"
                result["inference_tested"] = bool((result["gateway"] or {}).get("inference_tested"))
                if protocol["exit_code"] == 0 and result["gateway"] and result["gateway"].get("passed"):
                    batch_cmd, _ = execute("batch", ["scripts/run_i0_batch.py", "--gateway", str(gateway), "--output", str(private/"batch")], 2850)
                    summary_path = private/"batch/batch-summary.json"
                    if summary_path.is_file():
                        result["batch"] = json.loads(summary_path.read_text(encoding="utf-8"))
                        result["inference_tested"] |= result["batch"]["inference_tested"]
                    result["technical_pass"] = bool(batch_cmd["exit_code"] == 0 and result["batch"] and result["batch"]["mode"] == "live"
                                                    and result["batch"]["technical_pass"] and len(result["batch"]["runs"]) == 3)
            else:
                result["error"] = "model listing unavailable; live protocol and batch not executed"
        else:
            result["error"] = "development checks failed; live protocol and batch not executed"
    except KeyboardInterrupt:
        result["error"] = "user_cancelled"
    except (KarstError, OSError, ValueError, subprocess.SubprocessError) as exc:
        result["error"] = str(exc) if isinstance(exc, KarstError) else type(exc).__name__
    finally:
        try:
            after = git("rev-parse", "HEAD")
            dirty = bool(git("status", "--porcelain"))
        except (KarstError, subprocess.SubprocessError):
            after, dirty = None, True
        result["technical_pass"] = result["technical_pass"] and after == commit and not dirty
        save("result.json", result)
        save("environment.json", {"declared_role": args.role, "python": platform.python_version(), "system": platform.system(),
            "architecture": platform.machine(), "tested_commit": commit, "commit_after": after,
            "working_tree_dirty_before": False, "working_tree_dirty_after": dirty, "started_at": started, "finished_at": now(),
            "runtime_dependencies": [], "gateway_config_sha256": hashlib.sha256(gateway.read_bytes()).hexdigest(),
            "model": cfg["model"], "gateway_settings": {k: v for k, v in cfg.items() if k != "api_base"},
            "prompt_version": PROMPT_VERSION, "tools_sha256": hashlib.sha256(encoded(TOOL_DEFINITIONS)).hexdigest(),
            "system_prompt_sha256": hashlib.sha256(SYSTEM.encode("utf-8")).hexdigest(),
            "briefing_version": BRIEFING_VERSION, "briefing_sha256": hashlib.sha256(BRIEFING.encode("utf-8")).hexdigest(),
            "gateway_check_version": PROTOCOL_VERSION, "gateway_tool_choice_policy": TOOL_CHOICE_POLICY,
            "per_run_budget": template("http://127.0.0.1:1", "budget snapshot")["spec"]["budget"],
            "batch_runs": 3, "gateway_check_budget_is_separate": True, "human_acceptance": "pending"})
        save("commands.json", commands)
        source = {}
        for name in git("ls-files").splitlines():
            path = ROOT/name
            if path.is_file() and (name.startswith(("src/", "scripts/", "tests/", "config/", "knowledge/")) or name == "pyproject.toml"):
                source[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        private_hashes = {p.relative_to(private).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(private.rglob("*")) if p.is_file()}
        save("manifest.json", {"tested_commit": commit, "source_sha256": source, "private_files_sha256": private_hashes,
                               "shared_files_sha256": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(share.iterdir()) if p.is_file()}})
    print(json.dumps({"technical_pass": result["technical_pass"], "inference_tested": result["inference_tested"],
                      "human_acceptance": "pending", "feedback_directory": str(share)}, ensure_ascii=True, indent=2))
    return 0 if result["technical_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
