"""HTML link/GET-form research, with a new CLI process at every task boundary."""

import argparse
from collections import Counter
from contextlib import nullcontext
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT/"src"), str(ROOT)]

from karst.product_fixture import BRIEFING, SCENARIOS, application_fixture, score_html
from karst.gateway import load_gateway
from karst.research_config import product_template
from karst.research_store import ResearchStore


def save(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2)+"\n", encoding="utf-8", newline="\n")


def cli(folder, name, args):
    command = [sys.executable, str(ROOT/"scripts/karst.py"), *args]
    child = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=4000,
                           env=dict(os.environ, PYTHONIOENCODING="utf-8"))
    (folder/(name+".stdout.json")).write_bytes(child.stdout)
    (folder/(name+".stderr.txt")).write_bytes(child.stderr)
    save(folder/(name+".process.json"), {"command": command, "exit_code": child.returncode})
    if child.returncode != 0:
        raise RuntimeError(name+" failed with exit code "+str(child.returncode))
    return json.loads(child.stdout)


def batch(gateway, output, *, repeats=3, mock=False):
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    dirty = bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT))
    if not mock and dirty:
        raise RuntimeError("live HTML acceptance requires a clean frozen source revision")
    scores = []
    gateway_config = load_gateway(gateway)
    save(output/"gateway.json", gateway_config)
    # The protocol and thresholds are retained before the first model request.
    save(output/"protocol.json", {"version": "html-recovery-acceptance-v1", "source_revision": revision,
        "source_dirty": dirty, "mode": "mock" if mock else "live", "repeats": repeats,
        "scorer_version": "product-html-score-v1", "pause_after_tasks": 1,
        "between_reset_quiet_seconds": gateway_config["min_request_interval_seconds"],
        "variants": ["links", "form", "form"], "scenarios": list(SCENARIOS),
        "criteria": "All engineering checks; P1/P2 >=2 of 3, P3/P4 all 3. Fewer resets are development only.",
        "source_sha256": {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                          for p in sorted([*(ROOT/"src/karst").glob("*.py"), *(ROOT/"src/karst/methods").glob("*.json"), Path(__file__)])}})
    for scenario in SCENARIOS:
        for index in range(repeats):
            # Gateway pacing is local to each Run. A new reset must also wait
            # after the previous CLI process finished all model requests.
            if scores:
                time.sleep(gateway_config["min_request_interval_seconds"])
            folder = output/(scenario+"-reset-"+str(index+1))
            folder.mkdir()
            variant = ("links", "form", "form")[index]
            print(json.dumps({"event": "start", "scenario": scenario, "reset": index+1, "navigation": variant}), flush=True)
            try:
                with application_fixture(scenario, navigation=variant) as fixture:
                    env_before = {"KARST_I0_"+n.upper(): os.environ.get("KARST_I0_"+n.upper()) for n in fixture["tokens"]}
                    try:
                        for name, token in fixture["tokens"].items():
                            os.environ["KARST_I0_"+name.upper()] = token
                        # CLI uses actual HTTP in both modes. In mock mode the model
                        # server is explicitly a deterministic development substitute.
                        launch_path = folder/"launch.json"
                        save(launch_path, product_template(fixture["origin"], BRIEFING, mode="live"))
                        common = ["--config", str(launch_path), "--gateway", str(gateway), "--data-dir", str(folder/"data"), "--pause-after-tasks", "1"]
                        result = cli(folder, "run", ["run", *common])
                        invocations = 1
                        while result["run"]["state"] == "paused" and invocations < 10:
                            result = cli(folder, "resume-"+str(invocations), ["resume", *common, "--run-id", result["run_id"]])
                            invocations += 1
                    finally:
                        for key, value in env_before.items():
                            if value is None:
                                os.environ.pop(key, None)
                            else:
                                os.environ[key] = value
                        save(folder/"reset.json", {k: v for k, v in fixture.items() if k != "tokens"})
                save(folder/"reset.json", {k: v for k, v in fixture.items() if k != "tokens"})
                cli(folder, "status", ["status", "--data-dir", str(folder/"data"), "--run-id", result["run_id"]])
                cli(folder, "export", ["export", "--data-dir", str(folder/"data"), "--run-id", result["run_id"], "--output", str(folder/"export")])
                with ResearchStore(folder/"data", readonly=True) as store:
                    scored = score_html(store, result["run_id"], fixture, offline_passed=True)
                scored["checks"]["process_boundary_recovery"] = (invocations >= 2 and any(a["kind"] == "task_boundary_resumed" for a in result["audit"]))
                scored["passed"] = all(scored["checks"].values())
                scored.update(navigation=variant, invocations=invocations, inference_tested=not mock, capability_tests_executed=not mock)
                save(folder/"score.json", scored)
            except Exception as exc:
                (folder/"failure-traceback.txt").write_text(traceback.format_exc(), encoding="utf-8")
                scored = {"scenario": scenario, "navigation": variant, "passed": False, "error": type(exc).__name__, "message": str(exc)}
                save(folder/"failure.json", scored)
            scores.append(scored)
            save(output/"progress.json", {"completed": len(scores), "total": len(SCENARIOS)*repeats, "runs": scores})
            print(json.dumps({"event": "end", "scenario": scenario, "reset": index+1, "passed": scored["passed"]}), flush=True)
    successes = Counter(s["scenario"] for s in scores if s["passed"])
    engineering = all(s.get("checks") and all(v for k, v in s["checks"].items() if k not in ("scenario_outcome", "real_acquired_capability_followup")) for s in scores)
    summary = {"source_revision": revision, "mode": "mock" if mock else "live", "development_only": mock or repeats != 3,
        "engineering_pass": engineering, "all_runs_passed": all(s["passed"] for s in scores),
        "technical_pass": repeats == 3 and not mock and engineering and all(successes[n] >= (2 if n in ("P1", "P2") else 3) for n in SCENARIOS),
        "scenario_successes": dict(successes), "human_acceptance": "pending", "runs": scores}
    save(output/"batch-summary.json", summary)
    files = {str(p.relative_to(output)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(output.rglob("*")) if p.is_file()}
    save(output/"manifest.json", {"files_sha256": files})
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gateway", default="config/examples/research-gateway.json")
    parser.add_argument("--output", required=True)
    parser.add_argument("--repeats", type=int, choices=(1, 2, 3), default=3)
    parser.add_argument("--mock", action="store_true")
    args = parser.parse_args()
    if args.mock:
        from tests.i0_support import model_server
        from tests.product_support import product_model
        context = model_server(product_model)
    else:
        context = nullcontext(None)
    with context as mocked:
        gateway = Path(args.gateway).resolve()
        if mocked:
            gateway = Path(args.output).resolve().parent/(Path(args.output).name+"-gateway.json")
            gateway.parent.mkdir(parents=True, exist_ok=True)
            save(gateway, mocked[0])
        summary = batch(gateway, args.output, repeats=args.repeats, mock=args.mock)
    print(json.dumps({k: v for k, v in summary.items() if k != "runs"}), flush=True)
    return 0 if summary["technical_pass"] or (summary["development_only"] and summary["all_runs_passed"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
