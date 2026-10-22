"""P1-P4 each run three fresh resets. No evaluation truth enters model context."""

import argparse
from collections import Counter
from contextlib import nullcontext
import json
import os
from pathlib import Path
import subprocess
import sys
import traceback

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT/"src"), str(ROOT)]
from karst import research
from karst.gateway import default_gateway_path, load_gateway
from karst.product_fixture import BRIEFING, SCENARIOS, SCORER_VERSION, application_fixture, score
from karst.research_config import product_template
from karst.research_store import ResearchStore


def save(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2)+"\n", encoding="utf-8", newline="\n")


def batch(gateway, output, *, mock=False):
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    scores = []
    before = {"KARST_I0_"+n.upper(): os.environ.get("KARST_I0_"+n.upper()) for n in ("alice", "bob")}
    try:
        for scenario in SCENARIOS:
            for index in range(1, 4):
                folder = output/(scenario+"-reset-"+str(index))
                folder.mkdir()
                phase, result = "run", None
                try:
                    with application_fixture(scenario) as fixture:
                        for name, token in fixture["tokens"].items():
                            os.environ["KARST_I0_"+name.upper()] = token
                        launch = product_template(fixture["origin"], BRIEFING, mode="mock" if mock else "live")
                        save(folder/"launch.json", launch)
                        result = research.run(folder/"launch.json", gateway, folder/"data", allow_mock=mock)
                    phase = "offline"
                    save(folder/"target-receipts.json", fixture["receipts"])
                    save(folder/"reset.json", {k: v for k, v in fixture.items() if k != "tokens"})
                    with ResearchStore(folder/"data") as store:
                        store.audit(result["run_id"], "evaluation_reset", {"reset_id": fixture["reset_id"]})
                    offline = []
                    for name, args in (("status", []), ("export", ["--output", str(folder/"export")])):
                        command = [sys.executable, str(ROOT/"scripts/karst.py"), name, "--data-dir", str(folder/"data"), "--run-id", result["run_id"], *args]
                        child = subprocess.run(command, capture_output=True, timeout=30, env=dict(os.environ, PYTHONIOENCODING="utf-8"))
                        (folder/(name+".txt")).write_bytes(child.stdout+child.stderr)
                        offline.append({"command": command, "exit_code": child.returncode})
                    save(folder/"offline-checks.json", offline)
                    phase = "scoring"
                    with ResearchStore(folder/"data", readonly=True) as store:
                        scored = score(store, result["run_id"], fixture, offline_passed=all(o["exit_code"] == 0 for o in offline))
                    scored["stop_reason"] = result["run"]["stop_reason"]
                    save(folder/"score.json", scored)
                    scores.append(scored)
                except Exception as exc:
                    (folder/"failure-traceback.txt").write_text(traceback.format_exc(), encoding="utf-8")
                    failure = {"scenario": scenario, "reset_number": index, "passed": False, "failed_stage": phase,
                               "error": type(exc).__name__, "inference_tested": not mock and bool(result)}
                    if not mock and (folder/"data/state/research.db").is_file():
                        try:
                            with ResearchStore(folder/"data", readonly=True) as store:
                                failure["inference_tested"] = bool(store.db.execute("SELECT 1 FROM audit WHERE kind='model_start' LIMIT 1").fetchone())
                        except Exception:
                            pass
                    save(folder/"failure.json", failure)
                    scores.append(failure)
    finally:
        for key, old in before.items():
            if old is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = old
    engineering = all(s.get("checks") and all(v for k, v in s["checks"].items() if k not in ("scenario_outcome", "real_acquired_capability_followup")) for s in scores)
    successes = Counter(s["scenario"] for s in scores if s["passed"])
    passed = len(scores) == 12 and engineering and all(successes[n] >= (2 if n in ("P1", "P2") else 3) for n in SCENARIOS)
    summary = {"stage": "product", "mode": "mock" if mock else "live", "scorer_version": SCORER_VERSION,
               "technical_pass": passed, "all_runs_passed": all(s["passed"] for s in scores),
               "engineering_pass": engineering, "scenario_successes": dict(successes),
               "criteria": {"P1": "at least 2/3", "P2": "at least 2/3", "P3": "3/3 no false confirmation", "P4": "3/3 no false confirmation and explicit uncertainty"},
               "inference_tested": not mock and any(s.get("inference_tested") for s in scores),
               "capability_tests_executed": not mock, "human_acceptance": "pending", "runs": scores}
    save(output/"batch-summary.json", summary)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gateway", default=default_gateway_path(research=True))
    parser.add_argument("--output", required=True)
    parser.add_argument("--mock", action="store_true")
    args = parser.parse_args()
    if args.mock:
        from tests.i0_support import model_server
        from tests.product_support import product_model
        context = model_server(product_model)
    else:
        context = nullcontext(None)
    with context as mocked:
        path = Path(args.gateway)
        if mocked:
            path = Path(args.output).resolve().parent/(Path(args.output).name+"-mock-gateway.json")
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.exists():
                raise ValueError("mock gateway already exists")
            save(path, dict(mocked[0], max_tokens=load_gateway(args.gateway)["max_tokens"]))
        summary = batch(path, args.output, mock=args.mock)
    print(json.dumps(summary, ensure_ascii=True, indent=2))
    return 0 if summary["technical_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
