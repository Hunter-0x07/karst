"""Three fresh normal-business resets. Genuine model calls only unless explicitly --mock."""

import argparse
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
from karst.config import KarstError
from karst.gateway import default_gateway_path, load_gateway
from karst.i0_fixture import BRIEFING, application_fixture, score
from karst.research_config import template
from karst.research_store import ResearchStore


def save(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2)+"\n", encoding="utf-8", newline="\n")


def batch(gateway, output, *, mock=False, stage="i0"):
    briefing, build_launch, scorer = BRIEFING, template, score
    if stage == "research":
        from karst.research_fixture import BRIEFING as briefing, score as scorer
        from karst.research_config import research_template as build_launch
    elif stage != "i0":
        raise KarstError("unsupported batch stage")
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    scores = []
    env_before = {name: os.environ.get("KARST_I0_"+name.upper()) for name in ("alice", "bob")}
    try:
        for index in range(1, 4):
            folder = output/("reset-"+str(index))
            folder.mkdir()
            phase, result = "run", None
            try:
                with application_fixture() as fixture:
                    for name, values in fixture["users"].items():
                        os.environ["KARST_I0_"+name.upper()] = values["token"]
                    launch = build_launch(fixture["origin"], briefing, mode="mock" if mock else "live")
                    save(folder/"launch.json", launch)
                    # Evaluation answers remain in the orchestration process, not in
                    # the Host prompt, model-visible directory or tool registry.
                    result = research.run(folder/"launch.json", gateway, folder/"data", allow_mock=mock)
                # Target has been closed before both independent-process reads.
                phase = "offline"
                save(folder/"target-receipts.json", fixture["receipts"])
                save(folder/"reset.json", {"reset_id": fixture["reset_id"], "users": {n: {k: v for k, v in u.items() if k != "token"} for n, u in fixture["users"].items()}})
                commands = [[sys.executable, str(ROOT/"scripts/karst.py"), "status", "--data-dir", str(folder/"data"), "--run-id", result["run_id"]],
                            [sys.executable, str(ROOT/"scripts/karst.py"), "export", "--data-dir", str(folder/"data"), "--run-id", result["run_id"], "--output", str(folder/"export")]]
                offline = []
                for name, command in zip(("status", "export"), commands):
                    child = subprocess.run(command, capture_output=True, timeout=30, env=dict(os.environ, PYTHONIOENCODING="utf-8"))
                    (folder/(name+".txt")).write_bytes(child.stdout+child.stderr)
                    offline.append({"command": command, "exit_code": child.returncode})
                save(folder/"offline-checks.json", offline)
                phase = "scoring"
                with ResearchStore(folder/"data", readonly=True) as store:
                    scored = scorer(store, result["run_id"], fixture, offline_read_passed=all(x["exit_code"] == 0 for x in offline))
                scored["stop_reason"] = result["run"]["stop_reason"]
                save(folder/"score.json", scored)
                scores.append(scored)
            except Exception as exc:
                # A broken scorer must fail the reset, preserve its diagnostics,
                # and allow the rest of the frozen batch to be collected. User
                # cancellation (BaseException) still interrupts immediately.
                (folder/"failure-traceback.txt").write_text(traceback.format_exc(), encoding="utf-8")
                failure = {"passed": False, "reset_number": index, "failed_stage": phase,
                           "error": str(exc) if isinstance(exc, KarstError) else type(exc).__name__,
                           "inference_tested": not mock and bool(result and any(a["kind"] == "model_start" for a in result["audit"]))}
                if result:
                    failure["run_id"] = result["run_id"]
                    failure["stop_reason"] = result["run"]["stop_reason"]
                save(folder/"failure.json", failure)
                scores.append(failure)
    finally:
        for name, old in env_before.items():
            key = "KARST_I0_"+name.upper()
            if old is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = old
    summary = {"stage": stage, "mode": "mock" if mock else "live", "technical_pass": len(scores) == 3 and all(s["passed"] for s in scores),
               "inference_tested": not mock and any(s.get("inference_tested", False) for s in scores), "capability_tests_executed": False,
               "human_acceptance": "pending", "runs": scores}
    save(output/"batch-summary.json", summary)
    return summary


def main(*, stage="i0"):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gateway", default=default_gateway_path(research=stage == "research"))
    parser.add_argument("--output", required=True)
    parser.add_argument("--mock", action="store_true", help="explicit deterministic development check; never runtime acceptance")
    args = parser.parse_args()
    if args.mock:
        from tests.i0_support import model_server
        if stage == "research":
            from tests.frontier_support import frontier_model
            context = model_server(frontier_model)
        else:
            context = model_server()
    else:
        context = nullcontext(None)
    with context as mock_gateway:
        path = Path(args.gateway)
        if mock_gateway:
            path = Path(args.output).resolve().parent/(Path(args.output).name+"-mock-gateway.json")
            if path.exists():
                raise KarstError("mock gateway config already exists")
            path.parent.mkdir(parents=True, exist_ok=True)
            save(path, dict(mock_gateway[0], max_tokens=load_gateway(args.gateway)["max_tokens"]))
        result = batch(path, args.output, mock=args.mock, stage=stage)
    print(json.dumps(result, ensure_ascii=True, indent=2))
    return 0 if result["technical_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
