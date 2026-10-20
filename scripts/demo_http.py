"""Run a real loopback HTTP integration demonstration in a new output directory."""

import argparse
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT)]

from karst import application
from tests.support import config, server, write_config


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    # These are public, synthetic fixture identities, never real credentials.
    os.environ["KARST_TEST_ALICE"] = "demo-alice"
    os.environ["KARST_TEST_BOB"] = "demo-bob"
    with server() as (target, origin):
        cfg = config(origin, identities=True)
        config_path = write_config(output, cfg)
        result = application.probe(config_path, output / "data")
        received = list(target.seen)
    exported = application.export(output / "data", result["run_id"], output / "export")
    summary = {"run_id": result["run_id"], "requests": result["requests"],
               "evidence_count": len(result["evidence"]), "target_receipts": received,
               "stop_reason": result["stop_reason"], "export": exported,
               "scope": "real loopback HTTP integration; no model or vulnerability evaluation"}
    (output / "demo-result.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
