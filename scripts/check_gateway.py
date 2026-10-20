"""Explicit model inference and tool-round-trip diagnostics. Output directory must be new."""

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"src"))
from karst.gateway_checks import run_gateway_checks
from karst.config import KarstError


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="config/examples/gateway.json")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        result = run_gateway_checks(args.config, args.output)
    except (KarstError, OSError) as exc:
        result = {"passed": False, "error": str(exc) if isinstance(exc, KarstError) else type(exc).__name__}
    print(json.dumps(result, ensure_ascii=True, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
