"""Read-only preflight for the model service used in Tester's previous tests."""

import argparse
import http.client
import json
import os
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from karst.config import KarstError, parse_url, strict_json


def check(path):
    cfg = strict_json(Path(path).read_text(encoding="utf-8"))
    if not isinstance(cfg, dict) or not isinstance(cfg.get("api_base"), str) or not isinstance(cfg.get("model"), str):
        raise KarstError("invalid gateway configuration")
    endpoint, _, host, port, _ = parse_url(cfg["api_base"].rstrip("/") + "/models")
    from urllib.parse import urlsplit
    parts = urlsplit(endpoint)
    if parts.query:
        raise KarstError("model endpoint must not contain a query")
    headers = {"Accept": "application/json"}
    key = os.environ.get("TESTER_API_KEY")
    if key:
        if not re.fullmatch(r"[A-Za-z0-9._~+/=-]{1,8192}", key):
            raise KarstError("invalid TESTER_API_KEY")
        headers["Authorization"] = "Bearer " + key
    cls = http.client.HTTPSConnection if parts.scheme == "https" else http.client.HTTPConnection
    conn = cls(host, port, timeout=5)
    try:
        conn.request("GET", parts.path, headers=headers)
        response = conn.getresponse()
        if response.status != 200:
            return {"ready": False, "http_status": response.status, "reason": "models_endpoint_rejected", "inference_tested": False}
        raw = response.read(1048577)
        if len(raw) > 1048576:
            raise KarstError("model listing exceeds limit")
        listing = strict_json(raw.decode("utf-8"))
        if not isinstance(listing, dict) or not isinstance(listing.get("data"), list):
            raise KarstError("invalid model listing")
        found = any(isinstance(item, dict) and item.get("id") == cfg["model"] for item in listing["data"])
        return {"ready": found, "configured_model": cfg["model"], "reason": "model_listed" if found else "model_not_listed",
                "inference_tested": False, "notice": "Availability only; text and tool-call tests still required."}
    finally:
        conn.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="config/examples/gateway.json")
    args = parser.parse_args()
    try:
        result = check(args.config)
    except (KarstError, OSError, http.client.HTTPException, UnicodeError) as exc:
        result = {"ready": False, "reason": str(exc) if isinstance(exc, KarstError) else type(exc).__name__, "inference_tested": False}
    print(json.dumps(result, ensure_ascii=True, indent=2))
    return 0 if result["ready"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
