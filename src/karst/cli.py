"""Thin CLI: all behavior lives in application services."""

import argparse
import json
import sqlite3
import sys

from karst import application
from karst.config import KarstError


def main(argv=None):
    parser = argparse.ArgumentParser(prog="karst", description="Karst: first HTTP integration slice")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("list").add_argument("--data-dir", required=True)
    for name in ("doctor", "probe"):
        command = commands.add_parser(name)
        command.add_argument("--config", required=True)
        if name == "probe":
            command.add_argument("--data-dir", required=True)
    for name in ("status", "export", "evidence", "reconcile"):
        command = commands.add_parser(name)
        command.add_argument("--data-dir", required=True)
        command.add_argument("--run-id", required=True)
        if name == "export":
            command.add_argument("--output", required=True)
        if name == "evidence":
            command.add_argument("--evidence-id", required=True)
            command.add_argument("--raw", action="store_true", help="explicitly display restricted original evidence")
    command = commands.add_parser("run", help="I0 model/HTTP investigation")
    command.add_argument("--config", required=True)
    command.add_argument("--gateway", default="config/examples/gateway.json")
    command.add_argument("--data-dir", required=True)
    commands.add_parser("resume", help="not yet available")
    args = parser.parse_args(argv)
    try:
        if args.command == "resume":
            raise KarstError("resume is not implemented; reconcile and inspect retained evidence")
        from pathlib import Path
        formal = hasattr(args, "data_dir") and (Path(args.data_dir)/"state/research.db").is_file()
        if args.command == "run":
            from karst import research
            result = research.run(args.config, args.gateway, args.data_dir)
            print(json.dumps(result, ensure_ascii=True, indent=2))
            return 0 if any(r["kind"] == "task" and r["data"]["state"] == "delivered" for r in result["records"]) else 1
        if formal:
            from karst import research
            from karst.research_store import ResearchStore, ref
            if args.command == "list":
                with ResearchStore(args.data_dir, readonly=True) as store:
                    ids = store.db.execute("SELECT DISTINCT run_id FROM records WHERE kind='run'").fetchall()
                    result = {"runs": [{"run_id": row[0], **store.get(row[0])["data"]} for row in ids]}
            elif args.command in ("status", "reconcile"):
                result = getattr(research, args.command)(args.data_dir, args.run_id)
            elif args.command == "export":
                result = research.export(args.data_dir, args.run_id, args.output)
            elif args.command == "evidence":
                if not args.raw:
                    raise KarstError("original evidence requires --raw")
                with ResearchStore(args.data_dir, readonly=True) as store:
                    result = json.loads(store.evidence_bytes(ref(store.get(args.evidence_id)), args.run_id))
            else:
                raise KarstError("legacy probe requires a separate data directory")
            print(json.dumps(result, ensure_ascii=True, indent=2))
            return 0
        if args.command == "list":
            result = application.list_runs(args.data_dir)
        elif args.command == "doctor":
            result = application.doctor(args.config)
        elif args.command == "probe":
            result = application.probe(args.config, args.data_dir)
        elif args.command == "status":
            result = application.status(args.data_dir, args.run_id)
        elif args.command == "export":
            result = application.export(args.data_dir, args.run_id, args.output)
        elif args.command == "reconcile":
            result = application.reconcile(args.data_dir, args.run_id)
        else:
            if not args.raw:
                raise KarstError("original evidence may contain sensitive response data; --raw is required")
            result = json.loads(application.read_evidence(args.data_dir, args.run_id, args.evidence_id))
        print(json.dumps(result, ensure_ascii=True, indent=2))
        if args.command == "probe" and result["stop_reason"] != "probe_finished":
            return 1
        return 0
    except (KarstError, OSError, sqlite3.Error) as exc:
        message = str(exc) if isinstance(exc, KarstError) else f"local failure: {type(exc).__name__}"
        print(json.dumps({"error": message}, ensure_ascii=True), file=sys.stderr)
        return 2
