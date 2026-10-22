"""Export the public subset of this checkout for the mirror repository.

The mirror (lurkratel/karst) is a one-way publication target: export, verify, push.
Nothing is ever merged back. Only paths listed in public-manifest.txt leave this
repository, so records/, docs/ and run output cannot leak by accident.

Usage from the repository root:

    py -3.12 scripts/publish_mirror.py --output ../karst-public
    py -3.12 scripts/publish_mirror.py --output ../karst-public --verify

--verify runs the full test suite inside the exported copy, which catches a
manifest that forgot a file the tests or the CLI need.
"""

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "public-manifest.txt"
FORBIDDEN = ("records", "docs", "runs", ".venv", ".git")


def git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip()


def load_manifest() -> list[str]:
    if not MANIFEST.is_file():
        raise SystemExit(f"missing {MANIFEST.name}")
    paths, seen = [], set()
    for line in MANIFEST.read_text(encoding="utf-8").splitlines():
        entry = line.split("#", 1)[0].strip()
        if not entry:
            continue
        if entry.split("/")[0] in FORBIDDEN:
            raise SystemExit(f"refusing to publish private path: {entry}")
        if entry not in seen:
            seen.add(entry)
            paths.append(entry)
    return paths


def main() -> int:
    parser = argparse.ArgumentParser(description="Export the public mirror subset of this checkout.")
    parser.add_argument("--output", required=True, help="new directory outside the checkout")
    parser.add_argument("--verify", action="store_true", help="run the full test suite in the exported copy")
    parser.add_argument("--python", default=sys.executable, help="interpreter used by --verify")
    args = parser.parse_args()

    commit = git("rev-parse", "HEAD")
    if git("status", "--porcelain"):
        raise SystemExit("working tree is dirty; commit or stash before publishing")

    out = Path(args.output).resolve()
    if out.exists():
        raise SystemExit(f"{out} already exists; publishing needs a new directory")
    if ROOT in out.parents:
        raise SystemExit("output must live outside the checkout")

    paths = load_manifest()
    out.mkdir(parents=True)
    archive = out / ".mirror.tar"
    try:
        subprocess.run(["git", "archive", "--format=tar", f"--output={archive}", commit, *paths],
                       cwd=ROOT, check=True)
        shutil.unpack_archive(str(archive), str(out))
    finally:
        if archive.exists():
            archive.unlink()

    leaked = [str(p.relative_to(out)) for p in out.rglob("*") if p.name in FORBIDDEN]
    if leaked:
        shutil.rmtree(out, ignore_errors=True)
        raise SystemExit("private paths leaked into the export: " + ", ".join(sorted(leaked)))

    files = [p for p in out.rglob("*") if p.is_file()]
    version = "unknown"
    init = out / "src" / "karst" / "__init__.py"
    if init.is_file():
        for line in init.read_text(encoding="utf-8").splitlines():
            if line.startswith("__version__"):
                version = line.split("=", 1)[1].strip().strip('"').strip("'")
                break

    print(json.dumps({
        "source_commit": commit,
        "files": len(files),
        "bytes": sum(p.stat().st_size for p in files),
        "output": str(out),
        "suggested_message": f"sync: Tester@{commit} (v{version})",
    }, ensure_ascii=False, indent=2))

    if args.verify:
        env = dict(os.environ, PYTHONIOENCODING="utf-8")
        check = subprocess.run([args.python, "-m", "unittest", "discover", "-s", "tests", "-t", "."],
                               cwd=out, env=env)
        if check.returncode != 0:
            print("verification failed; do not publish this export", file=sys.stderr)
            return check.returncode
        print("verification passed")

    print("next: copy the tree into a fresh clone of the mirror, commit with the message above, then push")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
