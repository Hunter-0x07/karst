"""Collect a reproducible, metadata-only handoff package for another machine."""

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


def now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def main():
    parser = argparse.ArgumentParser(description="HTTP slice feedback; no model inference or external target testing")
    parser.add_argument("--output", required=True, help="a new directory outside the source checkout")
    parser.add_argument("--expected-commit", required=True, help="exact 40-character delivered commit SHA")
    parser.add_argument("--role", choices=("runtime", "development"), default="runtime")
    parser.add_argument("--check-model", action="store_true", help="optional model listing, not an HTTP acceptance gate")
    parser.add_argument("--git", default="git", help="Git executable if not on PATH")
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", args.expected_commit):
        parser.error("--expected-commit requires a full commit SHA")
    if sys.version_info[:2] != (3, 12):
        parser.error("this handoff requires Python 3.12; do not reuse the old Python 3.11 environment")

    def git(*parts):
        result = subprocess.run([args.git, "-c", f"safe.directory={ROOT.as_posix()}", "-C", str(ROOT), *parts],
                                capture_output=True, timeout=20)
        if result.returncode:
            raise RuntimeError("Git metadata unavailable")
        return result.stdout.decode("utf-8", errors="replace").strip()

    try:
        commit = git("rev-parse", "HEAD")
        dirty_before = bool(git("status", "--porcelain"))
        if commit != args.expected_commit:
            raise RuntimeError("checkout differs from the delivered commit; no tests started")
        if dirty_before:
            raise RuntimeError("working tree has local changes; preserve them and use a clean checkout for acceptance")
        output = Path(args.output).resolve()
        if output == ROOT or ROOT in output.parents:
            raise RuntimeError("feedback output must be outside the source checkout")
        output.mkdir(parents=True, exist_ok=False)
    except (RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=True), file=sys.stderr)
        return 2

    share = output / "feedback"
    private = output / "private"
    share.mkdir()
    private.mkdir()
    started = now()
    env = {k: v for k, v in os.environ.items() if k not in ("TESTER_API_KEY", "KARST_TEST_ALICE", "KARST_TEST_BOB")}
    env["PYTHONIOENCODING"] = "utf-8"

    def clean(text):
        replacements = [(str(ROOT), "<REPO>"), (str(output), "<OUTPUT>"),
                        (str(Path.home()), "<USER_HOME>"), (tempfile.gettempdir(), "<TEMP>")]
        for source, replacement in sorted(replacements, key=lambda x: len(x[0]), reverse=True):
            text = text.replace(json.dumps(source)[1:-1], replacement)
            text = text.replace(source, replacement).replace(source.replace("\\", "/"), replacement)
        return text

    def save_json(name, value):
        (share / name).write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")

    def run(label, command, timeout, *, command_env=env):
        start = time.monotonic()
        try:
            result = subprocess.run([sys.executable, *command], cwd=ROOT, env=command_env,
                                    capture_output=True, timeout=timeout)
            code, stdout, stderr = result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired as exc:
            code, stdout, stderr = 124, exc.stdout or b"", exc.stderr or b""
        text = clean((stdout + stderr).decode("utf-8", errors="replace"))
        (share / f"{label}.txt").write_text(text, encoding="utf-8", newline="\n")
        return {"command": ["<PYTHON>", *[clean(str(p)) for p in command]], "exit_code": code,
                "elapsed_seconds": round(time.monotonic() - start, 3)}, text

    unit, log = run("unittest", ["-m", "unittest", "tests.test_core", "-v"], 180)
    count_match = re.search(r"Ran (\d+) tests?", log)
    unit["tests"] = int(count_match.group(1)) if count_match else None
    unit["passed"] = unit["exit_code"] == 0 and unit["tests"] == 28 and log.rstrip().endswith("OK")
    demo, _ = run("demo", ["scripts/demo_http.py", "--output", str(private / "demo")], 60)
    demo["passed"] = False
    try:
        raw = json.loads((private / "demo" / "demo-result.json").read_text(encoding="utf-8"))
        expected = [["/", "anonymous"], ["/", "alice"], ["/", "bob"]]
        demo["passed"] = (demo["exit_code"] == 0 and raw.get("requests") == 3
                          and raw.get("evidence_count") == 3 and raw.get("target_receipts") == expected
                          and raw.get("stop_reason") == "probe_finished"
                          and (private / "demo/export/report.md").is_file())
        save_json("demo-summary.json", {k: raw.get(k) for k in ("run_id", "requests", "evidence_count", "target_receipts", "stop_reason", "scope")})
    except (OSError, ValueError):
        demo["reason"] = "demo output missing or invalid"

    model = {"requested": args.check_model, "required_for_this_stage": False, "inference_tested": False}
    if args.check_model:
        model_result, _ = run("model-preflight", ["scripts/check_model.py"], 30, command_env=dict(os.environ, PYTHONIOENCODING="utf-8"))
        model.update(model_result)
    dirty_after = True
    commit_after = None
    try:
        dirty_after = bool(git("status", "--porcelain"))
        commit_after = git("rev-parse", "HEAD")
    except (RuntimeError, OSError, subprocess.TimeoutExpired):
        pass
    technical_pass = unit["passed"] and demo["passed"] and not dirty_after and commit_after == commit
    environment = {"declared_role": args.role, "python": platform.python_version(), "system": platform.system(),
                   "machine_architecture": platform.machine(), "tested_commit": commit,
                   "working_tree_dirty_before": dirty_before, "working_tree_dirty_after": dirty_after,
                   "commit_after": commit_after, "started_at": started, "finished_at": now(),
                   "runtime_dependencies": [], "human_acceptance": "pending"}
    save_json("environment.json", environment)
    save_json("result.json", {"technical_pass": technical_pass, "human_acceptance": "pending", "unit": unit,
                              "demo": demo, "model_preflight": model, "capability_tests_executed": False})
    report = f"""# HTTP 基础切片反馈

- 声明执行侧：{args.role}（由调用者指定，不自动证明运行机器身份）。
- 被测试提交：`{commit}`。
- 工程检查：{unit['tests']} 项，退出码 {unit['exit_code']}，通过：{unit['passed']}。
- 三身份真实本机 HTTP 演示通过：{demo['passed']}。
- 代码/工作区保持不变：{not dirty_after and commit_after == commit}。
- 技术检查结果：{'passed' if technical_pass else 'failed'}；用户验收确认：pending。
- 模型列表检查为可选项，不影响本次 HTTP 阶段；没有执行模型推理或漏洞能力测试。

只回传本 feedback 目录。原始材料与数据库保留在同级 private 目录，不自动上传。
失败复测使用新的输出目录，保留本次记录。确认通过须由用户另行表达并绑定本提交。
"""
    (share / "result.md").write_text(report, encoding="utf-8", newline="\n")
    source_manifest = {}
    for name in git("ls-files").splitlines():
        path = ROOT / name
        if path.is_file() and (name.startswith(("src/", "scripts/", "tests/", "config/", "knowledge/")) or name == "pyproject.toml"):
            source_manifest[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    save_json("manifest.json", {"tested_commit": commit, "source_sha256": source_manifest,
                                 "shared_files_sha256": {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                                         for p in sorted(share.iterdir()) if p.is_file()}})
    print(json.dumps({"feedback_directory": str(share), "technical_pass": technical_pass,
                      "declared_role": args.role, "human_acceptance": "pending"}, ensure_ascii=True, indent=2))
    return 0 if technical_pass else 1


if __name__ == "__main__":
    raise SystemExit(main())
