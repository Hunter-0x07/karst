"""Reports are a projection of one persisted snapshot, never model-written verdicts."""

import hashlib
import json

from karst import __version__


def export_report(snapshot, destination):
    def save(name, value):
        (destination/name).write_text(json.dumps(value, ensure_ascii=False, indent=2)+"\n", encoding="utf-8", newline="\n")
    records = snapshot["records"]
    confirmed = {f["candidate_ref"]["id"] for f in snapshot["findings"]}
    candidates = [r for r in records if r["kind"] == "candidate"]
    coverage = {
        "scope": snapshot["run"]["spec"]["scope"], "stop_reason": snapshot["run"]["stop_reason"],
        "confirmed": snapshot["findings"],
        "ruled_out": [r for r in candidates if r["data"]["state"] == "ruled_out"],
        "pending": [r for r in candidates if r["id"] not in confirmed and r["data"]["state"] != "ruled_out"],
        "open_hypotheses": [r for r in records if r["kind"] == "hypothesis"],
        "waiting_opportunities": [r for r in records if r["kind"] == "opportunity" and r["data"]["state"] in ("proposed", "waiting", "ready", "deferred")],
        "failed_tasks": [r for r in records if r["kind"] == "task" and r["data"]["state"] != "delivered"],
        "capabilities": [r for r in records if r["kind"] == "capability"],
        "paths": [r for r in records if r["kind"] == "path_edge"],
        "not_tested": ["Undiscovered resources and operations outside recorded GETs"],
        "unsupported": ["Generic HTML/implicit business rules", "HTTP writes", "Browser/script execution", "Host/network privileges", "Resume"],
        "limits": ["Only explicit JSON access policies and identity-bound object reads are registered",
                   "Normal navigation alone is not a proven capability path", "No finding does not mean the target is safe"],
    }
    save("findings.json", snapshot["findings"])
    save("coverage.json", coverage)
    operations = [r for r in records if r["kind"] == "operation"]
    (destination/"operations.jsonl").write_text("".join(json.dumps(r, ensure_ascii=False)+"\n" for r in operations), encoding="utf-8", newline="\n")
    save("evidence-index.json", [r for r in records if r["kind"] == "evidence"])
    lines = ["# Karst 对象访问边界报告", "", "Run: `"+snapshot["run_id"]+"`", "",
             "停止原因："+snapshot["run"]["stop_reason"]["code"], "",
             "已确认："+str(len(confirmed))+"；已排除："+str(len(coverage["ruled_out"]))+"；待复核："+str(len(coverage["pending"])), ""]
    for finding in snapshot["findings"]:
        lines.extend(["## 已确认问题", "", finding["claim"], "", "影响："+finding["impact_boundary"], "",
                      "候选：`"+finding["candidate_ref"]["id"]+"`；主张版本："+str(finding["claim_revision"]),
                      "复核：`"+finding["verification_ref"]["id"]+"`", "",
                      "证据："+", ".join(r["id"] for r in finding["evidence_refs"]), ""])
    if not confirmed:
        lines.extend(["本次未确认安全问题。请结合待定项、实际覆盖和停止原因阅读。", ""])
    for label, rows in (("已排除候选", coverage["ruled_out"]), ("待复核候选", coverage["pending"]), ("开放假设", coverage["open_hypotheses"])):
        lines.extend(["## "+label, ""])
        for row in rows:
            claim = row["data"].get("claim", row["data"].get("question", ""))
            lines.extend([row["id"]+"："+(claim if isinstance(claim, str) else json.dumps(claim, ensure_ascii=False)), ""])
    lines.extend(["## 范围与限制", "", "仅支持明确 JSON 策略和具体对象读取核验；未测内容不代表安全。", "",
                  "HTTP 写操作、浏览器、主机/内网权限和恢复执行尚不支持。原始响应与模型会话留在受控数据目录。", ""])
    (destination/"report.md").write_text("\n".join(lines), encoding="utf-8", newline="\n")
    contexts = [a for a in snapshot["audit"] if a["kind"] == "context"]
    manifest = {"schema_version": "karst-product-report/1", "run_id": snapshot["run_id"], "program_version": __version__,
                "record_schema": snapshot["record_schema"], "runtime_profile": snapshot["run"]["spec"]["runtime_profile"],
                "budget": snapshot["run"]["spec"]["budget"], "usage": snapshot["usage"], "stop_reason": snapshot["run"]["stop_reason"],
                "contexts": contexts, "files_sha256": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(destination.iterdir()) if p.is_file()},
                "runtime": [a for a in snapshot["audit"] if a["kind"] == "runtime_manifest"],
                "reset_id": next((a["reset_id"] for a in snapshot["audit"] if a["kind"] == "evaluation_reset"), None),
                "original_evidence_included": False}
    save("manifest.json", manifest)
    return {"run_id": snapshot["run_id"], "output": str(destination), "files": sorted(p.name for p in destination.iterdir())}
