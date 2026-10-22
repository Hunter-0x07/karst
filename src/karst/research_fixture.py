"""Research-frontier integration acceptance on the resettable business application."""

from karst.i0_fixture import application_fixture

BRIEFING_VERSION = "research-frontier-business-v2"
BRIEFING = ("调查采购演示站。入口任务只读取入口并建立对象认识，分批发布有来源的资源、待验证假设和研究机会，"
            "再交付入口调查任务。将 Alice 和 Bob 各自订单的核对分别交给后续任务，问题与资源必须来自实际材料。"
            "两个后续任务的问题与预期产出中都明确要求实际用户名、订单编号、完整 reconciliation_code 和详情证据。"
            "入口任务交付后才由 Host 派发后续任务，不在入口任务中完成两人的调查。"
            "后续任务各自依据目录和详情整理实际用户名、订单编号、完整 reconciliation_code 及各自详情证据，"
            "同时如实记录归属或共享规则中仍不清楚的地方。不要重复访问已经保存的入口；"
            "每个身份的完整事实至少写入一条 observation 的 statement，并引用该身份详情证据；按需读取预览外的正文。"
            "授权范围内的身份对照可以执行，403 如实记为拒绝访问，不替代正常身份取证。"
            "已有证据可直接复用，不对同一 URL 和身份重复请求；共享规则仍不清楚时保留开放假设，"
            "不为相同未知点重复派发任务。只有实际新问题且存在新的可执行取证动作时才提出后续机会。"
            "此场景只检查多任务研究，不要求提出漏洞或权限结论。")


def score(store, run_id, fixture, *, offline_read_passed):
    from karst.research_scoring import score as research_score
    return research_score(store, run_id, fixture, offline_read_passed=offline_read_passed)
