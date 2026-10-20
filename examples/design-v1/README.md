# DESIGN-1.5 契约与内部上下文示例

这里全部是**合成说明材料**。没有真实目标请求、凭据、漏洞证明或能力测试成绩；`.test` 域名和注册表引用为占位。当前分支没有运行这些配置的产品入口。

| 文件 | 结构和用途 |
|---|---|
| [run-spec.example.json](run-spec.example.json) | `spec` 为完整 RunSpec 示例；外层 example_only/note 用于文档，不进入正式契约 |
| [publication.example.json](publication.example.json) | `program_envelope` 为增量研究信封，payload 包含观察、候选及下一步机会；运行时注入正式引用 |
| [receipts.example.json](receipts.example.json) | 首次接受、相同内容重放、同键异内容拒绝；摘要按 08 计算，均为合成回执 |
| [state-fragments.example.json](state-fragments.example.json) | `format=record-fragments` 明确表示局部字段片段，reference_catalog 仅用于示例引用闭合，不可直接导入正式存储 |
| [execution-context.example.json](execution-context.example.json) | Host 内部 ExecutionContext/Grant 的合成值，引用目录仅说明绑定；不是新增 karst-design/1 记录或可运行配置 |

示例场景是一项正常业务访问后的研究记录：测试身份读取了一个测试对象，研究者提出可能违反隔离规则，但尚未排除合法共享。已验证“能够读取”仍不足以确认漏洞，独立复核保留 inconclusive。会话代次变化又使原访问能力 stale，后续任务需要重新核对前提；其他可执行机会仍能继续。

读取顺序是 RunSpec → publication → receipts → state-fragments。记录片段按叙事顺序展示多个版本，不声称它们来自真实执行。片段中出现的 satisfied/verified 是说明状态迁移用的虚构值，证据目录里没有相应材料文件。

1.5 保留原四份领域示例及其摘要不变，新增内部执行上下文说明。Grant 只收窄 RunSpec 的允许范围/影响，由可信 Host 产生；目标解析、当前条件、额度和取消仍在执行时核对。示例中的历史截止时间和预算句柄不是有效授权。当前诊断程序不加载这些设计示例。

开放 Hypothesis 可以驱动合法采证，不要求待测能力预先 verified；只有作为其他动作已具备的能力前提时才检查当前有效状态。组合使用至少两项相关 basis_refs，实际动作和产出可证明依赖后才形成 proven；不改变既有 Finding 或路径状态定义。

RunSpec 同时启用问题发现和进一步研究，`stop_on_goal=false`。它声明了指定主机的执行及管理权限目标，但示例 I1 工具配置不提供主机判据，允许影响也没有主机管理动作。因此目标应保留为 blocked，并说明 unsupported/policy 条件缺口；继续允许的 Web 调查。填写目标不会自动授予工具、动作或扩大范围。

正式实现必须解析注册表、模型配置、依赖和身份引用，并检查目标、工具、动作与范围的实际交集；这些占位配置不能视为可直接运行的任务。预算和轮转数字仅演示可冻结的配置，不是建议使用的生产参数。

`research.publish` 接受后 Task 仍为 running，Candidate 初始为 open，结果不自动变为 Finding。相同信封重发得到 duplicate，保持原 local_ref 映射、result_ref 和 state_version；同键修改内容得到 IDEMPOTENCY_CONFLICT，无新增对象。终结交付改用 `research.submit_result`，在其独立幂等域内将结果与 Task/Attempt 终态一起提交。

能力 observed→verified 和候选 verifying→inconclusive 只改变记录 version，claim_revision 保持 1；后续主张、对象、依据或条件变化必须递增 claim_revision。会话代次变化立即影响当前能力是否可用，不需要等所有下游异步标记结束。

字段和状态以 [08 数据契约与状态机](../../docs/08-数据契约与状态机.md) 为准；行为以 [09 调度执行与核验协议](../../docs/09-调度执行与核验协议.md) 为准。示例检查只验证文档一致性；实际能力另按 [10 实施计划与验收规格](../../docs/10-实施计划与验收规格.md) 验收。
