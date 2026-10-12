# TaintSage 接入方案

状态：设计稿 v1（2026-10-13）。依据 [docs/12-TaintSage论文精读卡.md](./12-TaintSage论文精读卡.md)（论文全文提取 + 审计通过）。本文定义把 TAINTSAGE 的可借鉴机制接入 Sagent 的分阶段方案；每阶段独立提交、独立实验验证、可回滚。

v1 相对 v0 的调整（用户要求，2026-10-13）：**结构化状态抽象（原 P1）本轮不做**；Juliet 基准收缩为每个 CWE 选 50 个 pair，样本数据放在 `data/` 下。

## 0. 结论先行

TAINTSAGE 与 Sagent 的架构分工同构（确定性工具出事实、LLM 出语义），本轮接入聚焦**两块缺的机制**：

1. **source/sink 的 LLM 语义识别 + 风险链去重**（Sagent 目前是固定库函数表 + 人工启发，召回受限）；
2. **证据先行/四类证据标注 + 有界 on-demand 查询**（Sagent 已有 evidence-proxy 落盘，但语义提取粒度在 Agent 提示词里，未结构化）。

**明确不做**（用户决定，2026-10-13）：论文的 Structured State Abstraction（`M_f=⟨fn,sink,Info,Calls⟩` 参数级状态缓存）。原因是引入新状态存储/一致性校验/注入预算三块复杂度，而 Sagent 当前瓶颈不在状态复用而在 source/sink 召回与可测量性；如 Juliet 基线显示多二进制 unresolved 或 FN 与状态丢失相关，再单独提案（docs/12 §16 研究想法 1 已标注"暂缓，用户否决"）。

不借鉴的部分（明确排除）：TAINTSAGE 的实现代码（不可得）、其直接读反编译全文本做大上下文的方式（违反 Sagent 规模约束与 GUIDELINE「不要把全部反编译文本放进上下文」）、动态验证与符号执行（Sagent 默认不执行样本）。

## 1. 现状对照

| TAINTSAGE 组件 | Sagent 现有对应物 | 缺口 | 本轮决策 |
|---|---|---|---|
| DDC 提取（Ghidra P-code 跨函数后向切片） | angr RDA `query_sink_paths`（sink 驱动、参数级、节点预算） | 查询结果是一次性调用记录，不物化成链、不跨查询复用 | P2 可选（RDC 物化），排最后 |
| RDC 过滤（source 识别 + 去重） | `prompts/common/source-sink-model.md` 固定库函数表 → 候选 → 静态事实确认 | source 只靠固定表；无 rodata 字符串候选、无 (f,idx) 参数级分类、无链去重 | **P0 接入**（source 识别三件套 + 三条去重规则） |
| Exploitability-guided 语义提取（四类证据） | evidence-rules.md + evidence_proxy 工具证据 | 证据是工具调用级，函数内 Endpoint/Propagation/Constraint/Call-site 证据靠 Agent 临场发挥 | **P0 接入**（四类证据标注规范） |
| Structured State Abstraction（参数级状态 + 缓存复用） | 无 | 无 | **本轮不做**（用户决定） |
| 有界 on-demand 查询 | 工具预算（ghidra 128 次、paths 32 次、字节上限） | 无结构化查询通道（Agent 只能按现有 MCP 工具粒度发问） | 复用现有预算；「达到预算必须给保守结论」写入 coverage-rules |
| 报告/判定 | findings + 覆盖账本 + report.json | 无基准评测 | **P1 接入**（Juliet 基准闭环） |

## 2. 阶段划分

### P0（提示词级，最小改动）：source 识别增强 + 四类证据标注

**改动**：`prompts/common/source-sink-model.md` 增加三段——(a) 外部函数参数级分类 (f, idx)（引用 import 表与调用点证据）；(b) 内部函数 source 候选：rodata 字符串按引用频次 top-k 候选 → LLM 语义过滤；(c) source callsite 参数可控性检查（参数是否来自外部入口链）。`prompts/common/evidence-rules.md` 增加四类证据标注规范（Endpoint/Propagation/Constraint/Call-site），要求 Agent 在函数模型理由里按类标注。`coverage-rules.md` 增加「预算触顶必须保守结论，不得输出 confirmed」。

**不改代码**（纯提示词），因此**不进入** src/ 任何运行时逻辑。

**验收**：r01 契约测试断言新模板含上述条款；r02 fake-OpenCode 端到端跑通且覆盖账本行为不变（17+3 回归全绿）。真实样本（data/01_simple_demo）跑一遍 `--cwe all`，对比 source 候选数量变化（人工判读，产出记录进实验说明）。

### P1（评测闭环）：Juliet 基准（每 CWE 50 对）

**改动**：
- `scripts/eval/juliet_prepare.py`：下载 Juliet v1.3 → 每个 CWE（CWE-78/134/190/606，4 类）各选 50 个 pair（1 good + 1 bad 测试样例，固定随机种子保证可复现）→ 编译 → 剥离符号，模仿论文「剥离符号表」设置。样本数据按用户要求放在 `data/` 下：`data/juliet/CWE<编号>/<pair 序号>/1/{good,bad}/`（Juliet 原始目录约定，good=无漏洞对照、bad=含漏洞）。`data/juliet/` 加入 `.gitignore`（数据体积大、来源外部），只在 `data/juliet/README.md` 记录版本、种子与选取规则。
- `scripts/eval/run_bench.py`：对每个 bad 样例跑 Sagent 分析（`--cwe` 对应类型），对每个 good 样例同样跑（无告警为真阴性）；汇总 F1/precision/recall 与每样例耗时/token 到 `tests/eval/` 报告。评测产物按 EXPERIMENT.md 规则入 `tests/<日期>_xx_Juliet基准_r01/产物/`。

**验收**：4 个 CWE × 50 对跑出第一版基线数字（F1/precision/recall + 平均耗时 + 平均 token）并记录；基线不设门槛（先有数字）。本次运行同时产出任务②要求的「一次完整运行的时间与 token 开销」记录（见 docs/11 与实验说明）。

### P2（链物化 + 去重，可选）：RDC 物化

**改动**：`paths` 查询结果物化为链（从 sink 到 source 的函数序列）写 `<run>/state/risk-chains.json`；实现三条去重规则（等价链合并/保留更长/共享下游合并）在 `coverage.py` 查询统计前执行。此阶段不依赖状态缓存，排在最后；只有 P1 基线显示查询重复率高时才做。

## 3. 与既有约定的冲突处理

- docs/09 明确边界「不引入 RAG 或 TaintSage state cache」——边界更新为：借鉴范围聚焦 source/sink 识别、证据标注与评测闭环（见本文）；**结构化状态抽象与缓存本轮仍不做**，RAG 仍不做。docs/09 相应行已加注。
- GUIDELINE「领域逻辑不绑定具体 Agent 运行时」：P0 不新增模块；P1/P2 的脚本只编排 CLI 与报告解析，不 import runtime。
- 证据门禁不变：LLM 语义判断不能替代工具证据；confirmed finding 的证据门槛照旧。
- executed=false 不变：接入的是静态分析机制，不引入执行。
- 字节预算：P0 提示词增强计入 MAX_CONTEXT_BYTES（32KiB）预算；上线前用 fake-OpenCode 统计 prompt 长度，超预算即回滚条款。

## 4. 风险与回滚

| 风险 | 表现 | 缓解 |
|---|---|---|
| 提示词增强后 token 上涨 | 预算触顶、成本翻倍 | P0 上线前用 fake-OpenCode 统计 prompt 长度；超预算即回滚条款 |
| source 候选变多 → 覆盖账本无法闭合 | unresolved 暴涨、analysisStatus 全 inconclusive | 候选只是候选，须静态事实确认才进模型；候选不可证时直接 rejected 并记 reason |
| Juliet 编译环境差异 | 基准数字不可复现 | 固定编译器版本（记录于评测报告）；选取种子与脚本入库 |
| 无状态缓存导致多 CWE 重复分析成本高 | `--cwe all` 耗时×6 | 先记录基线数字（任务②），P1 基准报告里单列「无缓存 vs 论文有缓存」的口径差异 |

每阶段一个 `[feat]` 提交；P0 的回归以 r01+r02 全绿为准；回滚=git revert 对应提交。
