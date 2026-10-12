# TaintSage 接入方案

状态：设计稿 v0（2026-10-13）。依据 [docs/12-TaintSage论文精读卡.md](./12-TaintSage论文精读卡.md)（论文全文提取 + 审计通过）。本文定义把 TAINTSAGE 的可借鉴机制接入 Sagent 的分阶段方案；每阶段独立提交、独立实验验证、可回滚。

## 0. 结论先行

TAINTSAGE 与 Sagent 的架构分工同构（确定性工具出事实、LLM 出语义），因此接入不是推翻而是**补齐三块缺的机制**：

1. **结构化安全状态抽象 + 缓存复用**（论文两大机制之一，Sagent 完全没有；也是 Sagent 多二进制 unresolved 缺口和「更多 CWE 插件、完整跨函数污点状态扩展」暂缓项的直接解）；
2. **source/sink 的 LLM 语义识别 + 风险链去重**（Sagent 目前是固定库函数表 + 人工启发，召回受限）；
3. **证据先行/四类证据标注 + 有界 on-demand 查询**（Sagent 已有 evidence-proxy 落盘，但语义提取粒度在 Agent 提示词里，未结构化）。

不借鉴的部分（明确排除）：TAINTSAGE 的实现代码（不可得）、其直接读反编译全文本做大上下文的方式（违反 Sagent 规模约束与 GUIDELINE「不要把全部反编译文本放进上下文」）、动态验证与符号执行（Sagent 默认不执行样本）。

## 1. 现状对照

| TAINTSAGE 组件 | Sagent 现有对应物 | 缺口 | 借鉴方式 |
|---|---|---|---|
| DDC 提取（Ghidra P-code 跨函数后向切片） | angr RDA `query_sink_paths`（sink 驱动、参数级、节点预算） | 查询结果是一次性调用记录，不物化成链、不跨查询复用 | 把 paths 查询结果物化为 RDC 结构（链=函数序列），落 `candidates/queries/evidence.jsonl` 之外新增链索引 |
| RDC 过滤（source 识别 + 去重） | `prompts/common/source-sink-model.md` 固定库函数表 → 候选 → 静态事实确认 | source 只靠固定表；无 rodata 字符串候选、无 (f,idx) 参数级分类、无链去重 | 引入 source 识别三件套（外部函数分类/内部函数字符串候选/可控性检查）+ 三条去重规则 |
| Exploitability-guided 语义提取（四类证据） | evidence-rules.md + evidence_proxy 工具证据 | 证据是工具调用级，函数内的 Endpoint/Propagation/Constraint/Call-site 证据靠 Agent 临场发挥 | 在 prompts/common 增加证据标注规范（四类），并要求 Agent 按证据标注函数表示，标注进 findings 的 limitations |
| Structured State Abstraction（M_f=⟨fn,sink,Info,Calls⟩，缓存复用） | 无 | 无 | 新增状态缓存：`<run>/state/function-states/`，键=⟨函数名, sink, 入态哈希⟩，签名一致性校验 |
| 有界 on-demand 查询 | 工具预算（ghidra 128 次、paths 32 次、字节上限） | 无结构化查询通道（Agent 只能按现有 MCP 工具粒度发问） | 复用现有预算，不新开通道；把「达到预算必须给保守结论」写进 coverage-rules |
| 报告/判定 | findings + 覆盖账本 + report.json | 无基准评测 | 新增 Juliet 评测闭环（见 §3 P2） |

## 2. 阶段划分

### P0（提示词级，最小改动）：source 识别增强 + 四类证据标注

**改动**：`prompts/common/source-sink-model.md` 增加三段——(a) 外部函数参数级分类 (f, idx)（引用 import 表与调用点证据）；(b) 内部函数 source 候选：rodata 字符串按引用频次 top-k 候选 → LLM 语义过滤；(c) source callsite 参数可控性检查（参数是否来自外部入口链）。`prompts/common/evidence-rules.md` 增加四类证据标注规范（Endpoint/Propagation/Constraint/Call-site），要求 Agent 在函数模型理由里按类标注。`coverage-rules.md` 增加「预算触顶必须保守结论，不得输出 confirmed」。

**不改代码**（纯提示词），因此**不进入** src/ 任何运行时逻辑。

**验收**：r01 契约测试断言新模板含上述条款；r02 fake-OpenCode 端到端跑通且覆盖账本行为不变（17+3 回归全绿）。真实样本（data/01_simple_demo）跑一遍 `--cwe all`，对比 source 候选数量变化（人工判读，产出记录进实验说明）。

### P1（状态抽象缓存，最大的一块）：结构化安全状态 + 缓存

**改动**：
- 新增 `src/agent/security_state.py`：`SecurityState`（参数级 ParamInfo⟨idx,taint,cons,aux⟩ 映射）、`StateCache`（键=⟨functionName, sinkID, 入态指纹⟩，JSON 序列化，签名一致性校验——映射与实参不符即失效重算）。领域逻辑保持运行时无关（GUIDELINE）。
- Agent 报告 schema 增加可选 `functionStates` 节（与 TaintSage 的 Calls/ParamInfo 对齐）：每个分析过的函数给出 `{functionID, functionName, sink, params: [{idx, taint, constraints, aux}], summary, incomingFingerprint}`。
- `cli.py`：分析阶段结束后把 `functionStates` 写入 `<run>/state/function-states.json`；同组后续 CWE 运行时，在 build_prompt 时注入「可复用状态摘要」（只注入当前函数命中的条目，控制字节预算）。
- `coverage.py`：状态缓存不改变 finish_check 逻辑；缓存未命中不产生 unresolved（只是无复用）。

**验收**：r02 新用例——同一分析组第二次分析（不同 CWE）时 prompt 包含「可复用状态」注入且字节预算未超；状态格式非法时降级为不注入（不炸）。真实 demo 上 `--cwe all` 连续 6 个 CWE 跑通，token/耗时在说明.md 里留记录。

### P2（评测闭环）：Juliet 基准

**改动**：新增 `scripts/eval/juliet_build.py`（下载 Juliet v1.3 → 选取 CWE-78/134/190/606 子集 → 编译 → 剥离符号，模仿论文「剥离符号表」设置）+ `scripts/eval/run_bench.py`（对每个测试样例跑分析，汇总 F1/precision/recall 到 `tests/eval/` 下报告）。评测产物按 EXPERIMENT.md 规则入 `tests/<日期>_xx_Juliet基准_r01/产物/`。

**验收**：CWE-78 子集（≥50 例）跑出第一版基线数字并记录；基线不设门槛（先有数字）。

### P3（链物化 + 去重，可选）：RDC 物化

**改动**：`paths` 查询结果物化为链（从 sink 到 source 的函数序列）写 `<run>/state/risk-chains.json`；实现三条去重规则（等价链合并/保留更长/共享下游合并）在 `coverage.py` 查询统计前执行。此阶段依赖 P1 的缓存收益，排在最后。

## 3. 与既有约定的冲突处理

- docs/09 明确边界「不引入 RAG 或 TaintSage state cache」——**用户新需求推翻此边界**（2026-10-13），本文即边界更新；docs/09 相应行加注「见 docs/13」。
- GUIDELINE「领域逻辑不绑定具体 Agent 运行时」：`security_state.py` 不 import runtime；缓存读写由 cli.py 编排。
- 证据门禁不变：状态抽象是 Agent 语义产物，不能替代工具证据；confirmed finding 的证据门槛照旧。
- executed=false 不变：接入的是静态分析机制，不引入执行。
- 字节预算：状态注入计入 MAX_CONTEXT_BYTES（32KiB）内的新增份额，先按「每函数摘要 ≤ 512B、每轮注入 ≤ 8KiB」执行。

## 4. 风险与回滚

| 风险 | 表现 | 缓解 |
|---|---|---|
| LLM 状态格式漂移（P1 最大风险） | functionStates 解析失败/字段缺失 | 解析失败整体降级不注入（fail-open），r02 用例覆盖 |
| 缓存误复用（签名不一致但碰巧同名） | finding 证据链错误 | 签名一致性校验（callee 名+实参+返回变量）；不确定即重算 |
| 提示词增强后 token 上涨 | 预算触顶、成本翻倍 | P0 上线前用 fake-OpenCode 统计 prompt 长度；超预算即回滚条款 |
| Juliet 编译环境差异 | 基准数字不可复现 | 固定编译器版本（记录于评测报告）；样本编译脚本入库 |

每阶段一个 `[feat]` 提交；P0/P1 的回归以 r01+r02 全绿为准；回滚=git revert 对应提交。
