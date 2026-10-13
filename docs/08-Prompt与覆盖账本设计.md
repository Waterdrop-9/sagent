# Prompt 与覆盖账本设计

状态：设计稿 v0。

本文将参考项目中可复用的专家经验转化为 Sagent 自己的 prompt、工具和状态组织。本文只定义目标行为和接口，不绑定某个 Agent 底座或静态污点后端。

## 设计目标

Sagent 需要同时解决两个问题：

1. 让 Agent 能识别真实二进制中的攻击面、自定义 source、sink 和 sanitizer，而不是只依赖固定库函数名；
2. 让静态分析工具记录已检查范围、未覆盖语义和失败原因，避免 Agent 因上下文不足或查询成本而提前结束。

Agent 负责规划、语义解释、候选排序、补充查询和误报复核。确定性工具负责枚举、路径查询、去重、地址定位和覆盖记录。最终 findings 只允许 `confirmed` 或 `rejected`；证据不足的判断进入 `unresolved`，不作为第三种漏洞结果状态。

## Prompt 目录

Prompt 按通用规则、CWE 类型和阶段拆分：

```text
prompts/
├── common/
│   ├── evidence-rules.md
│   ├── attack-surface.md
│   ├── source-sink-model.md
│   ├── coverage-rules.md
│   └── report-schema.md
├── cwe-78.md
├── cwe-134.md
├── cwe-190.md
├── cwe-606.md
├── cwe-415.md
└── cwe-416.md
```

每个 CWE 使用一个完整 Markdown 文件，集中描述攻击面、候选模型、传播/生命周期复核、误报排除和输出要求。通用 prompt 规定证据、覆盖和状态语义；CWE 文件吸收外部问题清单的关键检查项，再加入 Sagent 的工具和证据规则。Prompt 中的知识不替代工具事实。

## 阶段一：攻击面侦查

Agent 首先调用 GhidraMCP 建立攻击面地图，查询顺序由风险和证据成本决定：

```text
程序信息
  → 导入/导出
  → 函数和字符串索引
  → 网络、IPC、文件、配置和动态加载候选
  → 候选函数反编译、调用关系和交叉引用
```

攻击面类别至少包括：

- 网络服务入口和协议解析；
- IPC、命令行和环境变量；
- 配置文件、设备节点和文件读取；
- 动态加载、插件和脚本解释器；
- 外部导入函数和内部包装函数；
- 认证、权限和会话状态。

每个候选攻击面记录：

```text
surface_id
category
function_id / address
evidence_ids
controllability: confirmed | candidate | unknown
status: open | checked | rejected | unknown
```

固定规则只能提高或降低优先级，不能单独把 API 名称判定为漏洞。

## 阶段二：自定义 source/sink 模型

固定库函数表只作为初始候选。Agent 可以根据 GhidraMCP 的反编译、调用点、字符串和外部函数关系提出自定义函数模型：

```json
{
  "function_id": "0x401230",
  "name": "FUN_00401230",
  "role": "candidate_sink",
  "cwe": ["CWE-78"],
  "sensitive_arguments": [0],
  "behavior": "将参数 0 传给 system",
  "evidence_ids": ["ev-001", "ev-002"],
  "confidence": "candidate"
}
```

模型分为三个状态：

- 内部模型可以使用 `candidate`：Agent 根据语义提出，尚未由静态关系确认；
- 最终 finding 的 `confirmed`：路径、可控性和关键约束都有证据；
- 最终 finding 的 `rejected`：存在明确反证，例如参数为常量、调用不可达或函数只是无关包装。

Agent 不能只因为函数名包含 `exec`、`recv`、`copy` 或 `parse` 就建立 confirmed 模型。自定义函数必须经过调用点、参数或返回值关系的静态复核。

## 阶段三：sink 驱动路径查询

对 confirmed 或高优先级 candidate sink，Agent 生成参数级查询任务：

```json
{
  "kind": "query_sink_paths",
  "component": "sha256:...",
  "sink_function": "0x401230",
  "sink_argument": 0,
  "source_candidates": ["0x402000", "http_get_param"],
  "max_depth": 8,
  "max_nodes": 5000,
  "timeout_seconds": 60
}
```

工具返回必须区分：

- `path_found`：找到带地址和参数映射的传播路径；
- `no_path`：在声明的分析范围内没有找到路径；
- `unknown`：存在未解析别名、间接调用、超时或其他不确定性；
- `unsupported`：工具不支持当前架构或语义；
- `failed`：工具执行失败。

`no_path` 不等于安全结论，`unknown` 更不能被 Agent 改写为 `no_path`。每条路径边必须记录函数、调用点、参数、地址或 IR/P-code 位置、来源工具和分析限制。

## 覆盖账本

覆盖账本是 Agent 结束分析前必须通过的状态，而不是可选日志：

```json
{
  "component": "sha256:...",
  "surfaces": {
    "total": 12,
    "checked": 10,
    "unknown": 2
  },
  "sources": {
    "candidate": 18,
    "confirmed": 7,
    "checked": 7,
    "unknown": 1
  },
  "sinks": {
    "candidate": 25,
    "confirmed": 11,
    "checked_arguments": 16,
    "unknown": 3
  },
  "paths": {
    "found": 8,
    "no_path": 5,
    "unknown": 3,
    "unsupported": 1,
    "failed": 0
  },
  "unresolved": [
    "间接调用 0x401880 的目标未解析"
  ]
}
```

结束条件至少包括：

1. 所有高优先级攻击面都有 checked、rejected 或 unknown 状态；
2. 所有 confirmed sink 的敏感参数都查询过；
3. 所有 candidate sink 要么被静态证据降级/确认，要么写入 unresolved；
4. 所有 `unknown`、`unsupported`、`failed` 都有原因；
5. 报告中的结论只能引用账本中的证据。

如果条件不满足，Agent 只能继续生成查询任务，或者输出 `inconclusive`，不能输出“未发现漏洞”的确定性结论。

## 阶段四：误报复核

每个候选发现必须经过以下顺序：

```text
source 可控性
  → sink 敏感参数
  → 每条传播边
  → 控制流可达性
  → 长度/范围/白名单/转义等 sanitizer
  → 跨组件和动态加载限制
```

最终复核结果只进入两类 finding：

- `confirmed`：路径、可控性和关键约束都有证据；
- `rejected`：有明确反证，并保存排除证据。

候选、工具未知和证据不足不进入 findings，统一写入 `unresolved`。`rejected` 不能简单删除，它用于后续去重、避免重复查询和解释为什么一个危险 API 没有形成漏洞。

## 不同 CWE 的问题组织

不同 CWE 共享阶段和覆盖账本，但使用不同的语义 prompt。首批启用 CWE-78、CWE-134、CWE-190、CWE-606、CWE-415 和 CWE-416：

| CWE | 重点 source | 重点 sink/事件 | 关键约束 |
| --- | --- | --- | --- |
| CWE-78 | 网络参数、IPC、配置和命令行 | `system`、`popen`、`exec*` 及自定义命令包装 | 命令拼接、白名单、转义、固定命令 |
| CWE-134 | 外部字符串、协议字段、文件内容 | `printf`、`syslog`、格式化包装 | 格式字符串是否由输入控制、参数数量 |
| CWE-190 | 外部整数、长度和计数 | 算术、分配大小、索引和循环边界 | 范围、符号、截断、乘法/加法溢出 |
| CWE-606 | 外部循环计数、长度和重试次数 | 循环条件、递归深度和资源消耗 | 上界、衰减、超时、限流和可达性 |
| CWE-415 | 外部输入触发的错误路径和资源生命周期 | `free`、`delete`、析构和清理分支 | 同一分配实例、别名、互斥路径和引用计数 |
| CWE-416 | 外部输入触发的对象生命周期和回调 | 释放后的读写、解引用、虚调用和外部调用 | 分配实例、别名、置空、重分配和线程同步 |

PoC 阶段通过外部引擎的 assistant 阶段模板接入，路径通过 `poc.prompt_file` 配置。漏洞分析问题序列不参与此阶段。只有最终 `confirmed` findings 才能进入 PoC 阶段；适配器只保存外部 Agent 响应，不执行生成的代码，也不把 candidate/unresolved 传入 PoC。

## 与实现的边界

实现应保持以下边界：

1. prompt 文件加载和阶段选择；
2. source/sink `FunctionModel` 和 `CoverageLedger` 结构；
3. GhidraMCP 事实转为候选模型的工具接口；
4. Agent 结束前的覆盖验证；
5. 结构化 finding 状态和证据引用。

参数级污点传播后端另行接入。它应实现统一的 `query_sink_paths` 接口，Agent 不直接依赖具体分析引擎。

## 产物规模与存储布局

分析产物可能包含数万函数、调用关系、反编译文本和大量路径。不能把完整反编译结果、所有 P-code 和全部证据放进一个 JSON，也不能把原始工具输出重复复制到每个 finding 中。

第一版采用“紧凑索引 + 少量保留证据 + 原始结果按需缓存”的布局。默认不为每个函数、每次查询和每条路径创建一个独立文件：

```text
analysis/<analysisGroupID>/
├── manifest.json
├── state/
│   ├── coverage-ledger.json
│   ├── function-index.json
│   └── findings.json
├── candidates.jsonl
├── queries.jsonl
├── evidence.jsonl
├── events/
│   └── analysis.jsonl
└── raw/
    ├── ghidra/
    └── path-backend/
```

各文件职责保持单一：

- `manifest.json` 只记录分析组、组件哈希、工具版本和 schema 版本；
- `coverage-ledger.json` 只保存状态、计数、ID 引用和 unresolved 摘要，不保存反编译文本；
- `function-index.json` 只保存函数 ID、地址、名称和文件位置；
- `candidates.jsonl` 只记录经过预筛选的攻击面、source、sink 和 sanitizer 候选；
- `queries.jsonl` 只记录已经执行或明确放弃的高价值查询；
- `evidence.jsonl` 只记录被 finding、复核或 unresolved 项引用的证据；
- `events/analysis.jsonl` 追加记录状态变化和工具调用，支持中断恢复；
- `raw/` 保留原始工具输出，结构化 JSON 只通过路径、哈希和范围引用它们。

函数模型不能内嵌完整反编译代码，只保存 `functionID`、摘要、角色、参数、证据 ID 和原始产物引用。大型反编译文本默认不进入持久化 finding，Agent 按函数或地址按需读取。

路径查询结果也分为摘要和保留细节：账本只保存 `queryID`、状态、路径数量、覆盖范围和查询记录引用；被 finding、复核或 unresolved 项引用的路径边写入 `queries.jsonl`，其余路径只保留计数和原始结果引用。重复的函数、调用点和证据通过 ID 去重。

文件写入需要设置边界：

- 单个函数模型、查询摘要和证据记录限制大小；
- 反编译文本、调用图和路径结果超过阈值时分块或压缩；
- JSONL 日志按大小或分析轮次滚动；
- 所有分片使用稳定 ID 和 schema 版本，避免依赖文件名顺序；
- 读取 Agent 上下文时只加载当前任务相关的摘要和证据，不把整个分析组放入 prompt。

当单个分析组的 JSONL 或查询记录达到实际瓶颈后，再引入 SQLite 或专用索引。数据库应从这些紧凑记录和原始产物导入，不能取代证据来源。

## 大型分析组的稀疏策略

一个分析组可能包含数千到数万函数。此时不能要求 Agent 阅读全部函数，也不能要求系统为所有函数建立完整安全模型。分析采用三层数据：

```text
全量静态索引
  → 高价值候选摘要
  → 当前路径和最终发现所需的证据
```

全量静态索引由 Ghidra 或路径后端按页提供，不全部复制到 Agent 上下文。候选摘要只保留满足以下条件的函数：

- 命中外部导入、攻击面字符串或危险操作；
- 位于高优先级攻击面或候选 source/sink 路径；
- 被其他已确认函数调用或引用；
- Agent 明确请求继续检查。

查询和候选排序使用预算：

```text
max_candidate_functions
max_sink_queries
max_path_depth
max_nodes_per_query
max_retained_evidence_bytes
```

这些预算属于分析任务级设置，不写入每条函数记录。达到预算后，CoverageLedger 记录 `budget_exhausted`，Agent 输出 `inconclusive` 或保留待处理项，不把未检查对象当成安全。

保留证据分成三种：

1. **临时观察**：只存在于当前 Agent 回合或工具缓存中，不写入长期产物；
2. **候选摘要**：写入 `candidates.jsonl`，只包含函数、地址、角色、理由和证据引用；
3. **结论证据**：只有被 finding、误报排除或 unresolved 项引用时，才写入 `evidence.jsonl`。

这样可以适当利用 Agent 当前上下文记忆能力，同时保留能恢复、复核和生成报告所需的最小本地证据。上下文记忆不能作为唯一持久化来源；跨轮次必须依靠紧凑摘要和证据 ID 恢复。

为避免 Agent lost in the middle，每个阶段只向它提供：

- 阶段目标和完成条件；
- 当前高价值候选的摘要；
- 当前查询及其结果；
- 与当前结论直接相关的证据；
- CoverageLedger 的未完成项和预算状态。

完整函数列表、全部反编译文本和历史对话不自动拼接进下一轮 prompt。
