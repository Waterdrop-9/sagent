# Prompt 与覆盖账本设计

状态：设计稿 v0。

本文将参考项目中可复用的专家经验转化为 Sagent 自己的 prompt、工具和状态组织。本文只定义目标行为和接口，不绑定某个 Agent 底座或静态污点后端。

## 设计目标

Sagent 需要同时解决两个问题：

1. 让 Agent 能识别真实二进制中的攻击面、自定义 source、sink 和 sanitizer，而不是只依赖固定库函数名；
2. 让静态分析工具记录已检查范围、未覆盖语义和失败原因，避免 Agent 因上下文不足或查询成本而提前结束。

Agent 负责规划、语义解释、候选排序、补充查询和误报复核。确定性工具负责枚举、路径查询、去重、地址定位和覆盖记录。Agent 没有证据时只能给出假设或 `inconclusive`。

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
├── cwe-78/
│   ├── attack-surface.md
│   ├── candidate-models.md
│   ├── propagation-review.md
│   ├── false-positive-review.md
│   └── poc.md
├── cwe-134/
├── cwe-190/
└── cwe-606/
```

每个文件只描述一个阶段的规则和输出要求。通用 prompt 规定证据、覆盖和状态语义；CWE prompt 规定该漏洞类型的 source、sink、sanitizer、约束和报告字段。Prompt 中的知识不替代工具事实。

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

- `candidate`：Agent 根据语义提出，尚未由静态关系确认；
- `confirmed`：静态工具确认了函数角色、敏感参数或传播关系；
- `rejected`：存在明确反证，例如参数为常量、调用不可达或函数只是无关包装。

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

复核结果分为：

- `confirmed`：路径、可控性和关键约束都有证据；
- `candidate`：存在完整候选路径，但仍有语义或可达性不确定；
- `inconclusive`：关键证据缺失或工具能力不足；
- `rejected`：有明确反证，并保存排除证据。

`rejected` 不能简单删除。它用于后续去重、避免重复查询和解释为什么一个危险 API 没有形成漏洞。

## 不同 CWE 的问题组织

不同 CWE 共享阶段和覆盖账本，但使用不同的语义 prompt：

| CWE | 重点 source | 重点 sink/事件 | 关键约束 |
| --- | --- | --- | --- |
| CWE-78 | 网络参数、IPC、配置和命令行 | `system`、`popen`、`exec*` 及自定义命令包装 | 命令拼接、白名单、转义、固定命令 |
| CWE-134 | 外部字符串、协议字段、文件内容 | `printf`、`syslog`、格式化包装 | 格式字符串是否由输入控制、参数数量 |
| CWE-190 | 外部整数、长度和计数 | 算术、分配大小、索引和循环边界 | 范围、符号、截断、乘法/加法溢出 |
| CWE-606 | 外部循环计数、长度和重试次数 | 循环条件、递归深度和资源消耗 | 上界、衰减、超时、限流和可达性 |

PoC prompt 只在证据阶段完成后运行。它引用发现项和证据，不重新判断漏洞，也不能把 candidate 自动提升为 confirmed。

## 与实现的边界

下一轮代码实现应先完成：

1. prompt 文件加载和阶段选择；
2. source/sink `FunctionModel` 和 `CoverageLedger` 结构；
3. GhidraMCP 事实转为候选模型的工具接口；
4. Agent 结束前的覆盖验证；
5. 结构化 finding 状态和证据引用。

参数级污点传播后端另行接入。它应实现统一的 `query_sink_paths` 接口，Agent 不直接依赖具体分析引擎。

## 产物规模与存储布局

分析产物可能包含数万函数、调用关系、反编译文本和大量路径。不能把完整反编译结果、所有 P-code 和全部证据放进一个 JSON，也不能把原始工具输出重复复制到每个 finding 中。

第一版采用“索引小文件 + 分片产物 + 原始结果引用”的布局：

```text
analysis/<analysisGroupID>/
├── manifest.json
├── state/
│   ├── coverage-ledger.json
│   ├── function-index.json
│   └── findings.json
├── models/
│   └── functions/<functionID>.json
├── queries/
│   └── <queryID>.json
├── evidence/
│   └── <evidenceID>.json
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
- 每个函数模型、查询和证据单独分片，避免单文件无限增长；
- `events/analysis.jsonl` 追加记录状态变化和工具调用，支持中断恢复；
- `raw/` 保留原始工具输出，结构化 JSON 只通过路径、哈希和范围引用它们。

函数模型不能内嵌完整反编译代码，只保存 `functionID`、摘要、角色、参数、证据 ID 和原始产物引用。大型反编译文本应保存在原始产物中，Agent 按函数或地址按需读取。

路径查询结果也分为摘要和详细结果：账本只保存 `queryID`、状态、路径数量、覆盖范围和详细结果引用；具体路径边写入对应查询文件。重复的函数、调用点和证据通过 ID 去重。

文件写入需要设置边界：

- 单个函数模型、查询摘要和证据记录限制大小；
- 反编译文本、调用图和路径结果超过阈值时分块或压缩；
- JSONL 日志按大小或分析轮次滚动；
- 所有分片使用稳定 ID 和 schema 版本，避免依赖文件名顺序；
- 读取 Agent 上下文时只加载当前任务相关的摘要和证据，不把整个分析组放入 prompt。

当单个分析组的分片数量或查询记录达到实际瓶颈后，再引入 SQLite 或专用索引。数据库应从这些结构化分片和原始产物导入，不能取代证据来源。
