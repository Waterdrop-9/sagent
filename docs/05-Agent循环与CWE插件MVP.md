# Agent 循环与 CWE 插件 MVP

状态：设计稿 v0。

## 目标

本模块把静态二进制事实、CWE 知识和 LLM agent 组织成一个可反复推进的分析循环。首版只验证以下主路径：

```text
分析组
  → CWE 插件提供候选 sink
  → 从 sink 参数反向查询数据依赖路径
  → 判断路径是否来自可控 source
  → 校验证据
  → 形成发现项或继续查询
```

首版不实现完整 Ghidra 适配、不实现知识 RAG、不实现状态缓存，也不执行样本。代码中的内存静态事实后端只用于验证循环接口。

## 设计原则

- 静态工具产生地址、函数、调用关系和数据依赖等事实；模型只能解释事实、选择下一步查询和提出假设。
- TaintSage 的核心复用点是 sink 驱动的路径查询。调用图用于寻找查询范围，不能单独充当数据流证据。
- BinReX 的核心复用点是“任务 → 工具产物 → 验证 → 更新状态 → 继续规划”。首版用一个循环表达多个角色，不拆成多个独立 Agent。
- CWE 知识通过插件 prompt 和规则直接注入，不使用 RAG。
- 每个结论必须保留来源、位置和验证结果；没有证据的判断停留在候选假设。

## 模块接口

### 静态分析工具

上层只依赖稳定的工具接口：

```text
query_sink_paths(sink_function, sink_argument) → data dependency paths
get_function(function_id) → function fact
```

真实实现以后由 Ghidra 适配器提供。工具结果使用普通结构化数据表示，不泄漏 Ghidra 内部对象。

### CWE 插件

插件提供：

- `cwe_id`：漏洞类型标识；
- `knowledge_prompt`：给规划和判断模型的领域知识；
- `initial_tasks()`：首批待执行任务；
- `follow_up_tasks()`：根据工具结果提出补充查询；
- `interpret()`：把已验证路径转为候选发现；
- `is_complete()`：判断当前证据是否足以结束任务。

插件可以扩展路径状态。例如 CWE-78 关注命令字符串和过滤，CWE-190 需要数值范围和算术约束。通用循环不直接写入这些 CWE 语义。

### 分析状态

```text
AnalysisState
  goal
  cwe
  pending_tasks
  artifacts
  evidence
  hypotheses
  findings
  failures
```

本轮暂不缓存函数状态。后续需要跨路径复用时，再把缓存作为独立模块加入。

## 循环行为

1. 插件把分析目标转换为 `query_paths` 任务。
2. Executor 调用静态工具并保存原始产物。
3. Validator 检查产物是否完整，路径中的边是否有数据依赖证据。
4. 插件解释已验证路径，判断 source、传播和 sink 是否满足 CWE 条件。
5. 插件可以根据证据缺口提出 `inspect_function` 等补充任务。
6. `is_complete()` 成立时生成结构化发现项；达到预算或工具失败时保留明确状态。

首个插件选择 CWE-78，因为 source、命令构造和 sink 路径容易做出可复核的最小闭环。CWE-134 可以复用同一循环；CWE-190 和 CWE-606 等需要更丰富数值约束后再加入。

## 证据要求

一个可报告的候选至少包含：

- 根组件和函数标识；
- source、传播函数和 sink 的有序路径；
- sink 敏感参数位置；
- 支持每条路径边的静态证据；
- source 可控性和 sanitizer 判断；
- 未验证部分、工具限制和置信度。

模型文本不能替代这些字段。工具失败或路径不完整时，结果进入失败或待处理状态。

## 后续替换点

- 用 Ghidra 适配器替换内存工具后端；
- 用 LLM Planner 替换示例插件中的固定任务规划；
- 为每个 CWE 增加 prompt、状态扩展、候选规则和报告字段；
- 在需要时加入结构化状态缓存和按需函数查询。
