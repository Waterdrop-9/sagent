# CWE-78 Sagent 分析规则

本文件合并该 CWE 的攻击面、候选模型、传播/生命周期复核、误报排除和输出约束。重点：命令拼接、shell 元字符、固定命令、白名单、转义和自定义 wrapper。

# 03 搜查命令注入

本轮目标：**识别所有可被远程触发的命令执行漏洞**。

## 起点

本仓库不产出 `clues/`、`notes/`、`binary/`、`decompile/` 目录——下面 vh 风格章节提到的线索文件一律不存在，忽略它们，改用「Sagent 工具与证据规则」的 GhidraMCP/query_sink_paths/ELF 解析工具自行收集。优先级从高到低：

1. **GhidraMCP 导入表/函数/反编译** — 找 `system/popen/exec*` 及自定义 wrapper（如 `doSystem`）的全部调用点（最精准）
2. **query_sink_paths** — 对高价值 sink 查参数数据依赖（覆盖清单，保证不漏）
3. **网络入口与 dispatch 表** — 反编译 handler 与 opcode 分发表（用于追可达性）
4. **依赖库 ELF 解析**（bash：`nm -D`/`objdump -d`/`strings`）— libauth/liblog 等未加载库的 `system/popen/exec*` 调用点（无 evidenceID，记 unresolved）
5. **自主探索**：`fork()+execve()` 两步模式、函数指针调用

## 搜查清单

对阶段 M 候选链摘要里的每一条链，以及工具枚举出的全部命令类 sink 调用点
（`system/popen/exec*` 及自定义 wrapper，如 `doSystem`），**必须每个都给出明确结论**。
候选链摘要中没有覆盖的 sink 也要主动枚举，不得遗漏。

## 步骤

1. **逐链判定**：按 per-chain-judgment.md 的协议，对候选链摘要中每一条链给出
   confirmed / rejected / unresolved 的明确 verdict；机械来源（callgraph/import_table/plt_link）
   不是确认依据，每一跳仍需要反汇编调用点证据。
2. **sink 枚举兜底**：用 GhidraMCP 找全 `system/popen/exec*` 调用点（含 fork+execve
   两步模式、函数指针调用），对照候选链清单，未出现的单独判定。
3. **分析参数构造**：
   - 完全字符串常量 → 无漏洞，写清楚（如 `system("mkdir -p ...")` 启动阶段常量 → rejected）
   - 含格式化（`sprintf`/`snprintf` 拼接）→ 检查拼接的变量来源
   - 直接用参数 → 检查调用者传入的参数来源
4. **追调用链到网络输入**：沿候选链 hops 向上追 caller（GhidraMCP 交叉引用），
   直到追到网络入口（recv 等），或明确不在网络链路上。
5. **检查过滤/防护**：白名单校验？shell 元字符过滤（`;` `|` `&` `` ` `` `$(`）？长度限制？
6. **驳斥清单（仅 confirmed 候选必须逐项通过）**：见 per-chain-judgment.md 的
   R1 source 可控性 / R2 逐跳传播 / R3 清洗约束 / R4 构造与影响。每项最多一次补充查询。

## 判定规则

- ✅ **confirmed**：网络输入可到达 + 过滤缺失或可绕过 + 驳斥清单 R1-R4 全部通过，
  且符合 confirmation-policy.md 的确认标准（引用链级证据时 confirmationBasis=reference-chain）。
- ❌ **rejected**：有明确反证（常量、路径不可达、有效校验、清洗约束、启动阶段执行），
  反证写进 finding 的 limitations。
- ❓ **unresolved**：某一环节证据不足（如依赖库内部未分析、跨组件未覆盖）→ 写 unresolved，
  说明缺哪一类证据，保留 evidenceIDs。

## 产出约束

最终 JSON 是唯一产出（见「Sagent 最终输出规则」）。不创建 vulns/notes/clues 目录文件。


## 硬性前置要求（所有漏洞类型通用）

### 1. 网络可达性是必要条件

本系统**只收录能通过网络请求触发的漏洞**。对每个候选漏洞，必须从网络入口
（recv/read 等输入源）出发，逐跳证明可达。

- 如果路径追不回网络入口（例如只在本地启动时调用一次）→ 记为 rejected，limitations 写"本地可达但非网络可达"
- 如果前置需要认证但认证本身无漏洞 → 仍算网络可达，但严重度降级，并在 limitations 中明确"需认证"

### 2. 去重：同一漏洞不写两份报告

**"同一漏洞"判定标准**：**sink 调用点地址相同**（例如同一处 `popen` 或同一处 `strcpy`），
哪怕从不同入口/不同上游函数到达。

- 发现"另一条调用链也能到达同一 sink"：**不创建新 finding**，而是在已有 finding 的 limitations/调用链描述里追加一条入口路径
- 判定前先核对已写出的 finding 列表，确认 sink 地址是否已被记录

**例外**：同一函数但不同 sink 点（例如同一函数里既有 `system` 又有 `fopen` 两处漏洞）算两个漏洞，各写一份。

### 3. 反作弊声明

- 每个命令类 sink **必须**在产出中被引用（有漏洞或在 unresolved 中说明未分析原因）
- "rejected" 结论必须给出具体理由（哪一步阻断了），不能只说"无漏洞"
- 调用链必须**自下而上完整**：从 sink 追到网络入口，中间每一跳都要有函数名和地址
- 没有确定可达性就写 unresolved，不要直接报 confirmed

## Sagent 工具与证据规则

1. 先使用 ELF 分析组中的 binaryID 和依赖关系确定范围，再使用 GhidraMCP 查询程序信息、导入、函数、字符串、反编译、调用关系和交叉引用。
2. 对高价值 sink 或生命周期事件调用 `query_sink_paths`；工具返回的 `path_found` 只是参数定义或依赖链，不能单独证明完整漏洞。
3. 每个结论必须引用 binaryID、functionID、调用点/地址和 evidenceIDs。Agent 推断必须标记为语义判断，不能把函数名或调用关系当作事实。
4. 从网络、IPC、命令行、环境、配置或文件入口逐跳检查可达性；认证要求、跨库边界、间接调用、别名和反编译限制都要记录。
5. 复核同一 sink 调用点的去重情况，不能因为多条入口路径重复创建同一个 finding。

## Sagent 最终输出规则

最终 JSON 必须包含 `findings`、`unresolved`、`coverage`。`findings[].status` 只能是 `confirmed` 或 `rejected`：

- `confirmed`：类型语义、外部可达性、传播/生命周期关系和安全影响均有工具证据；
- `rejected`：有明确反证，例如常量、路径不可达、有效校验、互斥控制流或对象实例不同。

证据不足、工具不支持、查询失败、跨组件未覆盖或只能提出候选时，不得放入 findings，改写入 `unresolved`，保留原因和 evidenceIDs。不要生成或执行 PoC；PoC 由独立阶段接收 confirmed findings。
