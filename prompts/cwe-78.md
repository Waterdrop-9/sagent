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

对 `clues/dangerous-sinks.md` 里出现的每个含 `system/popen/execve/execvp/system_lp/doSystem/…` 的函数，以及 `notes/02-attack-surface.md` 中流向这些 sink 的路径，**必须每个都给出明确结论**。

## 步骤

对每个候选函数：

1. **定位 sink 点**：Grep `decompile/*.c` 找到 `system(`、`popen(`、`exec*(` 的调用处
2. **分析参数构造**：
   - 完全字符串常量 → 无漏洞，说明清楚
   - 含格式化（`sprintf`/`snprintf` 拼接）→ 检查拼接的变量来源
   - 直接用参数 → 检查调用者传入的参数来源
3. **追调用链到网络输入**：
   - 向上追 caller（用 `function_index.txt` 找 callers）
   - 直到追到一个 handler（在 `notes/01-protocol.md` 里有记录），或明确不在 handler 链路上
4. **检查过滤/防护**：
   - 白名单校验？
   - shell 元字符过滤？（`;` `|` `&` `` ` `` `$(` ）
   - 长度限制？
5. **判定可达性**：从哪个 opcode/命令可触发？需要认证吗？

## 判定规则

- ✅ **确认漏洞**：网络输入可到达 + 过滤缺失或可绕过 + 可达性明确
- ❌ **无漏洞**：路径被常量/白名单/严格过滤阻断，或根本不在网络可达链路上
- ❓ **疑似/待定**：某一环节未确认（如某 SO 里的校验函数未分析）→ 记 notes，不创建 vulns

## 产出约束

### 有漏洞

每个漏洞创建一个文件：`vulns/VULN-NNN-cmdinj-<函数名简称>.md`

格式（必须包含以下章节）：

```markdown
# 命令注入：<简短描述>

## 基本信息
- 触发函数：`<Mangled Name>` @ 0x00XXXXXX
- 漏洞类型：command_injection
- 严重度：critical / high
- 置信度：high / medium / low
- 网络可利用：是
- 触发地址（sink 调用点）：0x00XXXXXX

## 调用链

```
网络入口 (opcode 0xXXXX)
  → handleXxx @ 0xYYY
    → funcA @ 0xZZZ
      → system(cmd, ...)  [sink @ 0x...]
```

## 数据流

- 输入来源：recv(sockfd, ..., N)
- 经过：...
- 到达 sink：`system("cmd " + user_input)`

## 关键代码（反编译片段）

(贴出 2-20 行关键代码)

## 修复建议
```

### 无漏洞/疑似

统一写到 `notes/03-cmd-injection.md`，格式：

```markdown
## 已分析（无漏洞）

- `funcA` @ 0x... — popen 参数是常量 "ls -la"，不可注入
- `funcB` @ 0x... — 实际不在网络链路上，调用者是本地启动脚本

## 疑似（需人工复审）

- `funcC` @ 0x... — 拼接路径后 system，但路径来源追到 libauth.so 未分析

## 覆盖清单

对比 clues/dangerous-sinks.md 里所有命令类 sink：
- [x] system @ 0x... (funcA)
- [x] popen @ 0x... (funcB)
- [ ] execve @ 0x... (funcD) — 未分析，原因...
```


## 硬性前置要求（所有漏洞类型通用）

### 1. 网络可达性是必要条件

本系统**只收录能通过网络请求触发的漏洞**。对每个候选漏洞，必须从网络入口（`notes/01-protocol.md` 的 dispatch 表）出发，逐跳证明可达。

- 如果路径追不回网络入口（例如只在本地启动时调用一次，或只被某个单元测试调用）→ **不创建 vulns 文件**，在对应的 notes 里记"本地可达但非网络可达"
- 如果前置需要认证但认证本身无漏洞 → 仍算网络可达，但严重度降级，并在 `基本信息` 中明确"需认证"

### 2. 去重：同一漏洞不写两份报告

**"同一漏洞"判定标准**：**sink 调用点地址相同**（例如同一处 `popen` 或同一处 `strcpy`），哪怕从不同入口/不同上游函数到达。

- 第一次发现：创建 `vulns/VULN-NNN-*.md`
- 发现"另一条调用链也能到达同一 sink"：**不创建新文件**，而是在已有的 vulns 文件的 `## 调用链` 章节里**追加一条入口路径**
- 判定前**必须先 Grep 现有 `vulns/` 目录**，确认 sink 地址是否已被记录

**例外**：同一函数但不同 sink 点（例如同一函数里既有 `system` 又有 `fopen` 两处漏洞）算两个漏洞，各写一份。

### 3. 不破坏已有的 vulns 文件

更新已有漏洞文件时，**只追加**调用链和数据流信息，不修改原有章节的事实描述。

## 反作弊声明

- `clues/dangerous-sinks.md` 里每个命令类 sink **必须**在产出中被引用（有漏洞或在"已分析"列表）
- "无漏洞"结论必须给出具体理由（哪一步阻断了），不能只说"无漏洞"
- 调用链必须**自下而上完整**：从 sink 追到网络入口，中间每一跳都要有函数名和地址
- 没有确定可达性就写"疑似"，不要直接报漏洞

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
