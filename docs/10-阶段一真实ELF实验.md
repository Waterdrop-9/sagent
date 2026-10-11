# 阶段一真实 ELF 实验

日期：2026-10-12

目标：验证分析组摘要、阶段化 CWE-78 prompt、OpenCode、DeepSeek 和 GhidraMCP 能否对真实 ELF 进行攻击面侦查和候选 source/sink 分析。

## 输入

```text
目标：data/01_simple_demo/server
显式依赖根：data/01_simple_demo
Agent：OpenCode 2.0.26
模型：DeepSeek deepseek-flash
反编译工具：GhidraMCP headless
```

运行命令：

```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra/libexec
export GHIDRA_MCP_EXTENSION_JAR=/path/to/GhidraMCP.jar

PYTHONPATH=src python3 -m agent.cli \
  --config config.toml \
  --target data/01_simple_demo/server \
  --dependency-root data/01_simple_demo \
  --goal "只做第一阶段攻击面侦查：确认程序、架构、导入函数、字符串和命令执行候选；不要声称完成静态污点传播，不要生成PoC，最后按要求输出JSON。"
```

## 观察结果

Agent 成功调用 GhidraMCP，并确认：

- 程序为 `server`；
- 格式为 ELF；
- 架构为 x86 64 位小端；
- 函数数为 78；
- 外部函数数为 32；
- 程序哈希与分析组 `binaryID` 一致。

Agent 识别出：

- TCP 服务监听和 `accept` 网络入口；
- 2 字节 opcode 分发协议；
- `remoteExec` 自定义命令处理函数；
- `doSystem` 自定义命令包装函数；
- `popen` 外部 sink；
- `system` 另一个调用点；
- `recv → remoteExec → doSystem → popen` 候选路径；
- `mkdir -p %s` 常量命令对应的固定 `system` 调用。

输出中将两个命令执行点区分为：

```text
remoteExec → doSystem → popen：CWE-78 candidate
固定路径 → system：rejected
```

Agent 同时输出了 function/address、调用点、证据 ID、限制和 coverage 摘要。这验证了自定义 source/sink wrapper 的 prompt 方向。

## 当前限制

`remoteExec` 仍然是 `candidate`，不是 `confirmed`，原因是当前还没有参数级静态污点传播后端。Agent 可以从反编译和汇编观察到参数关系，但不能替代确定性路径分析。

输出还保留了以下 unresolved 项：

- `libauth.so` 和 `liblog.so` 未加载；
- 间接调用和数据表语义未完全解析；
- `recv` 输入的 NUL 终止行为未确认；
- 覆盖账本暂时由 Agent 输出，尚未由 Sagent 验证器强制检查。

## 阶段结论

阶段一通过：

1. `elf.py` 分析组摘要成功传入 Agent；
2. Agent 能使用 GhidraMCP 建立攻击面地图；
3. Agent 能提出和解释自定义 source/sink wrapper；
4. Agent 能保留候选、排除和 unresolved 状态；
5. 仍需要阶段二的 `FunctionSecurityModel`、`AnalysisCoverageLedger` 验证器和参数级路径后端，才能把 candidate 提升为 confirmed。

## 参数路径后端联调

在同一个 `server` ELF 上启用 `AGENT_PATH_BACKEND_PYTHON` 后，OpenCode 同时加载 GhidraMCP 和 `paths` MCP server。Agent 对两个 sink 发起了参数查询：

```text
query_sink_paths(popen, 0)  → path_found
query_sink_paths(system, 0) → path_found
```

`popen` 查询返回：

- caller：`doSystem`；
- callsite：`0x401be7`；
- sink argument：`0`；
- RDA 定义链：寄存器、栈变量和调用点前的参数定义；
- 限制：source 可控性和跨函数完整性仍需继续验证。

`system` 查询的定义链最终指向常量 `"./files/recv"`。Agent 将该路径判为 `rejected`，而不是漏洞候选。

本次联调确认：

1. Agent 能发现自定义 `remoteExec → doSystem → popen` 路径；
2. 静态后端能够返回 sink 参数级定义链；
3. 常量输入可以作为误报排除证据；
4. `path_found` 仍不等于完整污点证明，最终状态必须保留限制；
5. 未加载的 `libauth.so`、`liblog.so` 和未解析间接调用进入 unresolved。
