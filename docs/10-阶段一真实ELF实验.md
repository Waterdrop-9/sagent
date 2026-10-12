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
- 原始 Agent coverage 不能作为完成证明；恢复后的本地产物门禁会重新核对工具 evidenceID、函数模型和每个 sink 参数。

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

## 报告结构门禁联调

在接入 `AgentReport` 校验后，完整真实请求仍能通过 CLI：

- `findings`：3 条；
- `unresolved`：3 条；
- `coverage`：包含程序、攻击面、sink 查询、候选模型和预算信息；
- `remoteExec`：`candidate`；
- 固定常量 `system` 路径：`rejected`；
- `receiveFile` 的非 CWE-78 路径：`rejected`。

CLI 会拒绝缺少 `findings`、`unresolved` 或 `coverage` 的输出，也会拒绝没有 `evidenceIDs` 或状态值非法的 finding。

## 本地产物复核

2026-10-12 使用同一次真实响应写入 [`tests/20261012_01_覆盖门禁_r01/产物/真实server联调_r01/`](../tests/20261012_01_覆盖门禁_r01/产物/真实server联调_r01/) 后，Sagent 重新核验得到：

- 3 条 `path_found` 查询，按解析后的 sink 地址与外部函数模型匹配；
- 11 个函数模型，其中 Agent 使用的 `sink_wrapper`、`validator` 和对象形式 `propagationMap` 被归一化为内部模型；
- `analysisStatus=inconclusive`，阻塞项包含未知攻击面、依赖库未在同一 Ghidra 会话加载、跨函数路径未覆盖、candidate 模型和无本地证据的静态观察；
- Agent 自报的 `pathToolResult` 没有生成查询记录，只有 paths MCP 代理实际保存的 JSONL 才能进入账本。

这次复核说明 `path_found` 可以成为证据，但不能单独把 finding 提升为 confirmed，也不能把未覆盖范围当作安全。

## 长 Prompt、静态工具和 PoC 门禁复跑

2026-10-12 重新整理 CWE prompt 后，每类 CWE 使用一个完整 Markdown 文件，CWE-78 文件约 150 行，包含外部问题清单中的攻击面、检查步骤、判定、覆盖和反作弊规则，并叠加 Sagent 的 GhidraMCP/evidence 约束。

先运行静态路径后端健康检查：

```bash
PYTHONPATH=src python3 scripts/static_analysis/check_path_backend.py \
  --python /tmp/sagent-angr-venv/bin/python \
  --binary data/01_simple_demo/server \
  --sink-function popen \
  --max-depth 4 --max-nodes 200
```

结果为 `path_found`，sink 为 `popen@0x401380`，返回 1 条调用点定义链，并保留 RDA 限制。

随后使用 `--poc` 复跑真实 Agent。结果为 1 条 `rejected`（固定 `system` 常量路径）、0 条 `confirmed`、整轮 `analysisStatus=inconclusive`；PoC 状态为 `skipped_no_confirmed_findings`，没有调用 PoC Agent，也没有生成或执行 PoC。候选命令注入路径和跨库路径进入 `unresolved`。
