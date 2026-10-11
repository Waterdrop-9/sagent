# Agent 底座、工具和 CWE 插件 MVP

状态：原型 v1。

## 目标架构

Sagent 不实现自己的 LLM，也不把 Python 调度循环当作 Agent。它通过统一 interface 接入生产级 Agent 底座：

```text
Claude Code / OpenCode
        ↓ AgentRuntime
Sagent Agent 适配层
        ↓
CWE Prompt 插件 + MCP Tool 插件
        ↓
静态二进制分析工具
        ↓
路径、证据和结构化报告
```

Agent 负责理解目标、规划查询、调用工具、解释结果和形成报告。Sagent 负责提供稳定的 CWE 知识、工具能力、输入边界和证据格式。

## 已实现的 MVP

代码位于 `src/agent/`：

- `runtime.py`：统一 `AgentRuntime` interface，以及 Claude Code 和 OpenCode CLI adapter。
- `plugins.py`：CWE 插件 interface 和 CWE-78 插件；插件从 `prompts/cwe-78/*.md` 读取 system prompt 和任务模板，并提供 MCP 配置。
- `mcp_server.py`：最小 MCP stdio 工具桥，目前提供 `query_sink_paths`。
- `cli.py`：选择底座、加载插件、生成 MCP 配置并启动 Agent。

调用示例：

```bash
PYTHONPATH=src python3 -m agent.cli \
  --runtime claude \
  --target data/01_simple_demo/server \
  --goal "检查是否存在外部输入到命令执行的路径" \
  --fixture data/02_agent_mvp_cwe78_paths.json \
  --dry-run
```

Prompt 文件位于：

```text
prompts/
└── cwe-78/
    ├── system.md
    └── task.md
```

运行时会校验两个文件存在且非空。`task.md` 使用 `{target}` 和 `{goal}` 两个占位符；新增 CWE 时新增对应目录和 Markdown 文件，不需要把知识写进 Python。

安装 Claude Code 或 OpenCode 并完成其自身认证后，去掉 `--dry-run` 即由真实 Agent 执行；本机未安装对应 CLI 时，程序会明确报错，不会伪造分析结果。

## TaintSage 思想的落点

CWE-78 插件要求 Agent 从 `system` 等命令执行 sink 的敏感参数开始调用 `query_sink_paths`，工具返回跨函数数据依赖路径和证据。Agent 再根据 prompt 判断 source 是否可控、路径上是否有拼接和过滤，并输出候选发现。

这复用了 TaintSage 的 sink 驱动路径查询；路径判断和最终解释交给真实 Agent。当前不实现 TaintSage 的 state cache，也不引入 RAG。

## 插件契约

每个 CWE 插件提供：

- `cwe_id` 和名称；
- prompt 目录中的 system prompt 和任务模板；
- 工具 schema 和 MCP server 配置；
- 用户任务 prompt；
- 结构化报告要求。

新增 CWE 时，Agent 底座和 MCP transport 不变，只新增一个插件及其静态工具实现。CWE-190 等需要数值约束的类型可以在工具返回的路径事实中加入范围、长度和控制条件。

## 边界

- 当前 fixture 模拟静态分析结果，真实 Ghidra 适配器尚未实现。
- MCP server 当前只有 CWE-78 的路径查询工具。
- Claude/OpenCode 的 CLI 负责真正的规划和循环；Sagent 不复制它们的 Agent loop。
- 当前只做候选发现，工具证据不足时必须由 Agent 输出 `inconclusive` 或 `unresolved`。
- Claude 和 OpenCode 的配置格式由各自 adapter 负责，避免业务层绑定具体底座。
