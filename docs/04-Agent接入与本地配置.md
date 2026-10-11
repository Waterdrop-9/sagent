# Agent 接入与本地配置

状态：配置设计与 Agent adapter 原型。

## 已确认方向

使用自有 Agent 适配层，首期接入 Claude Code 和 OpenCode，并支持通过各自底座配置选择模型。Agent 底座与模型提供方分开配置。

当前原型通过 CLI adapter 调用两个生产级 Agent 底座：Claude Code 使用非交互 print 模式，OpenCode 使用 `run` 模式。具体命令参数和 MCP 配置只存在于 adapter 内部。

Agent 的 prompt 和工具由 CWE 插件提供。Prompt 以 `prompts/<cwe>/` 下的 Markdown 文件保存，工具通过 MCP stdio server 暴露给底座，业务层不直接依赖某个 Agent 的内部工具格式。整体设计见 [Agent 底座、工具和 CWE 插件 MVP](./05-Agent循环与CWE插件MVP.md)。

## 配置草案

长期配置仍可使用本地 `config.toml` 设置底座、提供方、模型、地址和 API Key。当前 MVP 使用 CLI 参数选择底座，MCP 配置由插件在运行期间生成：

```toml
[agent]
runtime = "claude"

[model]
provider = "deepseek"
model = ""
base_url = ""
api_key = ""
# 可改用环境变量；指定时优先读取该变量，缺失则报错。
api_key_env = ""
```

支持直接配置 API Key，也支持环境变量引用。实际密钥不写入日志和报告；本地配置文件不提交，仓库只保留无密钥示例。

读取配置时校验必需字段。连接错误、鉴权失败和模型不可用分别报告，不能变成空分析结果。

## 当前原型限制

- 本机必须自行安装 Claude Code 或 OpenCode 并完成认证。
- 当前只提供 CWE-78 插件和 `query_sink_paths` fixture 工具。
- CWE-78 prompt 位于 `prompts/cwe-78/system.md` 和 `prompts/cwe-78/task.md`，修改 prompt 不需要修改 Python。
- Ghidra 静态分析适配器和实际模型服务配置仍待接入。

依赖检索仍然独立于 Agent 底座；Agent 只消费静态分析工具返回的结构化证据。
