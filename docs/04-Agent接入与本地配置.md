# Agent 接入与本地配置

状态：配置设计与 Agent adapter 原型。

## 接入方向

Sagent 通过统一 `AgentRuntime` 接入 Claude Code 和 OpenCode。后续开发主用 OpenCode，Claude Code 用于辅助验证。CWE prompt 保存在 `prompts/<cwe>/`，Ghidra 反编译和导航使用外部 [GhidraMCP](https://github.com/LaurieWired/GhidraMCP)。

## 配置文件

不要把本地配置直接提交。复制根目录模板：

```bash
cp config.toml.example config.toml
```

`config.toml` 只保存 Agent 相关配置：

```toml
[agent]
runtime = "opencode"
provider = "deepseek"
model = "deepseek-flash"
api_key = "sk-替换为你的 DeepSeek API Key"
base_url = "https://api.deepseek.com/v1"
timeout = 3600
```

API Key 直接写入本地 `config.toml`，不要提交该文件。DeepSeek 当前推荐模型名是 `deepseek-flash`；`deepseek-v4-flash` 是兼容旧名，不建议新配置继续使用。`base_url` 改成任意 OpenAI-compatible 服务地址即可使用本地模型。GhidraMCP 使用默认值；需要覆盖时使用环境变量：

```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra
export GHIDRA_MCP_EXTENSION_JAR=/path/to/GhidraMCP.jar
```

可选变量包括 `GHIDRA_MCP_MODE`、`GHIDRA_MCP_SERVER`、`GHIDRA_MCP_UVX`、`GHIDRA_MCP_PYTHON`、`GHIDRA_MCP_PACKAGE` 和 `GHIDRA_MCP_READY_TIMEOUT`（正整数秒）。它们属于部署环境设置，不写入项目配置模板。

参数级路径后端是可选依赖。安装 angr 的 Python 环境后，设置：

```bash
export AGENT_PATH_BACKEND_PYTHON=/path/to/python
```

Sagent 会额外注入 `paths` MCP server，提供 `query_sink_paths`。后端当前返回 RDA 定义链，不等同于完整污点证明；source 可控性、别名和间接调用限制会保留在结果中。

## 安装和验证

```bash
npm install -g --allow-scripts=@anthropic-ai/claude-code,@opencode/cli \
  @anthropic-ai/claude-code @opencode/cli
brew install ghidra
claude --version
claude doctor
opencode --version
java -version
```

GhidraMCP 扩展构建和 headless 验证步骤见根目录 [`部署与使用手册.md`](../部署与使用手册.md)。

## 运行

```bash
export ANTHROPIC_API_KEY="..."  # 使用 Claude 时设置对应变量
opencode auth login               # 使用 OpenCode 时完成 provider 登录
PYTHONPATH=src python3 -m agent.cli \
  --config config.toml \
  --target data/01_simple_demo/server \
  --goal "检查是否存在外部输入到命令执行的路径" \
  --dry-run
```

去掉 `--dry-run` 后由真实 Agent 执行。默认不执行样本。
