# Agent 接入与本地配置

状态：配置设计与 Agent adapter 原型。

## 已确认方向

使用自有 Agent 适配层，首期接入 Claude Code 和 OpenCode，并支持通过各自底座配置选择模型。Agent 底座与模型提供方分开配置。

当前原型通过 CLI adapter 调用两个生产级 Agent 底座：Claude Code 使用非交互 print 模式，OpenCode 使用 `run` 模式。具体命令参数和 MCP 配置只存在于 adapter 内部。

Agent 的 prompt 和工具由 CWE 插件提供。Prompt 以 `prompts/<cwe>/` 下的 Markdown 文件保存。反编译和二进制导航统一使用外部 [GhidraMCP](https://github.com/LaurieWired/GhidraMCP)，通过 MCP stdio server 注入 Claude/OpenCode；业务层不直接依赖 Ghidra API。整体设计见 [Agent 底座、工具和 CWE 插件 MVP](./05-Agent循环与CWE插件MVP.md)。

## 配置草案

长期配置仍可使用本地 `config.toml` 设置底座、提供方、模型、地址和 API Key。当前 MVP 使用 CLI 参数选择底座，MCP 配置由插件在运行期间生成。后续开发以 OpenCode 为主，Claude Code 作为辅助验证：

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

## 安装 Agent 和 Ghidra

macOS 上的安装命令：

```bash
npm install -g --allow-scripts=@anthropic-ai/claude-code,@opencode/cli \
  @anthropic-ai/claude-code @opencode/cli
brew install ghidra
```

安装后检查：

```bash
claude --version
claude doctor
opencode --version
ghidraRun
```

GhidraMCP 需要扩展 jar。先获取仓库并构建扩展：

```bash
git clone https://github.com/LaurieWired/GhidraMCP /tmp/GhidraMCP
GHIDRA_INSTALL_DIR="$(brew --prefix ghidra)/libexec" \
  "$(brew --prefix ghidra)/libexec/support/gradle/gradlew" \
  -p /tmp/GhidraMCP/extension buildExtension
unzip -p /tmp/GhidraMCP/extension/dist/*.zip \
  'GhidraMCP/lib/GhidraMCP.jar' > /tmp/GhidraMCP.jar
```

首次运行使用 headless GhidraMCP：

```bash
PYTHONPATH=src python3 -m agent.cli \
  --runtime opencode \
  --target data/01_simple_demo/server \
  --goal "检查是否存在外部输入到命令执行的路径" \
  --ghidra-install-dir "$(brew --prefix ghidra)/libexec" \
  --ghidra-extension-jar /tmp/GhidraMCP.jar \
  --dry-run
```

本机验证记录（2026-10-11）：Claude Code `2.1.296`、OpenCode `2.0.26` 已安装，Ghidra `12.1.2` 已安装；`claude doctor` 通过安装检查，但当前没有登录 Claude 或配置 API Key；OpenCode CLI 已能启动，但尚未完成 provider 登录。GhidraMCP headless MCP server 已使用 Ghidra 12.1.2 和构建出的 extension jar 完成 MCP 初始化验证。

后续开发默认使用 OpenCode：

```bash
opencode auth login
```

Claude Code 作为辅助验证：

```bash
claude
```

真实调用前需要分别完成 Claude Code 和 OpenCode 的账号或 API 配置。GhidraMCP 也支持打开 Ghidra GUI 插件后使用 `--ghidra-mode gui --ghidra-server http://127.0.0.1:8080/`。

## 当前原型限制

- 本机必须自行安装 Claude Code 或 OpenCode 并完成认证。
- 当前只提供 CWE-78 插件和 `query_sink_paths` fixture 工具。
- CWE-78 prompt 位于 `prompts/cwe-78/system.md` 和 `prompts/cwe-78/task.md`，修改 prompt 不需要修改 Python。
- GhidraMCP 已接入，当前提供反编译、函数、导入、导出、字符串、调用和交叉引用工具。
- 参数级静态污点传播工具仍在设计中；没有 `evidence` fixture 时，Agent 必须把 Ghidra 的调用/反编译观察标为候选证据。

依赖检索仍然独立于 Agent 底座；Agent 只消费静态分析工具返回的结构化证据。
