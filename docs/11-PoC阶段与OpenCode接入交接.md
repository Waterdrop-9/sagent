# PoC 阶段与 OpenCode 接入交接

本文用于恢复当前 PoC 阶段的开发。本文只描述当前实现和下一步检查项，不执行 Agent、样本或 PoC。

## 当前目标

PoC 是分析工作流的独立末阶段：

```text
ELF 分析组
  → GhidraMCP 攻击面分析
  → 静态路径查询
  → 证据整合和误报复核
  → 最终 findings
       ├─ confirmed
       └─ rejected
  → 只把 confirmed findings 交给 PoC 阶段
  → OpenCode 生成静态审计 PoC 或人工验证步骤
```

`candidate`、`unknown`、`unsupported`、`failed` 和 `inconclusive` 都不能进入 PoC。它们保留在 `unresolved` 或覆盖账本中。

## 当前代码位置

- `src/agent/poc_stage.py`：读取 PoC 阶段模板，检查输入 finding 的状态并构造独立 PoC prompt。
- `src/agent/cli.py`：分析报告完成后筛选 `status == "confirmed"`，再创建独立 PoC 请求。
- `src/agent/runtime.py`：`OpenCodeRuntime` 负责启动 `opencode run --standalone`；运行前把调用方环境里过期的 `PWD` 修正为实际 cwd（opencode 用 `PWD` 做项目发现，不一致会读不到 cwd 下的 `.opencode/opencode.json`）；运行后删除临时配置并清理空的 `.opencode/` 目录，保持工作目录（如 `poc/`）干净。
- `src/agent/config.py`：读取 `[poc]` 配置。
- `prompts/poc-stage.md`：仓库内专用 PoC 阶段模板（Sagent 自建，不依赖外部文件；报告叙事结构借鉴 vulnhunter 的 PoC 生成 prompt 思想，契约仍由 Sagent 自己定义）。
- `config.toml.example`：PoC 配置示例。

CLI 入口：

```bash
PYTHONPATH=src python3 -m agent.cli \
  --config config.toml \
  --target <elf> \
  --dependency-root <dependency-root> \
  --cwe CWE-78 \
  --goal "完成静态分析和证据复核" \
  --poc \
  --output tests/YYYYMMDD_序号_目的_rxx/产物
```

`--poc` 与本地 `[poc].enabled = true` 任一满足即可启用阶段；两者都关闭时只运行分析阶段。

## OpenCode 调用链

分析阶段和 PoC 阶段共用 `OpenCodeRuntime`，但请求是两次独立调用：

1. 分析请求使用 CWE prompt、分析组上下文和 Ghidra/paths MCP 配置。
2. 本地程序解析 Agent JSON，重新核验 evidenceID 和覆盖账本。
3. 只筛选最终 `findings` 中的 `confirmed` 项。
4. 创建 `<run>/poc/`，把请求写入 `<run>/poc-request.md`。
5. 使用 `AgentRequest` 调用 OpenCode，工作目录为 `<run>/poc/`。
6. OpenCode 返回后写入 `<run>/poc-response.md` 和 `<run>/poc-manifest.json`。
7. 不执行 response 中的脚本、样本、网络请求或生成的命令。

request/response/manifest 属于流程账目，放在 run 目录顶层；`poc/` 目录只留给模型生成的 PoC 报告。

OpenCode 请求使用分析运行时的 provider、model、API Key 和 base URL。MCP 配置由分析阶段生成，并由 OpenCode runtime 临时写入请求工作目录的 `.opencode/opencode.json`；请求结束后恢复或删除该临时文件。

## PoC 产物

confirmed finding 触发 PoC 时，目录应包含：

```text
<run>/
├── poc-request.md
├── poc-response.md
├── poc-manifest.json
└── poc/
    ├── <functionID>.CWE-78.poc.md   # PoC 报告（8 小节叙事）
    └── <functionID>.CWE-78.poc.py   # 验证脚本（借鉴 vh 的 poc/<name>.py）
```

`poc-manifest.json` 至少记录：

```json
{
  "stage": "poc",
  "runtime": "opencode",
  "findingCount": 1,
  "findingIDs": ["<binaryID>/<functionID>"],
  "request": "poc-request.md",
  "response": "poc-response.md",
  "executed": false
}
```

没有 confirmed finding 时不创建 PoC 请求，报告应记录：

```json
{
  "poc": {
    "status": "skipped_no_confirmed_findings",
    "findingCount": 0
  }
}
```

## 配置

当前配置字段是：

```toml
[poc]
enabled = false
prompt_file = "prompts/poc-stage.md"
```

`prompt_file` 相对路径按 config.toml 所在目录解析。模板是 Sagent 自建的 `prompts/poc-stage.md`，不再引用外部 `config/assistant/AGENTS.md.template`。

PoC 阶段模板必须描述：只处理 confirmed findings、引用已有 evidenceIDs、生成静态审计材料、把文件写入当前 `poc/` 工作目录，并保持 `executed = false`。模板不应承担漏洞重新判断、source/sink 重新发现或覆盖账本判定。

报告叙事结构（基本信息/触发条件/输入形态/调用路径/关键参数/人工验证步骤/证据引用/限制与不确定性）和"每个 finding 配一个可运行验证脚本"的产出方式借鉴了 vulnhunter（`vulnhunter_v2_local/config/`）的 PoC 生成 prompt 思想；借鉴仅限 prompt 组织方式，vulnhunter 源码本身不被修改。模板要求 `poc/` 目录里只写 PoC 报告和验证脚本，不写笔记、日志、配置等其它文件，也不创建子目录；验证脚本只生成不执行，由人工在隔离环境运行（`executed` 保持 false）。

外部漏洞分析问题目录不属于 PoC 阶段。不要把 `config/foolish/*.md` 当作 PoC prompt，也不要用它驱动 PoC 请求。

## 最近验证结论

- `OpenCodeRuntime` 已有独立请求能力，fake OpenCode CLI 的端到端测试通过。
- PoC 阶段模板已换成仓库内 `prompts/poc-stage.md`（报告叙事结构与验证脚本产出方式借鉴 vulnhunter 的 PoC prompt 思想），模板契约测试（只处理 confirmed、只引用已有 evidenceIDs、executed 保持 false、不重判/不重发现/不做账本判定、8 小节结构与 poc/ 干净要求）全部通过。
- fake OpenCode 全链路测试通过：confirmed 触发时 run 级 `poc-request.md`/`poc-response.md`/`poc-manifest.json` 落盘、manifest 结构正确、cwd 是 `<run>/poc/`、`poc/` 目录里只有模型生成的报告和验证脚本；无 confirmed 时报告 `skipped_no_confirmed_findings` 且不建 `poc/`。
- confirmed fixture（`doSystem`，5 个真实 evidenceID）已通过本地证据门禁，run 产物在 `tests/20261012_02_PoC阶段_r01/产物/group-6aeb5375a9c368ad/run-4a9b6b216ae1/`。
- 真实 OpenCode PoC 请求已成功（新模板 + 干净布局）：模型只引用已有 evidenceID，生成 `poc/doSystem.CWE-78.poc.md`（8 小节：基本信息/触发条件/输入形态/调用路径/关键参数/人工验证步骤/证据引用/限制与不确定性，人工验证步骤全部标注“需人工执行”）和可运行的 `poc/doSystem.CWE-78.poc.py`（--host/--port/--command 命令行参数、默认端口 8002=0x1f42 有证据出处、默认只发无害命令 `id`、带超时与异常处理、仅供授权隔离环境由人工执行）；`poc-manifest.json` 记录 `executed: false`；未执行样本。
- 真实请求暴露并修复了一个运行时缺陷：调用方 shell 携带过期 `PWD`（指向仓库根）时 opencode 项目发现失效，报 `Model unavailable`；`_CliRuntime.run` 现在把 `PWD` 修正为实际 cwd，并有回归测试。
- 真实 `server` demo 的静态路径后端曾返回 `path_found`，但 RDA 只提供函数内定义链；demo 自身最终无 confirmed finding，PoC 为 `skipped_no_confirmed_findings`。验证“成功生成 PoC”走 confirmed fixture 路径。

## 恢复后的检查顺序

1. 检查 `src/agent/poc_stage.py` 的模板契约，确认模板不是外部漏洞分析问题清单。—— 已完成：模板为 `prompts/poc-stage.md`。
2. 检查 `cli.py` 只从最终 `findings` 筛选 `confirmed`，不从 functionModels、candidate 或 coverage 计数推断。—— 已完成。
3. 检查 PoC 请求的 cwd 是 `<run>/poc/`，并确认 request/response/manifest 在 run 目录顶层独立保存、`poc/` 里只有模型生成的报告和验证脚本。—— 已完成，fake 测试断言 cwd 为 poc 绝对路径与干净目录。
4. 用 fake OpenCode 验证文件落盘和 manifest 内容；这个测试不执行样本。—— 已完成，`tests/20261012_02_PoC阶段_r01/test_poc_cli.py`。
5. 准备有真实 evidenceID 的 confirmed fixture 后，再用 OpenCode 做一次真实 PoC 请求。—— 已完成，fixture 与真实请求脚本见 `tests/20261012_02_PoC阶段_r01/`。
6. 真实请求完成后，把产物放在对应 `tests/.../产物/`；`tests/` 目录继续保持 gitignore。—— 已完成。

后续恢复时的收尾：把本次改动整理提交（PoC 模板、runtime 的 PWD 修复、模板契约测试、文档更新）；`tests/` 下新增实验目录不进入版本库。
