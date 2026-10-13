# Anthropic Messages 兼容客户端

本文描述 `src/agent/llm_client.py`：一个不依赖 CLI 底座、直接用标准库 HTTP 调用
Anthropic Messages 协议（`POST {base_url}/v1/messages`）的最小客户端。

## 职责与边界

职责：把一次「消息列表 → 模型文本」的调用翻译成 Anthropic Messages 请求，并把响应
还原成文本。调用契约只有一个：

```python
client(messages: list[dict[str, str]]) -> str
```

边界（明确不做）：流式输出、工具调用、多轮会话、图片输入、重试与限流。
`client` 只做一次请求，失败即抛 `LlmClientError`，重试策略由调用方决定。

## 为什么需要它

Sagent 的 Agent 循环走 `runtime.py` 的 `_CliRuntime`，它只负责**启动外部 CLI**
（`claude -p` / `opencode run`），工具循环由那个 CLI 自己实现。因此「sagent 能不能用
Claude 接口」原本取决于外部 CLI：

- `runtime = "claude"` 需要本机装 `claude` CLI，它通过 `ANTHROPIC_API_KEY` /
  `ANTHROPIC_BASE_URL` 连 Claude 兼容端点（`config.agent_environment` 就是为此准备环境变量）；
- 缺 CLI 时无法直接使用 API key 跑分析。

本模块提供脱离 CLI 的最小协议实现，供**不需要工具循环**的调用点使用（当前唯一的已知
消费方是阶段 M2 的语义分类 `risk_chains.classify_with_llm`）。它不替代 `_CliRuntime`：
带工具的 Agent 阶段仍然走 CLI 底座。

## 接口与配置

```python
from agent.llm_client import llm_client_from_env

client = llm_client_from_env()      # 环境变量不全时返回 None
if client is not None:
    text = client([{"role": "system", "content": "..."},
                   {"role": "user", "content": "..."}])
```

端点设置全部来自环境变量，**凭据不落盘、不进日志**：

| 变量 | 含义 | 缺省 |
| --- | --- | --- |
| `SAGENT_LLM_BASE_URL` | 兼容端点基址 | 无（必填；缺失即返回 None） |
| `SAGENT_LLM_API_KEY` | API key | 无（必填） |
| `SAGENT_LLM_MODEL` | 模型名 | 无（必填） |
| `SAGENT_LLM_MAX_TOKENS` | 单次输出预算 | `DEFAULT_MAX_TOKENS` = 8192 |
| `SAGENT_LLM_TIMEOUT` | 单次请求超时秒数 | 120 |

后两项解析失败（空值、非数字、非正数、`inf`）时退回默认值，不会静默变成 0。

`LlmSettings` 是显式构造入口，字段为 `base_url` / `api_key` / `model` /
`max_tokens` / `timeout`，三者齐全才构成一次可用调用，缺一即 `ValueError`。

## URL 规则（不猜协议）

`_messages_url` 按 Anthropic 文档的形状归一，规则确定、无启发式：

| 输入的 base_url | 请求地址 |
| --- | --- |
| `https://api.anthropic.com` | `https://api.anthropic.com/v1/messages` |
| `https://api.anthropic.com/v1` | `https://api.anthropic.com/v1/messages` |
| `https://api.deepseek.com/anthropic` | `https://api.deepseek.com/anthropic/v1/messages` |
| `.../v1/messages`（已完整） | 原样使用 |

非 `http(s)` 基址直接 `ValueError`。同一个主机可能同时提供两套协议（DeepSeek 的
`/v1` 是 OpenAI 兼容、`/anthropic` 是 Messages 兼容），地址猜不出来，**必须由调用方
显式给出**；客户端不对 `base_url` 做协议探测。

## 协议要点

- `system` 必须提升为顶层参数：放进 `messages` 的 `role="system"` 会被官方端点 400 拒绝。
  多条 system 消息以空行拼接。
- 请求头：`x-api-key` + `anthropic-version: 2023-06-01` + `content-type: application/json`。
- `messages` 至少需要一条非 system 消息，否则本地即拒绝，不发请求。
- 默认 `temperature = 0`：同一输入重复调用应给出相同结果。

### content 块过滤

响应 `content` 是块数组，**只有 `type == "text"` 的块拼成返回值**。推理模型会先输出
`thinking` 块（如 `deepseek-flash`、Claude 扩展思考模式），把 thinking 当正文会让
JSON 解析必然失败。

预算给不足时模型可能整个预算都花在思考上、正文为空。实测（`deepseek-flash`，输入
约 1.4 KB 分类任务）：`max_tokens=2048` 时返回 `stop_reason=max_tokens`、无文本块；
8192 时才拿到正文。因此默认预算取 8192，且正文为空时错误信息里带上 `stop_reason`
和当前预算，便于定位。

## 失败行为

所有失败都收敛成 `LlmClientError`，异常文本**不含 api key**：

| 情况 | 异常文本 |
| --- | --- |
| HTTP 4xx/5xx | `HTTP <status>: <错误体 message 或截断的响应体>`（截断上限 300 字符） |
| HTTP 200 但 `type == "error"` | 同上，按错误体处理 |
| 响应不是 JSON | 提示响应不是 JSON（附截断片段） |
| 正文无文本块 | `LLM 响应没有文本块（stop_reason=...）；可提高 max_tokens（当前 N）` |
| 连接失败/超时 | 端点不可达 / 请求失败（附原因） |

调用方（如 `classify_with_llm`）必须把 `LlmClientError` 当作可降级信号：可选增强功能
失败时退回确定性机制，不中断分析主流程。

## 验证

`tests/20261014_08_LLM接口兼容_r01/test_llm_client.py`（32 项）：

- 请求形状：system 顶层提升、`max_tokens`、鉴权头、超时、纯 system 请求被本地拒绝；
- content 块：thinking 不作文本、多文本块拼接、仅 thinking 时报错；
- 错误路径：HTTP 401/500 错误体、200+error、非 JSON、网络失败、超时、key 不回显；
- URL 规则四个分支 + 非 http 基址拒绝；
- 环境变量构造：合法覆盖、非法值退回默认、部分/空值关闭功能；
- 真实 HTTP 往返：用例内起 `ThreadingHTTPServer`，断言实际请求路径/头/体；
- 配置面：`config.toml` 出现 `anthropic_*` / `llm_*` 键必须显式报错。

传输层通过 `opener` 参数注入，单测不发真实网络请求。

## 接入状态

**阶段 M2（LLM 语义分类）暂未接入流水线**（用户决定，2026-10-14）：`cli.py` 与
`phase_m_worker.py` 都不构造本客户端，阶段 M 全程纯机械（`stats.m2Used == false`，
`chains[].semanticHints` 不出现），`config.toml` 也没有对应配置项。

因此本模块当前**不是流水线的一环**，只是已实现并测试过的能力。日后接入时：
需要决定端点配置的来源（配置项或环境变量）、在 `_run_phase_m` 里构造客户端并传入
`llm_client=`，并补一条 `risk-chains.json` 的 `m2Used` 断言。
