"""Anthropic Messages 兼容的直接 LLM 客户端。

本模块用标准库 HTTP 直接请求 ``{base_url}/v1/messages``，不经过 claude/opencode
CLI，也不引入模型 SDK。调用契约只有一个：``client(messages: [{role, content}])``
返回模型文本；调用方（如 ``risk_chains.classify_with_llm``）只依赖这个函数签名
（GUIDELINE §9），换协议只动本模块。

端点设置从 ``SAGENT_LLM_BASE_URL`` / ``SAGENT_LLM_API_KEY`` / ``SAGENT_LLM_MODEL``
读取，见 ``llm_client_from_env``：凭据走环境变量，不落盘。

只实现真实用到的那部分协议：system 顶层参数、max_tokens、content 文本块。
不做流式、工具调用、多轮会话和图片输入。
"""

from __future__ import annotations

import json
import logging
import math
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Protocol

LOG = logging.getLogger(__name__)

# Anthropic 协议版本头；Claude 兼容端点（含官方 /v1/messages）都要求它。
ANTHROPIC_VERSION = "2023-06-01"

# 模型输出预算。推理模型会先产出 thinking 块再输出正文，预算太小会把预算全烧在
# 思考上、正文为空（实测 deepseek-flash：max_tokens=2048 时整段预算用于思考、
# content 无文本块；8192 时才拿到正文）。短 JSON 回答也要给足思考余量。
DEFAULT_MAX_TOKENS = 8192

# 确定性要求：同一输入重复调用不应给出不同结果。
DEFAULT_TEMPERATURE = 0.0

# 未显式给出时的兜底地址：官方 Anthropic Messages API。
DEFAULT_ANTHROPIC_BASE_URL = "https://api.anthropic.com"

# 端点设置的环境变量名。凭据只存在于进程环境里，不写进落盘产物、不进日志。
ENV_API_KEY = "SAGENT_LLM_API_KEY"
ENV_BASE_URL = "SAGENT_LLM_BASE_URL"
ENV_MODEL = "SAGENT_LLM_MODEL"
ENV_MAX_TOKENS = "SAGENT_LLM_MAX_TOKENS"
ENV_TIMEOUT = "SAGENT_LLM_TIMEOUT"

# 错误信息里回显响应体的上限：够定位问题，不把整段模型输出灌进日志。
_ERROR_DETAIL_LIMIT = 300


class LlmClientError(RuntimeError):
    """LLM 端点不可达、拒绝请求或返回无法使用的结果。"""


class HttpResponse(Protocol):
    """urllib 响应的最小接口；测试用假响应实现它即可，不需要网络。"""

    status: int

    def read(self) -> bytes: ...


# 传输层注入点：默认是 urllib，测试替换为假实现。
# 返回 (状态码, 响应体字符串)；HTTP 错误响应也走返回值，不抛异常。
Opener = Callable[[urllib.request.Request, float], tuple[int, str]]


@dataclass(frozen=True)
class LlmSettings:
    """端点设置；base_url/api_key/model 三者齐全才构成一次可用调用。"""

    base_url: str
    api_key: str
    model: str
    max_tokens: int = DEFAULT_MAX_TOKENS
    timeout: float = 120.0

    def __post_init__(self) -> None:
        if not self.base_url.strip():
            raise ValueError("LLM base_url 不能为空")
        if not self.api_key.strip():
            raise ValueError("LLM api_key 不能为空")
        if not self.model.strip():
            raise ValueError("LLM model 不能为空")
        if type(self.max_tokens) is not int or self.max_tokens <= 0:
            raise ValueError("LLM max_tokens 必须是正整数")
        if not math.isfinite(self.timeout) or self.timeout <= 0:
            raise ValueError("LLM timeout 必须是有限正数")


def _summarize_http_error(error: urllib.error.HTTPError) -> str:
    """从 Anthropic 风格错误体里取出 message；取不到退回状态行。"""
    try:
        body = error.read().decode("utf-8", "replace")
    except Exception:  # 读取失败不影响我们要报告的原始错误
        return f"HTTP {error.code}"
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        payload = None
    if isinstance(payload, dict):
        detail = payload.get("error")
        if isinstance(detail, dict) and isinstance(detail.get("message"), str):
            return f"HTTP {error.code}: {detail['message']}"
    return f"HTTP {error.code}: {body.strip()[:_ERROR_DETAIL_LIMIT]}"


def _default_opener(request: urllib.request.Request, timeout: float) -> tuple[int, str]:
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return int(response.status), response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as error:
        # 4xx/5xx 用返回值表达，调用方统一按状态码判断错误类型。
        return int(error.code), error.read().decode("utf-8", "replace")


class MessagesClient:
    """``client(messages) -> 文本``：把 Anthropic Messages 协议收敛成一个函数。"""

    def __init__(
        self,
        settings: LlmSettings,
        *,
        opener: Opener = _default_opener,
        temperature: float | None = DEFAULT_TEMPERATURE,
    ) -> None:
        self.settings = settings
        self._opener = opener
        self._temperature = temperature
        # 需要用户把 {base_url}/v1/messages 配全时用这个属性拼地址。
        self.url = _messages_url(settings.base_url)

    def __call__(self, messages: list[dict[str, str]]) -> str:
        request = urllib.request.Request(
            self.url,
            data=_request_body(self.settings, messages, self._temperature),
            method="POST",
            headers={
                "content-type": "application/json",
                # 兼容端点可能只认其中一种鉴权头；两个都带。
                "x-api-key": self.settings.api_key,
                "authorization": f"Bearer {self.settings.api_key}",
                "anthropic-version": ANTHROPIC_VERSION,
                "accept": "application/json",
            },
        )
        try:
            status, body = self._opener(request, self.settings.timeout)
        except urllib.error.URLError as exc:
            # 网络不可达、DNS 失败和超时（TimeoutError 是 OSError 子类）。
            raise LlmClientError(f"LLM 端点不可达: {exc.reason}") from exc
        except OSError as exc:
            raise LlmClientError(f"LLM 请求失败: {exc}") from exc
        if status != 200:
            raise LlmClientError(f"LLM 端点返回错误: {_error_message(status, body)}")
        payload = _parse_payload(body)
        usage = payload.get("usage")
        if isinstance(usage, dict):
            LOG.info(
                "M2 分类调用 tokens in=%s out=%s stop=%s",
                usage.get("input_tokens"), usage.get("output_tokens"),
                payload.get("stop_reason"),
            )
        text = _extract_text(payload)
        if not text.strip():
            # 推理模型可能只产出 thinking 块（正文被 max_tokens 截断时为常态）。
            raise LlmClientError(
                f"LLM 响应没有文本块（stop_reason={payload.get('stop_reason')}）；"
                f"可提高 max_tokens（当前 {self.settings.max_tokens}）"
            )
        return text


def _messages_url(base_url: str) -> str:
    """由用户配置拼出 Messages 端点。

    官方文档给的是主机地址（``https://api.anthropic.com``），OpenAI 风格的兼容
    配置习惯带 ``/v1``；两种写法都应落到同一个端点，所以这里不做猜测试错，
    按后缀规则补全：已以 ``/messages`` 结尾就原样使用，已带版本段就只补
    ``/messages``，否则补 ``/v1/messages``。
    """
    trimmed = base_url.strip().rstrip("/")
    if not trimmed:
        raise ValueError("LLM base_url 不能为空")
    if not trimmed.startswith(("http://", "https://")):
        raise ValueError(f"LLM base_url 必须以 http:// 或 https:// 开头: {base_url}")
    path = trimmed.split("://", 1)[1]
    if path.endswith("/messages"):
        return trimmed
    if "/v1" in path:
        return trimmed + "/messages"
    return trimmed + "/v1/messages"


def _request_body(
    settings: LlmSettings, messages: list[dict[str, str]], temperature: float | None
) -> bytes:
    """把 [{role, content}] 收敛成 Messages 请求体。

    与 OpenAI 风格的差别只有一处：system 提示必须提到顶层 ``system`` 参数，
    不能作为 messages 里的角色（官方端点会直接 400）。这里同时兼容两者。
    """
    system_parts: list[str] = []
    conversation: list[dict[str, str]] = []
    for message in messages:
        role = str(message.get("role", ""))
        content = str(message.get("content", ""))
        if role == "system":
            system_parts.append(content)
        else:
            conversation.append({"role": role, "content": content})
    if not conversation:
        raise LlmClientError("Messages 请求至少需要一条非 system 消息")
    body: dict[str, Any] = {
        "model": settings.model,
        "max_tokens": settings.max_tokens,
        "messages": conversation,
    }
    if system_parts:
        body["system"] = "\n\n".join(system_parts)
    if temperature is not None:
        body["temperature"] = temperature
    return json.dumps(body, ensure_ascii=False).encode("utf-8")


def _parse_payload(body: str) -> dict[str, Any]:
    try:
        payload = json.loads(body)
    except json.JSONDecodeError as exc:
        raise LlmClientError(
            f"LLM 响应不是 JSON: {body.strip()[:_ERROR_DETAIL_LIMIT]}"
        ) from exc
    if not isinstance(payload, dict):
        raise LlmClientError("LLM 响应不是 JSON 对象")
    if payload.get("type") == "error":
        # 少数端点用 200 承载错误体；按错误处理，不能当成功解析。
        raise LlmClientError(f"LLM 端点返回错误: {_error_message(200, body)}")
    return payload


def _extract_text(payload: dict[str, Any]) -> str:
    """只拼接 text 块。

    内容数组里可能同时有 thinking/tool_use 块；把 thinking 当正文会让
    classify_with_llm 拿到推理过程而非 JSON，必须按类型过滤。
    """
    blocks = payload.get("content")
    if not isinstance(blocks, list):
        return ""
    return "".join(
        block.get("text", "")
        for block in blocks
        if isinstance(block, dict) and block.get("type") == "text"
    )


def _error_message(status: int, body: str) -> str:
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        payload = None
    if isinstance(payload, dict):
        detail = payload.get("error")
        if isinstance(detail, dict) and isinstance(detail.get("message"), str):
            return f"HTTP {status}: {detail['message']}"
    return f"HTTP {status}: {body.strip()[:_ERROR_DETAIL_LIMIT]}"


def _env_positive(raw: str | None, target: Callable[[str], Any]) -> Any | None:
    """把环境变量解析成正数；空值或非法值返回 None（调用方用默认值）。"""
    if raw is None or not raw.strip():
        return None
    try:
        value = target(raw.strip())
    except (TypeError, ValueError):
        return None
    return value if math.isfinite(value) and value > 0 else None


def llm_client_from_env(
    environ: Mapping[str, str] | None = None,
) -> MessagesClient | None:
    """从环境变量构造客户端；缺任一项时返回 None（调用方据此关闭可选功能）。

    ``llm_max_tokens`` / ``llm_timeout`` 也可由 ``SAGENT_LLM_MAX_TOKENS`` /
    ``SAGENT_LLM_TIMEOUT`` 覆盖，解析失败或非正数时按默认值处理。
    """
    env = os.environ if environ is None else environ
    base_url = (env.get(ENV_BASE_URL) or "").strip()
    api_key = (env.get(ENV_API_KEY) or "").strip()
    model = (env.get(ENV_MODEL) or "").strip()
    if not (base_url and api_key and model):
        return None
    overrides: dict[str, Any] = {}
    max_tokens = _env_positive(env.get(ENV_MAX_TOKENS), int)
    if max_tokens is not None:
        overrides["max_tokens"] = max_tokens
    timeout = _env_positive(env.get(ENV_TIMEOUT), float)
    if timeout is not None:
        overrides["timeout"] = timeout
    return MessagesClient(
        LlmSettings(base_url=base_url, api_key=api_key, model=model, **overrides)
    )
