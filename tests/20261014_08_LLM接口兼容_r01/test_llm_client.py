"""Anthropic Messages 兼容客户端（llm_client.py）单元测试。

覆盖协议形状（system 顶层参数、max_tokens、鉴权头）、content 块过滤（thinking
块不能当正文）、错误处理（HTTP 错误/网络失败/空正文一律降级）、环境变量构造与
key 不进异常文本。另有一个起真实 HTTP 服务的用例，端到端验证标准库请求路径。
"""

from __future__ import annotations

import json
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from agent.config import ConfigError, load_config
from agent.llm_client import (
    ANTHROPIC_VERSION,
    DEFAULT_MAX_TOKENS,
    ENV_API_KEY,
    ENV_BASE_URL,
    ENV_MAX_TOKENS,
    ENV_MODEL,
    ENV_TIMEOUT,
    LlmClientError,
    LlmSettings,
    MessagesClient,
    _extract_text,
    _messages_url,
    llm_client_from_env,
)
from agent.risk_chains import classify_with_llm


class StubResponse:
    def __init__(self, body: str, status: int = 200) -> None:
        self.status = status
        self._body = body.encode("utf-8")

    def read(self) -> bytes:
        return self._body


class RecordingOpener:
    """假传输层：记录请求对象，返回预置响应。"""

    def __init__(self, body: str = "{}", status: int = 200) -> None:
        self.body = body
        self.status = status
        self.requests: list = []
        self.timeouts: list[float] = []

    def __call__(self, request, timeout):
        self.requests.append(request)
        self.timeouts.append(timeout)
        return self.status, self.body

    @property
    def payload(self) -> dict:
        request = self.requests[-1]
        return json.loads(request.data.decode("utf-8"))

    @property
    def headers(self) -> dict:
        return {key.lower(): value for key, value in self.requests[-1].headers.items()}


def reply(*blocks: dict, stop_reason: str = "end_turn", usage: dict | None = None) -> str:
    return json.dumps({
        "id": "msg_1",
        "type": "message",
        "role": "assistant",
        "model": "stub",
        "content": list(blocks),
        "stop_reason": stop_reason,
        "usage": usage or {"input_tokens": 10, "output_tokens": 5},
    })


def text_block(text: str) -> dict:
    return {"type": "text", "text": text}


def thinking_block(thinking: str) -> dict:
    return {"type": "thinking", "thinking": thinking, "signature": "sig"}


def settings(**overrides) -> LlmSettings:
    values = {
        "base_url": "https://api.anthropic.com",
        "api_key": "sk-test-key",
        "model": "claude-x",
        "timeout": 5.0,
    }
    values.update(overrides)
    return LlmSettings(**values)


class RequestShapeTests(unittest.TestCase):
    def test_system_hoisted_and_messages_kept(self):
        opener = RecordingOpener(reply(text_block('{"ok":true}')))
        client = MessagesClient(settings(), opener=opener)
        text = client([
            {"role": "system", "content": "只做分类"},
            {"role": "user", "content": "输入"},
        ])
        self.assertEqual(text, '{"ok":true}')
        payload = opener.payload
        # system 必须是顶层参数：放进 messages 角色会被官方端点 400 拒绝。
        self.assertEqual(payload["system"], "只做分类")
        self.assertEqual(payload["messages"], [{"role": "user", "content": "输入"}])
        self.assertEqual(payload["model"], "claude-x")
        self.assertEqual(payload["max_tokens"], DEFAULT_MAX_TOKENS)

    def test_multiple_system_messages_joined(self):
        opener = RecordingOpener(reply(text_block("x")))
        MessagesClient(settings(), opener=opener)([
            {"role": "system", "content": "a"},
            {"role": "system", "content": "b"},
            {"role": "user", "content": "hi"},
        ])
        self.assertEqual(opener.payload["system"], "a\n\nb")
        self.assertEqual(opener.payload["messages"], [{"role": "user", "content": "hi"}])

    def test_auth_and_version_headers(self):
        opener = RecordingOpener(reply(text_block("x")))
        MessagesClient(settings(), opener=opener)([{"role": "user", "content": "hi"}])
        headers = opener.headers
        self.assertEqual(headers["x-api-key"], "sk-test-key")
        self.assertEqual(headers["anthropic-version"], ANTHROPIC_VERSION)
        self.assertEqual(opener.timeouts[-1], 5.0)

    def test_only_system_messages_is_rejected_without_request(self):
        opener = RecordingOpener(reply(text_block("x")))
        with self.assertRaises(LlmClientError):
            MessagesClient(settings(), opener=opener)([{"role": "system", "content": "s"}])
        self.assertEqual(opener.requests, [])


class ContentBlockTests(unittest.TestCase):
    def test_thinking_block_is_not_returned_as_text(self):
        # 推理模型先出 thinking 再出正文；把 thinking 当正文会让 M2 解析失败。
        opener = RecordingOpener(reply(thinking_block("我先想想"), text_block('{"ok":1}')))
        text = MessagesClient(settings(), opener=opener)([{"role": "user", "content": "hi"}])
        self.assertEqual(text, '{"ok":1}')
        self.assertNotIn("想想", text)

    def test_multiple_text_blocks_concatenated(self):
        opener = RecordingOpener(reply(text_block('{"a"'), text_block(":1}")))
        text = MessagesClient(settings(), opener=opener)([{"role": "user", "content": "hi"}])
        self.assertEqual(text, '{"a":1}')

    def test_extract_text_ignores_unknown_blocks(self):
        payload = {"content": [{"type": "tool_use", "id": "t"}, thinking_block("t"), text_block("ok")]}
        self.assertEqual(_extract_text(payload), "ok")

    def test_thinking_only_response_raises(self):
        opener = RecordingOpener(reply(thinking_block("只有思考"), stop_reason="max_tokens"))
        with self.assertRaises(LlmClientError) as ctx:
            MessagesClient(settings(), opener=opener)([{"role": "user", "content": "hi"}])
        self.assertIn("没有文本块", str(ctx.exception))
        self.assertIn("max_tokens", str(ctx.exception))


class ErrorHandlingTests(unittest.TestCase):
    def test_http_error_message_extracted(self):
        body = json.dumps({"error": {"type": "authentication_error",
                                     "message": "Authentication Fails"}})
        opener = RecordingOpener(body, status=401)
        with self.assertRaises(LlmClientError) as ctx:
            MessagesClient(settings(), opener=opener)([{"role": "user", "content": "hi"}])
        self.assertIn("HTTP 401", str(ctx.exception))
        self.assertIn("Authentication Fails", str(ctx.exception))

    def test_api_key_not_leaked_in_error_text(self):
        secret = "sk-super-secret-value-1234"
        opener = RecordingOpener("upstream exploded", status=500)
        with self.assertRaises(LlmClientError) as ctx:
            MessagesClient(settings(api_key=secret), opener=opener)(
                [{"role": "user", "content": "hi"}]
            )
        # 端点可能回显被掩码的 key 前缀；完整 key 不能出现在错误文本里。
        self.assertNotIn(secret, str(ctx.exception))

    def test_status_200_error_body_is_treated_as_error(self):
        opener = RecordingOpener(json.dumps({"type": "error",
                                             "error": {"message": "overloaded"}}))
        with self.assertRaises(LlmClientError) as ctx:
            MessagesClient(settings(), opener=opener)([{"role": "user", "content": "hi"}])
        self.assertIn("overloaded", str(ctx.exception))

    def test_non_json_response_raises_without_crashing(self):
        opener = RecordingOpener("<html>gateway</html>")
        with self.assertRaises(LlmClientError) as ctx:
            MessagesClient(settings(), opener=opener)([{"role": "user", "content": "hi"}])
        self.assertIn("不是 JSON", str(ctx.exception))

    def test_network_failure_is_wrapped(self):
        import urllib.error

        def failing(request, timeout):
            raise urllib.error.URLError("connection refused")

        with self.assertRaises(LlmClientError) as ctx:
            MessagesClient(settings(), opener=failing)([{"role": "user", "content": "hi"}])
        self.assertIn("不可达", str(ctx.exception))

    def test_timeout_is_wrapped(self):
        def timing_out(request, timeout):
            raise TimeoutError("timed out")

        with self.assertRaises(LlmClientError) as ctx:
            MessagesClient(settings(), opener=timing_out)([{"role": "user", "content": "hi"}])
        self.assertIn("请求失败", str(ctx.exception))


class UrlTests(unittest.TestCase):
    def test_documented_and_openai_style_bases_land_on_same_endpoint(self):
        expected = "https://api.anthropic.com/v1/messages"
        for raw in ("https://api.anthropic.com",
                    "https://api.anthropic.com/",
                    "https://api.anthropic.com/v1"):
            self.assertEqual(_messages_url(raw), expected)

    def test_already_complete_url_unchanged(self):
        raw = "https://proxy.internal/anthropic/v1/messages"
        self.assertEqual(_messages_url(raw), raw)

    def test_provider_specific_path_preserved(self):
        self.assertEqual(
            _messages_url("https://api.deepseek.com/anthropic"),
            "https://api.deepseek.com/anthropic/v1/messages",
        )

    def test_non_http_base_rejected(self):
        for raw in ("", "   ", "api.anthropic.com", "ftp://host"):
            with self.assertRaises(ValueError):
                _messages_url(raw)


class SettingsValidationTests(unittest.TestCase):
    def test_missing_fields_rejected(self):
        for overrides in ({"base_url": ""}, {"api_key": ""}, {"model": "  "}):
            with self.assertRaises(ValueError):
                settings(**overrides)

    def test_bad_budget_and_timeout_rejected(self):
        for overrides in ({"max_tokens": 0}, {"max_tokens": 1.5}, {"timeout": 0}, {"timeout": float("inf")}):
            with self.assertRaises(ValueError):
                settings(**overrides)


class EnvironmentFactoryTests(unittest.TestCase):
    """环境变量驱动的构造路径：凭据与端点只经环境传递，不落盘。"""

    def test_full_env_builds_client(self):
        client = llm_client_from_env({
            ENV_BASE_URL: "https://api.deepseek.com/anthropic",
            ENV_API_KEY: "sk-env",
            ENV_MODEL: "deepseek-flash",
        })
        self.assertIsNotNone(client)
        self.assertEqual(client.settings.api_key, "sk-env")
        self.assertEqual(client.settings.max_tokens, DEFAULT_MAX_TOKENS)
        self.assertEqual(client.url, "https://api.deepseek.com/anthropic/v1/messages")

    def test_budget_and_timeout_overrides(self):
        client = llm_client_from_env({
            ENV_BASE_URL: "https://host/anthropic",
            ENV_API_KEY: "sk-env",
            ENV_MODEL: "m",
            ENV_MAX_TOKENS: "512",
            ENV_TIMEOUT: "30.5",
        })
        self.assertEqual(client.settings.max_tokens, 512)
        self.assertEqual(client.settings.timeout, 30.5)

    def test_invalid_overrides_fall_back_to_defaults(self):
        # 非法预算/超时不静默变成 0，而是退回默认值（否则请求必然被端点拒绝）。
        def built(**env):
            return llm_client_from_env({
                ENV_BASE_URL: "https://host/anthropic", ENV_API_KEY: "k", ENV_MODEL: "m", **env,
            }).settings

        for bad in ("0", "-1", "abc", "  ", "1.5"):
            self.assertEqual(built(**{ENV_MAX_TOKENS: bad}).max_tokens, DEFAULT_MAX_TOKENS, bad)
        for bad in ("0", "-1", "abc", "  ", "inf"):
            self.assertEqual(built(**{ENV_TIMEOUT: bad}).timeout, 120.0, bad)
        # 合法值仍生效，确认上一条不是「永远返回默认值」。
        self.assertEqual(built(**{ENV_MAX_TOKENS: "512"}).max_tokens, 512)
        self.assertEqual(built(**{ENV_TIMEOUT: "0.5"}).timeout, 0.5)

    def test_partial_or_blank_env_disables_feature(self):
        self.assertIsNone(llm_client_from_env({}))
        self.assertIsNone(llm_client_from_env({ENV_BASE_URL: "https://host", ENV_MODEL: "m"}))
        self.assertIsNone(llm_client_from_env({ENV_BASE_URL: "", ENV_API_KEY: "k", ENV_MODEL: "m"}))
        self.assertIsNone(llm_client_from_env({ENV_BASE_URL: "  ", ENV_API_KEY: "k", ENV_MODEL: "m"}))

    def test_env_values_are_stripped(self):
        client = llm_client_from_env({
            ENV_BASE_URL: " https://host/anthropic \n",
            ENV_API_KEY: " sk-env ",
            ENV_MODEL: " m ",
        })
        self.assertEqual(client.settings.model, "m")
        self.assertEqual(client.settings.api_key, "sk-env")


class ConfigTests(unittest.TestCase):
    """配置文件不承载 LLM 端点：M2 未接入，出现这些键必须是显式报错而非静默忽略。"""

    def load(self, document: str):
        import tempfile

        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "config.toml"
            path.write_text(document, encoding="utf-8")
            return load_config(path).agent

    def test_existing_agent_keys_still_parse(self):
        agent = self.load(
            '[agent]\nruntime = "opencode"\nprovider = "deepseek"\n'
            'model = "deepseek-flash"\napi_key = "sk-agent"\n'
            'base_url = "https://api.deepseek.com/v1"\ntimeout = 60\n'
        )
        self.assertEqual(agent.model, "deepseek-flash")
        self.assertEqual(agent.base_url, "https://api.deepseek.com/v1")
        self.assertFalse(hasattr(agent, "anthropic_base_url"))

    def test_llm_related_keys_rejected(self):
        for key, value in (("anthropic_base_url", '"https://host/anthropic"'),
                           ("anthropic_api_key", '"sk-x"'),
                           ("anthropic_model", '"m"'),
                           ("llm_max_tokens", "1024"),
                           ("llm_timeout", "45")):
            with self.assertRaises(ConfigError) as ctx:
                self.load(f'[agent]\nruntime = "opencode"\n{key} = {value}\n')
            self.assertIn(key, str(ctx.exception))


class PhaseMIntegrationTests(unittest.TestCase):
    """可选消费方（risk_chains.classify_with_llm）的降级契约。

    M2 尚未接入流水线，但它是本客户端唯一已知消费方，必须保证：客户端失败或模型
    输出不可解析时，调用方拿到 None 降级，而不是异常穿透到分析主流程。
    """

    def test_classification_uses_client_text(self):
        opener = RecordingOpener(reply(text_block(
            '{"externalFunctions":[],"libClass":{"libauth.so":"custom"},'
            '"wrapperHints":[{"binary":"server","name":"doSystem","hint":"命令执行 wrapper"}]}'
        )))
        client = MessagesClient(settings(), opener=opener)
        result = classify_with_llm(client, {"analysisGroupID": "g", "components": []})
        self.assertEqual(result["libClass"], {"libauth.so": "custom"})
        self.assertEqual(result["wrapperHints"][0]["hint"], "命令执行 wrapper")

    def test_failing_client_degrades_to_none(self):
        def failing(messages):
            raise LlmClientError("endpoint down")

        self.assertIsNone(classify_with_llm(failing, {"analysisGroupID": "g"}))

    def test_non_json_model_output_degrades_to_none(self):
        opener = RecordingOpener(reply(text_block("我不知道")))
        client = MessagesClient(settings(), opener=opener)
        self.assertIsNone(classify_with_llm(client, {"analysisGroupID": "g"}))


class RealHttpTests(unittest.TestCase):
    """起一个真实 HTTP 服务，验证标准库请求路径（URL、头、连接）。"""

    def setUp(self):
        captured: dict = {}

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("content-length", "0"))
                captured["path"] = self.path
                captured["headers"] = {k.lower(): v for k, v in self.headers.items()}
                captured["body"] = json.loads(self.rfile.read(length).decode("utf-8"))
                payload = reply(text_block('{"ok":true}')).encode("utf-8")
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args):
                pass

        self.captured = captured
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.server.shutdown)
        self.addCleanup(self.server.server_close)

    def test_real_request_round_trip(self):
        port = self.server.server_address[1]
        client = MessagesClient(settings(base_url=f"http://127.0.0.1:{port}/anthropic"))
        text = client([{"role": "system", "content": "sys"}, {"role": "user", "content": "hi"}])
        self.assertEqual(text, '{"ok":true}')
        self.assertEqual(self.captured["path"], "/anthropic/v1/messages")
        self.assertEqual(self.captured["headers"]["x-api-key"], "sk-test-key")
        self.assertEqual(self.captured["headers"]["anthropic-version"], ANTHROPIC_VERSION)
        self.assertEqual(self.captured["body"]["system"], "sys")
        self.assertEqual(self.captured["body"]["messages"], [{"role": "user", "content": "hi"}])

    def test_real_error_status_raises(self):
        port = self.server.server_address[1]
        handler_class = self.server.RequestHandlerClass

        class ErrorHandler(handler_class):
            def do_POST(self):
                payload = json.dumps({"error": {"message": "bad model"}}).encode("utf-8")
                self.send_response(400)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        self.server.RequestHandlerClass = ErrorHandler
        try:
            client = MessagesClient(settings(base_url=f"http://127.0.0.1:{port}"))
            with self.assertRaises(LlmClientError) as ctx:
                client([{"role": "user", "content": "hi"}])
            self.assertIn("HTTP 400", str(ctx.exception))
            self.assertIn("bad model", str(ctx.exception))
        finally:
            self.server.RequestHandlerClass = handler_class


if __name__ == "__main__":
    unittest.main()
