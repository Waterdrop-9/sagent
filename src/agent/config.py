"""读取本地 Agent 配置。"""

from __future__ import annotations

import math
import os
import tomllib
from dataclasses import dataclass
from pathlib import Path


class ConfigError(ValueError):
    """配置文件缺失、格式错误或字段无效。"""


@dataclass(frozen=True)
class AgentConfig:
    runtime: str
    provider: str
    model: str | None
    api_key: str | None
    base_url: str | None
    timeout: float
    session_retries: int


@dataclass(frozen=True)
class Config:
    path: Path
    agent: AgentConfig
    poc: PocConfig


@dataclass(frozen=True)
class PocConfig:
    enabled: bool
    prompt_file: Path | None


@dataclass(frozen=True)
class GhidraMcpConfig:
    mode: str
    server: str
    uvx: str
    python: str
    package: str
    command: str | None
    ready_timeout: int
    install_dir: Path | None
    extension_jar: Path | None


def load_config(path: str | Path = "config.toml") -> Config:
    config_path = Path(path).expanduser().resolve()
    try:
        raw = tomllib.loads(config_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"读取配置失败: {config_path}: {exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"TOML 格式错误: {config_path}: {exc}") from exc

    if set(raw) - {"agent", "poc"} or not isinstance(raw.get("agent"), dict):
        raise ConfigError("配置只允许包含 [agent] 和可选的 [poc] 表")
    agent = raw["agent"]
    allowed = {"runtime", "provider", "model", "api_key", "base_url", "timeout",
               "session_retries"}
    unknown = set(agent) - allowed
    if unknown:
        raise ConfigError(f"未知 agent 配置项: {sorted(unknown)}")

    runtime = agent.get("runtime")
    if runtime not in {"claude", "opencode"}:
        raise ConfigError("agent.runtime 必须是 claude 或 opencode")
    provider = agent.get("provider", "")
    if not isinstance(provider, str):
        raise ConfigError("agent.provider 必须是字符串")
    model = agent.get("model")
    if model is not None and not isinstance(model, str):
        raise ConfigError("agent.model 必须是字符串")
    model = model or None
    api_key = agent.get("api_key")
    if api_key is not None and not isinstance(api_key, str):
        raise ConfigError("agent.api_key 必须是字符串")
    api_key = api_key or None
    base_url = agent.get("base_url")
    if base_url is not None and not isinstance(base_url, str):
        raise ConfigError("agent.base_url 必须是字符串")
    base_url = base_url or None
    timeout = agent.get("timeout", 3600)
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or timeout <= 0:
        raise ConfigError("agent.timeout 必须是有限正数")
    session_retries = agent.get("session_retries", 2)
    if type(session_retries) is not int or session_retries < 0:
        raise ConfigError("agent.session_retries 必须是非负整数")
    poc_raw = raw.get("poc", {})
    if not isinstance(poc_raw, dict):
        raise ConfigError("poc 必须是表")
    unknown_poc = set(poc_raw) - {"enabled", "prompt_file"}
    if unknown_poc:
        raise ConfigError(f"未知 poc 配置项: {sorted(unknown_poc)}")
    poc_enabled = poc_raw.get("enabled", False)
    if type(poc_enabled) is not bool:
        raise ConfigError("poc.enabled 必须是布尔值")
    prompt_file_value = poc_raw.get("prompt_file")
    if prompt_file_value is not None and not isinstance(prompt_file_value, str):
        raise ConfigError("poc.prompt_file 必须是字符串")
    prompt_file = None
    if prompt_file_value:
        prompt_file = Path(prompt_file_value).expanduser()
        if not prompt_file.is_absolute():
            prompt_file = config_path.parent / prompt_file
        prompt_file = prompt_file.resolve()
    if poc_enabled and prompt_file is None:
        raise ConfigError("poc.enabled=true 时必须配置 poc.prompt_file")
    return Config(
        path=config_path,
        agent=AgentConfig(
            runtime=runtime,
            provider=provider,
            model=model,
            api_key=api_key,
            base_url=base_url,
            timeout=float(timeout),
            session_retries=session_retries,
        ),
        poc=PocConfig(enabled=poc_enabled, prompt_file=prompt_file),
    )


def agent_environment(config: AgentConfig) -> dict[str, str]:
    """为 Claude 类底座准备凭据和兼容接口地址。"""
    if config.runtime == "opencode":
        return {"AGENT_API_KEY": config.api_key} if config.api_key else {}
    environment: dict[str, str] = {}
    if config.api_key:
        environment["ANTHROPIC_API_KEY"] = config.api_key
    if config.base_url:
        environment["ANTHROPIC_BASE_URL"] = config.base_url
    return environment


def load_ghidra_config(environ: dict[str, str] | None = None) -> GhidraMcpConfig:
    """从部署环境读取 GhidraMCP 设置，不把机器路径写进项目 TOML。"""
    env = os.environ if environ is None else environ
    mode = env.get("GHIDRA_MCP_MODE", "headless")
    if mode not in {"headless", "gui"}:
        raise ConfigError("GHIDRA_MCP_MODE 必须是 headless 或 gui")
    try:
        ready_timeout = int(env.get("GHIDRA_MCP_READY_TIMEOUT", "30"))
    except ValueError as exc:
        raise ConfigError("GHIDRA_MCP_READY_TIMEOUT 必须是正整数秒数") from exc
    if ready_timeout <= 0:
        raise ConfigError("GHIDRA_MCP_READY_TIMEOUT 必须是正整数秒数")
    def value(name: str, default: str) -> str:
        result = env.get(name, default)
        if not result:
            raise ConfigError(f"{name} 不能为空")
        return result

    return GhidraMcpConfig(
        mode=mode,
        server=value("GHIDRA_MCP_SERVER", "http://127.0.0.1:8080/"),
        uvx=value("GHIDRA_MCP_UVX", "uvx"),
        python=value("GHIDRA_MCP_PYTHON", "3.13"),
        package=value(
            "GHIDRA_MCP_PACKAGE",
            "ghidra-mcp[headless] @ git+https://github.com/LaurieWired/GhidraMCP",
        ),
        # 容器等无 uvx/网络的部署用 GHIDRA_MCP_COMMAND 直接指定启动命令，
        # 例如 "/opt/sagent-venv/bin/python -m ghidra_mcp.cli"。
        command=env.get("GHIDRA_MCP_COMMAND") or None,
        ready_timeout=ready_timeout,
        install_dir=Path(env["GHIDRA_INSTALL_DIR"]) if env.get("GHIDRA_INSTALL_DIR") else None,
        extension_jar=(Path(env["GHIDRA_MCP_EXTENSION_JAR"]) if env.get("GHIDRA_MCP_EXTENSION_JAR") else None),
    )
