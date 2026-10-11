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


@dataclass(frozen=True)
class Config:
    path: Path
    agent: AgentConfig


@dataclass(frozen=True)
class GhidraMcpConfig:
    mode: str
    server: str
    uvx: str
    python: str
    package: str
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

    if set(raw) != {"agent"} or not isinstance(raw.get("agent"), dict):
        raise ConfigError("配置只允许包含 [agent] 表")
    agent = raw["agent"]
    allowed = {"runtime", "provider", "model", "api_key", "base_url", "timeout"}
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
    return Config(
        path=config_path,
        agent=AgentConfig(
            runtime=runtime,
            provider=provider,
            model=model,
            api_key=api_key,
            base_url=base_url,
            timeout=float(timeout),
        ),
    )


def agent_environment(config: AgentConfig) -> dict[str, str]:
    """为 Claude 类底座准备凭据和兼容接口地址。"""
    if config.runtime != "claude":
        return {}
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
        ready_timeout=ready_timeout,
        install_dir=Path(env["GHIDRA_INSTALL_DIR"]) if env.get("GHIDRA_INSTALL_DIR") else None,
        extension_jar=(Path(env["GHIDRA_MCP_EXTENSION_JAR"]) if env.get("GHIDRA_MCP_EXTENSION_JAR") else None),
    )
