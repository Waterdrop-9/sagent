"""把不同生产级 Agent CLI 收敛到一个 Sagent 接口。"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Mapping, Protocol

LOG = logging.getLogger(__name__)


class AgentRuntimeError(RuntimeError):
    """Agent CLI 不可用、调用失败或输出无法读取。"""


@dataclass(frozen=True)
class AgentRequest:
    system_prompt: str
    user_prompt: str
    mcp_config: Path | None = None
    cwd: Path | None = None
    model: str | None = None
    provider: str | None = None
    base_url: str | None = None
    max_turns: int | None = None
    environment: Mapping[str, str] | None = None


@dataclass(frozen=True)
class AgentResponse:
    runtime: str
    command: tuple[str, ...]
    text: str
    raw_stdout: str
    raw_stderr: str
    returncode: int
    # 底座能提供时的 token/cost 开销（opencode 从本地会话库读出）；读不到时为 None。
    usage: dict[str, int | float] | None = None


class AgentRuntime(Protocol):
    name: str

    def build_command(self, request: AgentRequest) -> tuple[str, ...]: ...

    def run(self, request: AgentRequest) -> AgentResponse: ...


class _CliRuntime:
    name = "cli"

    # 这些错误不在此层重试（由子类更细粒度的重试接管，避免重试爆炸）。
    _non_retryable_markers: tuple[str, ...] = ()

    def __init__(
        self,
        executable: str,
        *,
        timeout: float = 3600,
        environment: Mapping[str, str] | None = None,
        session_retries: int = 0,
    ) -> None:
        self.executable = executable
        self.timeout = timeout
        self.environment = dict(environment or {})
        self.session_retries = session_retries

    def _check_executable(self) -> str:
        executable = shutil.which(self.executable) or (
            self.executable if Path(self.executable).is_file() else None
        )
        if not executable:
            raise AgentRuntimeError(
                f"找不到 {self.name} Agent CLI: {self.executable}；"
                f"请安装它，或在 PATH 中提供 {self.name} 命令"
            )
        return executable

    def _effective_env(self, request: AgentRequest) -> dict[str, str]:
        """本次子进程继承的环境：进程环境 + 运行时/请求注入，PWD 修正为实际 cwd。"""
        env = os.environ.copy()
        env.update(self.environment)
        if request.environment:
            env.update(request.environment)
        if request.cwd is not None:
            # 调用方 shell 可能携带过期的 PWD（指向工作区根而非实际 cwd）；
            # opencode 等项目发现依赖 PWD，不一致时读不到 cwd/.opencode 下的配置。
            env["PWD"] = str(Path(request.cwd).resolve())
        return env

    def run(self, request: AgentRequest) -> AgentResponse:
        self._check_executable()
        command = self.build_command(request)
        env = self._effective_env(request)
        # 命令本身是关键 debug 信息：底座、模型与工作目录一目了然。
        LOG.info(
            "运行命令: %s%s",
            " ".join(command),
            f" (cwd={request.cwd})" if request.cwd is not None else "",
        )
        # 会话级重试：底座非零退出或超时（如 provider 瞬时超时）时，复用同一
        # prompt 与工作目录重跑整个会话。报告内容无效不在这一层管（cli 层有
        # 报告级重试）。子类声明不重试的错误标记（如启动竞态，由更细粒度的
        # 退避重试接管）直接抛出。
        delay = 2.0
        for attempt in range(self.session_retries + 1):
            try:
                return self._run_once(command, env, request)
            except AgentRuntimeError as exc:
                if (
                    attempt >= self.session_retries
                    or any(marker in str(exc) for marker in self._non_retryable_markers)
                ):
                    raise
                LOG.warning(
                    "会话失败，%.0fs 后重试（第 %d/%d 次）: %s",
                    delay,
                    attempt + 1,
                    self.session_retries,
                    str(exc).splitlines()[0],
                )
                time.sleep(delay)
                delay *= 2
        raise AssertionError("unreachable")

    def _run_once(
        self, command: tuple[str, ...], env: dict[str, str], request: AgentRequest
    ) -> AgentResponse:
        started = time.monotonic()
        try:
            completed = subprocess.run(
                command,
                cwd=request.cwd,
                env=env,
                text=True,
                capture_output=True,
                timeout=self.timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise AgentRuntimeError(
                f"{self.name} Agent 超时（{self.timeout:.0f}s）"
            ) from exc
        except OSError as exc:
            raise AgentRuntimeError(f"启动 {self.name} Agent 失败: {exc}") from exc

        LOG.info(
            "进程退出 code=%d stdout=%dB stderr=%dB 耗时=%.1fs",
            completed.returncode,
            len(completed.stdout.encode()),
            len(completed.stderr.encode()),
            time.monotonic() - started,
        )
        if completed.returncode != 0:
            detail = completed.stderr.strip() or completed.stdout.strip()
            raise AgentRuntimeError(
                f"{self.name} Agent 退出码为 {completed.returncode}: {detail}"
            )
        return AgentResponse(
            runtime=self.name,
            command=command,
            text=self._extract_text(completed.stdout),
            raw_stdout=completed.stdout,
            raw_stderr=completed.stderr,
            returncode=completed.returncode,
        )

    @staticmethod
    def _extract_text(stdout: str) -> str:
        return stdout.strip()


class ClaudeCodeRuntime(_CliRuntime):
    """Claude Code 的非交互模式适配器。"""

    name = "claude"

    def __init__(
        self,
        executable: str = "claude",
        *,
        timeout: float = 3600,
        environment: Mapping[str, str] | None = None,
    ) -> None:
        super().__init__(executable, timeout=timeout, environment=environment)

    def build_command(self, request: AgentRequest) -> tuple[str, ...]:
        command = [
            self.executable,
            "-p",
            request.user_prompt,
            "--output-format",
            "json",
        ]
        if request.system_prompt:
            command.extend(("--append-system-prompt", request.system_prompt))
        if request.mcp_config:
            command.extend(("--mcp-config", str(request.mcp_config)))
        if request.model:
            command.extend(("--model", request.model))
        if request.max_turns is not None:
            command.extend(("--max-turns", str(request.max_turns)))
        return tuple(command)

    @staticmethod
    def _extract_text(stdout: str) -> str:
        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError:
            return stdout.strip()
        if isinstance(payload, dict) and isinstance(payload.get("result"), str):
            return payload["result"]
        if isinstance(payload, dict) and isinstance(payload.get("content"), str):
            return payload["content"]
        return json.dumps(payload, ensure_ascii=False)


class OpenCodeRuntime(_CliRuntime):
    """OpenCode 的非交互 `run` 适配器。"""

    name = "opencode"

    # opencode 会话库中本次请求的开销列；行不存在或库读不了时 usage 为 None。
    _USAGE_COLUMNS = (
        "tokens_input",
        "tokens_output",
        "tokens_reasoning",
        "tokens_cache_read",
        "tokens_cache_write",
        "cost",
    )

    # 两个 `opencode run --standalone` 几乎同时启动时，standalone 服务偶发起不来
    # （"Standalone server exited before reporting readiness"）。这是启动竞态，不是
    # 分析失败：退避重试有限次；重试只发生在会话尚未开始产出之前，不重复消耗分析。
    _SERVER_START_RACE = "Standalone server exited before reporting readiness"
    _STARTUP_RETRIES = 2
    # 启动竞态由 _run_with_startup_retry 的短退避接管；会话级重试跳过它，
    # 避免两层重试叠加成 9 次会话。
    _non_retryable_markers = (_SERVER_START_RACE,)

    def __init__(
        self,
        executable: str = "opencode",
        *,
        timeout: float = 3600,
        environment: Mapping[str, str] | None = None,
        session_retries: int = 2,
    ) -> None:
        super().__init__(
            executable,
            timeout=timeout,
            environment=environment,
            session_retries=session_retries,
        )
        self._standalone: bool | None = None

    def build_command(self, request: AgentRequest) -> tuple[str, ...]:
        prompt = request.user_prompt
        if request.system_prompt:
            prompt = f"[SYSTEM INSTRUCTIONS]\n{request.system_prompt}\n\n[USER TASK]\n{prompt}"
        # 使用独立服务，确保本次请求读取 Sagent 生成的 provider/MCP 配置。
        # `--standalone` 是 opencode ≥1.16 的旗标；旧版 run 本身就是无头模式，
        # 传入该旗标会直接打帮助并退出（容器内 1.15.12 实测）。
        command = [self.executable, "run"]
        if self._supports_standalone():
            command.append("--standalone")
        if request.model:
            model = request.model
            if request.provider and "/" not in model:
                model = f"{request.provider}/{model}"
            command.extend(("--model", model))
        command.append(prompt)
        return tuple(command)

    def _supports_standalone(self) -> bool:
        """opencode 是否认识 `run --standalone`；探测结果缓存到实例。"""
        if self._standalone is None:
            try:
                probe = subprocess.run(
                    [self.executable, "run", "--help"],
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
                self._standalone = "--standalone" in (probe.stdout or "")
            except (OSError, subprocess.TimeoutExpired):
                # 底座不可用或探测超时：宁可不加旗标，让真正运行时的报错说话。
                self._standalone = False
        return self._standalone

    def _run_with_startup_retry(self, request: AgentRequest) -> AgentResponse:
        """standalone 服务启动竞态时退避重试；其它错误原样抛出。"""
        delay = 2.0
        for attempt in range(self._STARTUP_RETRIES + 1):
            try:
                return super().run(request)
            except AgentRuntimeError as exc:
                if (
                    self._SERVER_START_RACE not in str(exc)
                    or attempt >= self._STARTUP_RETRIES
                ):
                    raise
                LOG.warning(
                    "底座会话启动竞态，%ds 后重试（第 %d/%d 次）: %s",
                    int(delay),
                    attempt + 1,
                    self._STARTUP_RETRIES,
                    str(exc).splitlines()[0],
                )
                time.sleep(delay)
                delay *= 2
        raise AssertionError("unreachable")

    def run(self, request: AgentRequest) -> AgentResponse:
        started = time.time()
        cwd = (request.cwd or Path.cwd()).resolve()
        env = self._effective_env(request)
        if not request.mcp_config:
            response = self._run_with_startup_retry(request)
            return replace(response, usage=self._session_usage(cwd, started, env))
        # OpenCode 2 从项目的 .opencode/opencode.json 发现配置。
        config_dir = cwd / ".opencode"
        config_path = config_dir / "opencode.json"
        previous = config_path.read_bytes() if config_path.exists() else None
        config_dir.mkdir(exist_ok=True)
        try:
            config_path.write_bytes(request.mcp_config.read_bytes())
            config_path.chmod(0o600)
            response = self._run_with_startup_retry(replace(request, cwd=cwd))
            return replace(response, usage=self._session_usage(cwd, started, env))
        finally:
            if previous is None:
                config_path.unlink(missing_ok=True)
                # 配置是我们写进去的：连空目录一起清掉，保持 cwd（如 poc/）干净。
                try:
                    config_dir.rmdir()
                except OSError as exc:
                    # 目录里出现模型写入的其它文件时清不掉，属于正常情况，只记 debug。
                    LOG.debug("清理 .opencode 目录失败: %s", exc)
            else:
                config_path.write_bytes(previous)

    def _session_usage(
        self, cwd: Path, started_at: float, env: Mapping[str, str]
    ) -> dict[str, int | float] | None:
        """从 opencode 本地会话库读出本次 run 的 token/cost 开销。

        每个 `opencode run` 对应 session_v2 一行；按运行目录 + 启动时间窗匹配最近一行。
        任何失败都只记 debug 并返回 None——开销是观测信息，不允许反过来让分析失败。
        """
        data_home = env.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
        db_path = Path(data_home) / "opencode" / "opencode.db"
        if not db_path.is_file():
            return None
        # 时间窗放宽 1s：session 的行写入时间可能与子进程启动有轻微先后差异。
        started_ms = int(started_at * 1000) - 1000
        try:
            import sqlite3  # opencode 是可选的底座；用不到它时不引入该模块。

            connection = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5)
            try:
                row = connection.execute(
                    f"SELECT {', '.join(self._USAGE_COLUMNS)} FROM session_v2 "
                    "WHERE directory IN (?, ?) AND time_created >= ? "
                    "ORDER BY time_created DESC LIMIT 1",
                    (str(cwd), str(cwd.resolve()), started_ms),
                ).fetchone()
            finally:
                connection.close()
        except Exception as exc:
            LOG.debug("读取 opencode 会话开销失败: %s", exc)
            return None
        if row is None:
            return None
        return dict(zip(self._USAGE_COLUMNS, row))


def runtime_from_name(name: str, **kwargs: object) -> AgentRuntime:
    if name == "claude":
        return ClaudeCodeRuntime(**kwargs)
    if name == "opencode":
        return OpenCodeRuntime(**kwargs)
    raise ValueError(f"不支持的 Agent 底座: {name}")
