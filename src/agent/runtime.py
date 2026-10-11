"""把不同生产级 Agent CLI 收敛到一个 Sagent 接口。"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Protocol


class AgentRuntimeError(RuntimeError):
    """Agent CLI 不可用、调用失败或输出无法读取。"""


@dataclass(frozen=True)
class AgentRequest:
    system_prompt: str
    user_prompt: str
    mcp_config: Path | None = None
    cwd: Path | None = None
    model: str | None = None
    max_turns: int | None = None


@dataclass(frozen=True)
class AgentResponse:
    runtime: str
    command: tuple[str, ...]
    text: str
    raw_stdout: str
    raw_stderr: str
    returncode: int


class AgentRuntime(Protocol):
    name: str

    def build_command(self, request: AgentRequest) -> tuple[str, ...]: ...

    def run(self, request: AgentRequest) -> AgentResponse: ...


class _CliRuntime:
    name = "cli"

    def __init__(
        self,
        executable: str,
        *,
        timeout: float = 3600,
        environment: Mapping[str, str] | None = None,
    ) -> None:
        self.executable = executable
        self.timeout = timeout
        self.environment = dict(environment or {})

    def _check_executable(self) -> str:
        executable = shutil.which(self.executable) or (
            self.executable if Path(self.executable).is_file() else None
        )
        if not executable:
            raise AgentRuntimeError(
                f"找不到 {self.name} Agent CLI: {self.executable}；"
                f"请安装它或传入 --{self.name}-executable"
            )
        return executable

    def run(self, request: AgentRequest) -> AgentResponse:
        self._check_executable()
        command = self.build_command(request)
        env = os.environ.copy()
        env.update(self.environment)
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

    def __init__(
        self,
        executable: str = "opencode",
        *,
        timeout: float = 3600,
        environment: Mapping[str, str] | None = None,
    ) -> None:
        super().__init__(executable, timeout=timeout, environment=environment)

    def build_command(self, request: AgentRequest) -> tuple[str, ...]:
        prompt = request.user_prompt
        if request.system_prompt:
            prompt = f"[SYSTEM INSTRUCTIONS]\n{request.system_prompt}\n\n[USER TASK]\n{prompt}"
        command = [self.executable, "run", prompt]
        if request.model:
            command.extend(("--model", request.model))
        return tuple(command)

    def run(self, request: AgentRequest) -> AgentResponse:
        environment = dict(self.environment)
        if request.mcp_config:
            environment["OPENCODE_CONFIG"] = str(request.mcp_config)
        original = self.environment
        self.environment = environment
        try:
            return super().run(request)
        finally:
            self.environment = original


def runtime_from_name(name: str, **kwargs: object) -> AgentRuntime:
    if name == "claude":
        return ClaudeCodeRuntime(**kwargs)
    if name == "opencode":
        return OpenCodeRuntime(**kwargs)
    raise ValueError(f"不支持的 Agent 底座: {name}")
