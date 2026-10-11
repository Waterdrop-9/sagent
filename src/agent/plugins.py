"""CWE prompt 和工具插件。"""

from __future__ import annotations

import json
import os
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .config import GhidraMcpConfig


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    input_schema: dict[str, object]


class CwePlugin(Protocol):
    cwe_id: str
    name: str
    system_prompt: str
    tools: tuple[ToolSpec, ...]

    def build_user_prompt(
        self, goal: str, target: Path, analysis_context: str = ""
    ) -> str: ...

    def mcp_config(
        self, target: Path, source_root: Path, **kwargs: object
    ) -> dict[str, object]: ...


class Cwe78Plugin:
    """CWE-78 的首个工具和 prompt 插件。"""

    cwe_id = "CWE-78"
    name = "cwe78"

    def __init__(self, prompt_root: Path | None = None) -> None:
        root = prompt_root or Path(__file__).resolve().parents[2] / "prompts"
        self.prompt_root = root / "cwe-78"
        common_root = root / "common"
        common_prompts = tuple(
            self._read_file(common_root / name)
            for name in (
                "evidence-rules.md",
                "attack-surface.md",
                "source-sink-model.md",
                "coverage-rules.md",
                "report-schema.md",
            )
        )
        phase_prompts = tuple(
            self._read_file(self.prompt_root / name)
            for name in (
                "system.md",
                "attack-surface.md",
                "candidate-models.md",
                "propagation-review.md",
                "false-positive-review.md",
                "poc.md",
            )
        )
        self.system_prompt = "\n\n".join(common_prompts + phase_prompts)
        self.task_prompt = self._read_prompt("task.md")

    def _read_prompt(self, name: str) -> str:
        return self._read_file(self.prompt_root / name)

    @staticmethod
    def _read_file(path: Path) -> str:
        try:
            content = path.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise FileNotFoundError(f"prompt 不存在或不可读: {path}") from exc
        if not content:
            raise ValueError(f"prompt 为空: {path}")
        return content

    tools = (
        ToolSpec(
            name="query_sink_paths",
            description="从指定 sink 函数的敏感参数反向查询跨函数数据依赖路径。",
            input_schema={
                "type": "object",
                "properties": {
                    "sink_function": {"type": "string"},
                    "sink_argument": {"type": "integer", "minimum": 0},
                },
                "required": ["sink_function", "sink_argument"],
                "additionalProperties": False,
            },
        ),
    )

    def build_user_prompt(
        self, goal: str, target: Path, analysis_context: str = ""
    ) -> str:
        prompt = self.task_prompt.format(target=target, goal=goal)
        if analysis_context:
            prompt += "\n\n## 分析组上下文\n\n```json\n" + analysis_context + "\n```"
        return prompt

    def mcp_config(
        self,
        target: Path,
        source_root: Path,
        *,
        ghidra: GhidraMcpConfig,
        provider: str | None = None,
        model: str | None = None,
        api_key: str | None = None,
        base_url: str | None = None,
    ) -> dict[str, object]:
        """为 Claude/OpenCode 生成 GhidraMCP 和可选证据工具配置。"""

        ghidra_mode = ghidra.mode
        ghidra_server = ghidra.server
        ghidra_uvx = ghidra.uvx
        ghidra_python = ghidra.python
        ghidra_package = ghidra.package
        ready_timeout = ghidra.ready_timeout
        uvx = shutil.which(ghidra_uvx) or ghidra_uvx
        ghidra_args = [
            "--python",
            ghidra_python,
            "--from",
            ghidra_package,
            "ghidra-mcp",
            "--ready-timeout",
            str(ready_timeout),
        ]
        ghidra_env: dict[str, str] = {}
        ghidra_install_dir = ghidra.install_dir
        ghidra_extension_jar = ghidra.extension_jar
        if ghidra_mode == "headless":
            ghidra_args.extend(("--headless", "--binary", str(target.resolve())))
            if ghidra_install_dir:
                ghidra_args.extend(("--ghidra-install-dir", str(ghidra_install_dir.resolve())))
                ghidra_env["GHIDRA_INSTALL_DIR"] = str(ghidra_install_dir.resolve())
            if ghidra_extension_jar:
                ghidra_args.extend(("--extension-jar", str(ghidra_extension_jar.resolve())))
        else:
            ghidra_args.extend(("--ghidra-server", ghidra_server))

        claude_servers: dict[str, object] = {
            "ghidra": {"command": uvx, "args": ghidra_args, "env": ghidra_env}
        }
        opencode_servers: dict[str, object] = {
            "ghidra": {
                "type": "local",
                "codemode": False,
                "command": [uvx, *ghidra_args],
                "environment": ghidra_env,
            }
        }
        path_python = os.environ.get("AGENT_PATH_BACKEND_PYTHON")
        if path_python:
            path_command = [path_python, "-m", "agent.path_server", "--binary", str(target.resolve())]
            claude_servers["paths"] = {
                "command": path_python,
                "args": path_command[1:],
                "env": {"PYTHONPATH": str(source_root.resolve())},
            }
            opencode_servers["paths"] = {
                "type": "local",
                "codemode": False,
                "command": path_command,
                "environment": {"PYTHONPATH": str(source_root.resolve())},
            }
        return {
            "claude": {"mcpServers": claude_servers},
            "opencode": {
                "$schema": "https://opencode.ai/config.json",
                "model": f"{provider}/{model}" if provider and model else None,
                "providers": self._provider_config(provider, model, api_key, base_url),
                "mcp": {"servers": opencode_servers},
            },
        }

    @staticmethod
    def _provider_config(
        provider: str | None,
        model: str | None,
        api_key: str | None,
        base_url: str | None,
    ) -> dict[str, object]:
        if not provider or not model:
            return {}
        settings: dict[str, str] = {}
        if api_key:
            settings["apiKey"] = api_key
        if base_url:
            settings["baseURL"] = base_url
        return {
            provider: {
                "name": provider,
                "package": "@opencode/ai/providers/openai-compatible",
                "settings": settings,
                "models": {model: {"name": model}},
            }
        }


def write_runtime_config(
    plugin: CwePlugin,
    runtime: str,
    target: Path,
    source_root: Path,
    output: Path,
    **kwargs: object,
) -> Path:
    configs = plugin.mcp_config(target, source_root, **kwargs)
    if runtime not in configs:
        raise ValueError(f"插件没有为 {runtime} 提供 MCP 配置")
    output.write_text(
        json.dumps(configs[runtime], ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return output
