"""CWE prompt 和工具插件。"""

from __future__ import annotations

import json
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


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

    def build_user_prompt(self, goal: str, target: Path) -> str: ...

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
        self.system_prompt = self._read_prompt("system.md")
        self.task_prompt = self._read_prompt("task.md")

    def _read_prompt(self, name: str) -> str:
        path = self.prompt_root / name
        try:
            content = path.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise FileNotFoundError(f"CWE-78 prompt 不存在或不可读: {path}") from exc
        if not content:
            raise ValueError(f"CWE-78 prompt 为空: {path}")
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

    def build_user_prompt(self, goal: str, target: Path) -> str:
        return self.task_prompt.format(target=target, goal=goal)

    def mcp_config(
        self,
        target: Path,
        source_root: Path,
        *,
        fixture: Path | None = None,
        ghidra_mode: str = "headless",
        ghidra_server: str = "http://127.0.0.1:8080/",
        ghidra_install_dir: Path | None = None,
        ghidra_extension_jar: Path | None = None,
    ) -> dict[str, object]:
        """为 Claude/OpenCode 生成 GhidraMCP 和可选证据工具配置。"""

        if ghidra_mode not in {"headless", "gui"}:
            raise ValueError(f"不支持的 Ghidra 模式: {ghidra_mode}")
        uvx = shutil.which("uvx") or "uvx"
        ghidra_args = [
            "--from",
            "ghidra-mcp[headless] @ git+https://github.com/LaurieWired/GhidraMCP",
            "ghidra-mcp",
        ]
        ghidra_env: dict[str, str] = {}
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
                "command": [uvx, *ghidra_args],
                "environment": ghidra_env,
            }
        }
        if fixture:
            evidence_command = [
                sys.executable,
                "-m",
                "agent.mcp_server",
                "--fixture",
                str(fixture.resolve()),
            ]
            claude_servers["evidence"] = {
                "command": evidence_command[0],
                "args": evidence_command[1:],
                "env": {"PYTHONPATH": str(source_root.resolve())},
            }
            opencode_servers["evidence"] = {
                "type": "local",
                "command": evidence_command,
                "environment": {"PYTHONPATH": str(source_root.resolve())},
            }
        return {
            "claude": {"mcpServers": claude_servers},
            "opencode": {
                "$schema": "https://opencode.ai/config.json",
                "mcp": {"servers": opencode_servers},
            },
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
