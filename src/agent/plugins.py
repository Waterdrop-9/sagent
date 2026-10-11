"""CWE prompt 和工具插件。"""

from __future__ import annotations

import json
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

    def mcp_config(self, fixture: Path, source_root: Path) -> dict[str, object]: ...


class Cwe78Plugin:
    """CWE-78 的首个工具和 prompt 插件。"""

    cwe_id = "CWE-78"
    name = "cwe78"
    system_prompt = """你是 Sagent 的二进制漏洞分析 Agent。
你正在分析 ELF/固件中的 CWE-78 OS Command Injection。

工作规则：
1. 先调用 query_sink_paths，从命令执行 sink 的敏感参数开始反向查询数据依赖路径。
2. 只把工具返回的路径和证据当作二进制事实；模型推断必须标记为 hypothesis。
3. 检查路径起点是否是外部可控输入，并检查命令拼接、白名单、转义和固定命令限制。
4. 只有 source、传播路径、sink 参数和关键证据都具备时才输出 candidate finding。
5. 不要执行样本，不要把没有工具证据的函数名、地址或可控性写成事实。

最终只输出 JSON，结构为：
{"findings": [{"cwe": "CWE-78", "source": ..., "sink": ..., "path": [...],
"evidence": [...], "confidence": "candidate|confirmed|inconclusive",
"limitations": [...]}], "unresolved": [...]}。
"""

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
        return (
            f"目标文件：{target}\n"
            f"分析目标：{goal}\n"
            "请先枚举你需要查询的 CWE-78 sink，再使用工具获取路径，最后按系统提示输出 JSON。"
        )

    def mcp_config(self, fixture: Path, source_root: Path) -> dict[str, object]:
        command = [
            sys.executable,
            "-m",
            "agent.mcp_server",
            "--fixture",
            str(fixture.resolve()),
        ]
        server = {
            "type": "local",
            "command": command,
            "environment": {"PYTHONPATH": str(source_root.resolve())},
        }
        return {
            "claude": {
                "mcpServers": {
                    "cwe78": {
                        "command": command[0],
                        "args": command[1:],
                        "env": server["environment"],
                    }
                }
            },
            "opencode": {
                "$schema": "https://opencode.ai/config.json",
                "mcp": {"servers": {"cwe78": server}},
            },
        }


def write_runtime_config(
    plugin: CwePlugin,
    runtime: str,
    fixture: Path,
    source_root: Path,
    output: Path,
) -> Path:
    configs = plugin.mcp_config(fixture, source_root)
    if runtime not in configs:
        raise ValueError(f"插件没有为 {runtime} 提供 MCP 配置")
    output.write_text(
        json.dumps(configs[runtime], ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return output
