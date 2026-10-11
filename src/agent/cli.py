"""启动 Sagent：选择真实 Agent 底座，加载 CWE prompt 和 MCP 工具插件。"""

from __future__ import annotations

import argparse
import tempfile
from pathlib import Path

from .plugins import Cwe78Plugin, write_runtime_config
from .runtime import AgentRuntimeError, AgentRequest, runtime_from_name


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Sagent Agent 原型")
    parser.add_argument("--runtime", choices=("claude", "opencode"), required=True)
    parser.add_argument("--executable", help="Agent CLI 路径；默认使用 PATH 中的命令")
    parser.add_argument("--target", type=Path, required=True, help="待分析 ELF 或固件组件")
    parser.add_argument("--goal", required=True, help="人工分析目标")
    parser.add_argument("--fixture", type=Path, required=True, help="静态工具路径 fixture")
    parser.add_argument("--model")
    parser.add_argument("--max-turns", type=int)
    parser.add_argument("--timeout", type=float, default=3600)
    parser.add_argument("--dry-run", action="store_true", help="只生成 prompt、MCP 配置和命令")
    args = parser.parse_args(argv)

    source_root = Path(__file__).resolve().parents[1]
    plugin = Cwe78Plugin()
    runtime_kwargs: dict[str, object] = {"timeout": args.timeout}
    if args.executable:
        runtime_kwargs["executable"] = args.executable
    runtime = runtime_from_name(args.runtime, **runtime_kwargs)
    with tempfile.TemporaryDirectory(prefix="agent-") as directory:
        config_path = write_runtime_config(
            plugin,
            args.runtime,
            args.fixture,
            source_root,
            Path(directory) / f"{args.runtime}-mcp.json",
        )
        request = AgentRequest(
            system_prompt=plugin.system_prompt,
            user_prompt=plugin.build_user_prompt(args.goal, args.target),
            mcp_config=config_path,
            cwd=Path.cwd(),
            model=args.model,
            max_turns=args.max_turns,
        )
        command = runtime.build_command(request)
        if args.dry_run:
            print("COMMAND:")
            print(" ".join(command))
            print("\nSYSTEM PROMPT:\n" + request.system_prompt)
            print("\nUSER PROMPT:\n" + request.user_prompt)
            print("\nMCP CONFIG:\n" + config_path.read_text(encoding="utf-8"))
            return 0
        try:
            response = runtime.run(request)
        except AgentRuntimeError as exc:
            parser.error(str(exc))
        else:
            print(response.text)
            return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
