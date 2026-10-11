"""启动 Sagent：选择真实 Agent 底座，加载 CWE prompt 和 MCP 工具插件。"""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

from .analysis_context import AnalysisContextError, build_contexts, render_contexts
from .agent_report import AgentReportError, parse_report
from .config import ConfigError, agent_environment, load_config, load_ghidra_config
from .plugins import Cwe78Plugin, write_runtime_config
from .runtime import AgentRuntimeError, AgentRequest, runtime_from_name


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Sagent Agent 原型")
    parser.add_argument("--config", type=Path, default=Path("config.toml"))
    parser.add_argument("--target", type=Path, required=True, help="待分析 ELF 或固件组件")
    parser.add_argument(
        "--dependency-root",
        action="append",
        type=Path,
        default=[],
        help="显式依赖目录，可重复；单 ELF 不自动扫描父目录",
    )
    parser.add_argument("--goal", required=True, help="人工分析目标")
    parser.add_argument("--dry-run", action="store_true", help="只生成 prompt、MCP 配置和命令")
    args = parser.parse_args(argv)
    args.target = args.target.expanduser().resolve()

    try:
        config = load_config(args.config)
    except ConfigError as exc:
        parser.error(str(exc))
    source_root = Path(__file__).resolve().parents[1]
    try:
        analysis_contexts = build_contexts(args.target, args.dependency_root)
    except AnalysisContextError as exc:
        parser.error(str(exc))
    analysis_context = render_contexts(analysis_contexts)
    try:
        ghidra = load_ghidra_config()
    except ConfigError as exc:
        parser.error(str(exc))
    plugin = Cwe78Plugin()
    runtime = runtime_from_name(config.agent.runtime, timeout=config.agent.timeout)
    with tempfile.TemporaryDirectory(prefix="agent-") as directory:
        config_path = write_runtime_config(
            plugin,
            config.agent.runtime,
            args.target,
            source_root,
            Path(directory) / f"{config.agent.runtime}-mcp.json",
            ghidra=ghidra,
            provider=config.agent.provider,
            model=config.agent.model,
            api_key=config.agent.api_key,
            base_url=config.agent.base_url,
        )
        request = AgentRequest(
            system_prompt=plugin.system_prompt,
            user_prompt=plugin.build_user_prompt(args.goal, args.target, analysis_context),
            mcp_config=config_path,
            cwd=Path.cwd(),
            model=config.agent.model,
            provider=config.agent.provider,
            base_url=config.agent.base_url,
            environment=agent_environment(config.agent),
        )
        command = runtime.build_command(request)
        if args.dry_run:
            print("COMMAND:")
            print(" ".join(command))
            print("\nSYSTEM PROMPT:\n" + request.system_prompt)
            print("\nUSER PROMPT:\n" + request.user_prompt)
            mcp_config = config_path.read_text(encoding="utf-8")
            if config.agent.api_key:
                mcp_config = mcp_config.replace(config.agent.api_key, "<redacted>")
            print("\nMCP CONFIG:\n" + mcp_config)
            return 0
        try:
            response = runtime.run(request)
        except AgentRuntimeError as exc:
            parser.error(str(exc))
        else:
            try:
                report = parse_report(response.text)
            except AgentReportError as exc:
                parser.error(str(exc))
            print(json.dumps(report, ensure_ascii=False, indent=2))
            return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
