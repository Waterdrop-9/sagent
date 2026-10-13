"""阶段 M 候选链物化的子进程入口。

cli.py 用 AGENT_PATH_BACKEND_PYTHON（带 angr 的解释器）启动本模块，让阶段 M
拿到 callgraph 级机械能力；该解释器不可用时 cli.py 退回进程内无 angr 模式
（仅导入表/PLT 链）。本模块只做输入重建 → run_phase_m → 输出落盘，不打印报告。
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .analysis_context import AnalysisGroupContext
from .risk_chains import RiskChainsError, run_phase_m


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="阶段 M 候选链物化 worker")
    parser.add_argument("--context-json", required=True, help="AnalysisGroupContext.to_dict() 的 JSON 路径")
    parser.add_argument("--root-path", required=True, help="root ELF 绝对路径")
    parser.add_argument("--cwe", required=True)
    parser.add_argument("--workdir", required=True, help="run 目录（写 risk-chains.json）")
    parser.add_argument("--component-paths-json", default="{}", help="{binaryID: 绝对路径}")
    args = parser.parse_args(argv)

    data: dict[str, Any] = json.loads(Path(args.context_json).read_text(encoding="utf-8"))
    component_paths = {
        binary_id: Path(path).resolve()
        for binary_id, path in json.loads(Path(args.component_paths_json).read_text(encoding="utf-8")).items()
    }
    context = AnalysisGroupContext(
        analysis_group_id=data["analysisGroupID"],
        root=data["root"],
        components=tuple(data["components"]),
        dependencies=tuple(data["dependencies"]),
        pending_dependencies=data.get("pendingDependencies", 0),
        root_path=Path(args.root_path).resolve(),
        component_paths=component_paths,
    )
    try:
        run_phase_m(
            context,
            args.cwe,
            Path(args.workdir),
            component_paths=component_paths or None,
        )
    except RiskChainsError as exc:
        print(f"阶段 M 失败: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
