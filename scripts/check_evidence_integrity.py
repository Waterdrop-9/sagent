"""核对报告引用的 evidenceID 是否都能在 raw 证据记录中找到（防幻觉审计）。

用法: python3 scripts/check_evidence_integrity.py <产物根目录>

对产物根下每个 group-*/run-*/report.json 做交叉校验；发现缺失引用时打印明细并退出码 1。
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

EVIDENCE_ID_PATTERN = re.compile(r"ev-[0-9a-f]{20}")


def _raw_evidence_ids(run_dir: Path) -> set[str]:
    ids: set[str] = set()
    # 多二进制模式下每个 GhidraMCP 会话各写一份 ghidra-<binaryID[:8]>.jsonl，
    # 故按 glob 收集 raw/ 下全部证据日志（ghidra.jsonl / paths.jsonl / ghidra-*.jsonl）。
    for journal in sorted((run_dir / "raw").glob("*.jsonl")):
        for line in journal.read_text(encoding="utf-8").splitlines():
            if line.strip():
                try:
                    ids.add(json.loads(line)["evidenceID"])
                except (KeyError, json.JSONDecodeError):
                    continue
    return ids


def _collect_citations(report: dict) -> set[str]:
    """只统计结构性引用位置（evidenceIDs 数组），忽略诊断文本里的 ID 字样。"""
    cited: set[str] = set()
    for finding in report.get("findings", []):
        cited.update(finding.get("evidenceIDs", []))
    coverage = report.get("coverage", {})
    for model in coverage.get("functionModels", []):
        cited.update(model.get("evidenceIDs", []))
        for entry in model.get("propagationMap", []):
            cited.update(entry.get("evidenceIDs", []))
    for surface in coverage.get("attackSurfaces", []):
        cited.update(surface.get("evidenceIDs", []))
    for query in coverage.get("pathQueries", []):
        cited.update(query.get("evidenceIDs", []))
    # 只保留符合 ID 形态的字符串（模型可能往数组里塞任意文本）
    return {c for c in cited if isinstance(c, str) and EVIDENCE_ID_PATTERN.fullmatch(c)}


def check(run_dir: Path) -> tuple[int, list[str]]:
    report_path = run_dir / "report.json"
    if not report_path.exists():
        return 0, []
    report = json.loads(report_path.read_text(encoding="utf-8"))
    known = _raw_evidence_ids(run_dir)
    cited = _collect_citations(report)
    missing = sorted(cited - known)
    return len(missing), missing


def main() -> int:
    parser = argparse.ArgumentParser(description="核对报告证据引用完整性")
    parser.add_argument("output", type=Path, help="产物根目录（含 group-*/run-*/）")
    args = parser.parse_args()
    root = args.output.expanduser().resolve()
    failed = False
    checked = 0
    for report_path in sorted(root.glob("group-*/run-*/report.json")):
        run_dir = report_path.parent
        count, missing = check(run_dir)
        checked += 1
        if missing:
            failed = True
            print(f"{run_dir.name}: {count} 个缺失引用: {missing}")
        else:
            print(f"{run_dir.name}: OK")
    print(f"共检查 {checked} 个 run 目录" + ("，全部通过" if not failed else "，存在缺失引用"))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
