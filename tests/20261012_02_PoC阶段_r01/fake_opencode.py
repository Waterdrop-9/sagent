#!/usr/bin/env python3
"""Fake opencode CLI：分析阶段落盘工具记录并输出报告，PoC 阶段输出响应。

真实 opencode 的调用形状是 `opencode run --standalone [--model x] <prompt>`，
prompt 是最后一个参数。分析阶段通过 cwd/.opencode/opencode.json 里
evidence_proxy 命令的 --directory/--group-id/--binary-id 找到产物目录并
写入原始工具记录；PoC 阶段在 cwd 写一份 PoC 报告和一个验证脚本，输出
响应并把当前工作目录打进响应，供测试断言 PoC 请求的 cwd 是 <run>/poc/
且 poc/ 目录干净。
"""

import json
import os
import sys
from pathlib import Path

POC_MARKER = "独立的 PoC 生成阶段"
MODE = os.environ.get("FAKE_OPENCODE_MODE", "normal")


def load_artifact_dir() -> tuple[Path, str, str]:
    """从 OpenCode 运行时写入的配置里解析产物目录、组和 binaryID。"""
    config = json.loads((Path.cwd() / ".opencode" / "opencode.json").read_text())
    command = config["mcp"]["servers"]["ghidra"]["command"]
    arguments = list(command)
    return (
        Path(arguments[arguments.index("--directory") + 1]),
        arguments[arguments.index("--group-id") + 1],
        arguments[arguments.index("--binary-id") + 1],
    )


def write_records(directory: Path, group_id: str, binary_id: str, skip: bool) -> None:
    def record(server: str, tool: str, arguments: dict, content: str, evidence_id: str) -> dict:
        return {
            "server": server,
            "tool": tool,
            "arguments": arguments,
            "analysisGroupID": group_id,
            "binaryID": binary_id,
            "elapsedSeconds": 0,
            "result": {"isError": False, "content": [{"type": "text", "text": content}]},
            "evidenceID": evidence_id,
        }

    raw = directory / "raw"
    raw.mkdir(parents=True, exist_ok=True)
    ghidra = [
        record("ghidra", "get_program_info", {}, "fake program info for server", "ev-fake-ghidra-1"),
        record("ghidra", "decompile_function", {"function": "doSystem"}, "fake decompile of doSystem", "ev-fake-ghidra-2"),
    ]
    (raw / "ghidra.jsonl").write_text(
        "".join(json.dumps(item, ensure_ascii=False) + "\n" for item in ghidra), encoding="utf-8"
    )
    if skip:
        return
    paths = [record(
        "paths", "query_sink_paths", {"sink_function": "popen", "sink_argument": 0},
        json.dumps({
            "status": "path_found",
            "sink": {"functionID": "0x401380", "functionName": "popen", "argument": 0},
            "paths": [{"kind": "rda", "callsite": "0x401be7", "definition": "argv[1]"}],
            "coverage": {},
            "limitations": [],
        }),
        "ev-fake-paths-1",
    )]
    (raw / "paths.jsonl").write_text(
        "".join(json.dumps(item, ensure_ascii=False) + "\n" for item in paths), encoding="utf-8"
    )


def report(binary_id: str, skip: bool) -> dict:
    if skip:
        return {
            "findings": [{
                "cwe": "CWE-78", "binaryID": binary_id, "functionID": "doSystem",
                "source": "remoteExec", "sink": "popen", "sinkParams": [0],
                "path": "remoteExec → doSystem@0x401ba2 → popen@0x401380",
                "evidenceIDs": ["ev-fake-ghidra-1"], "status": "rejected",
                "confidence": "high", "limitations": ["fake opencode 实验环境"],
            }],
            "unresolved": [],
            "coverage": {
                "attackSurfaces": [{
                    "surfaceID": "network", "category": "network",
                    "functionID": "remoteExec", "status": "checked",
                    "evidenceIDs": ["ev-fake-ghidra-1"],
                }],
                "functionModels": [{
                    "binaryID": binary_id, "functionID": "popen", "functionName": "popen",
                    "functionAddress": "0x401380", "roles": ["sink"], "cweTypes": ["CWE-78"],
                    "sinkParams": [0], "status": "rejected", "confidence": "high",
                    "evidenceIDs": ["ev-fake-ghidra-1"], "limitations": [], "propagationMap": [],
                }],
            },
        }
    return {
        "findings": [{
            "cwe": "CWE-78", "binaryID": binary_id, "functionID": "doSystem",
            "source": "remoteExec", "sink": "popen", "sinkParams": [0],
            "path": "remoteExec → doSystem@0x401ba2 → popen@0x401380",
            "evidenceIDs": ["ev-fake-paths-1", "ev-fake-ghidra-2"],
            "status": "confirmed", "confidence": "high",
            "limitations": ["fake opencode 实验环境"],
        }],
        "unresolved": [],
        "coverage": {
            "attackSurfaces": [{
                "surfaceID": "network", "category": "network",
                "functionID": "remoteExec", "status": "checked",
                "evidenceIDs": ["ev-fake-ghidra-1"],
            }],
            "functionModels": [
                {
                    "binaryID": binary_id, "functionID": "popen", "functionName": "popen",
                    "functionAddress": "0x401380", "roles": ["sink"], "cweTypes": ["CWE-78"],
                    "sinkParams": [0], "status": "confirmed", "confidence": "high",
                    "evidenceIDs": ["ev-fake-paths-1", "ev-fake-ghidra-2"], "limitations": [], "propagationMap": [],
                },
                {
                    "binaryID": binary_id, "functionID": "doSystem", "functionName": "doSystem",
                    "functionAddress": "0x401ba2", "roles": ["wrapper"], "cweTypes": [],
                    "status": "confirmed", "confidence": "high",
                    "evidenceIDs": ["ev-fake-ghidra-2"], "limitations": [], "propagationMap": [],
                },
            ],
        },
    }


def main() -> int:
    prompt = sys.argv[-1]
    if POC_MARKER in prompt:
        # 模拟模型行为：只在 PoC 工作目录里写一份 PoC 报告和一个验证脚本，
        # 供测试断言 poc/ 目录里只有这两个文件、没有账目文件。
        (Path.cwd() / "doSystem.CWE-78.md").write_text(
            "# PoC 报告（fake opencode）\n\n"
            "findingID: fake/doSystem\n"
            "evidenceIDs: ev-fake-paths-1, ev-fake-ghidra-2\n",
            encoding="utf-8",
        )
        (Path.cwd() / "doSystem.CWE-78.py").write_text(
            '#!/usr/bin/env python3\n'
            '"""验证脚本（fake opencode）。仅供授权环境测试，由人工在隔离环境执行。\n\n'
            "findingID: fake/doSystem\n"
            "evidenceIDs: ev-fake-paths-1, ev-fake-ghidra-2\n"
            '"""\n'
            'print("fake poc script")\n',
            encoding="utf-8",
        )
        print(f"poc response from fake opencode\ncwd={Path.cwd().resolve()}")
        return 0
    directory, group_id, binary_id = load_artifact_dir()
    if MODE == "invalid":
        # 模拟底座输出不含有效报告 JSON 的失败路径（用于验证 error.json 记账）。
        print("模型输出里没有报告 JSON（fake opencode 故障模式）。")
        return 0
    if MODE == "flaky-server":
        # 模拟两个 standalone 会话同时启动时的服务竞态：第一次启动失败、
        # 第二次成功。用于验证 OpenCodeRuntime 的退避重试。
        marker = directory / "flaky-server-attempt"
        attempt = 0
        if marker.exists():
            attempt = int(marker.read_text(encoding="utf-8").strip())
        attempt += 1
        marker.write_text(str(attempt), encoding="utf-8")
        if attempt == 1:
            print(
                "Error: Standalone server exited before reporting readiness\n"
                "    at <anonymous> (/$bunfs/root/chunk-kp0jmrzw.js:2:974)",
                file=sys.stderr,
            )
            return 1
    if MODE == "bad-json-once":
        # 模拟模型输出方差：第一次 JSON 字符串里夹了未转义引号（解码失败，
        # 整份报告无效），第二次输出有效报告。用于验证 cli 的报告级重试。
        marker = directory / "bad-json-attempt"
        attempt = 0
        if marker.exists():
            attempt = int(marker.read_text(encoding="utf-8").strip())
        attempt += 1
        marker.write_text(str(attempt), encoding="utf-8")
        if attempt == 1:
            write_records(directory, group_id, binary_id, skip=False)
            print("静态分析完成（fake opencode）。")
            print("```json")
            print('{"findings": [], "unresolved": [], "coverage": {"attackSurfaces": [{"path": "snprintf(\"mkdir -p %s\") 未转义引号"}], "functionModels": []}}')
            print("```")
            return 0
    if MODE == "session-fail-twice":
        # 模拟 provider 瞬时超时导致的会话失败：前两次 opencode 非零退出
        # （真实现场：deepseek 请求 "Timed out waiting for response data"），
        # 第三次成功。用于验证 runtime 层的会话级重试。
        marker = directory / "session-fail-attempt"
        attempt = 0
        if marker.exists():
            attempt = int(marker.read_text(encoding="utf-8").strip())
        attempt += 1
        marker.write_text(str(attempt), encoding="utf-8")
        if attempt <= 2:
            print("Error: Timed out waiting for response data", file=sys.stderr)
            return 1
    write_records(directory, group_id, binary_id, skip=MODE == "skip")
    report_data = report(binary_id, skip=MODE == "skip")
    if MODE == "recall-basis":
        # 模拟 recall 模式下的模型输出：confirmed finding 带引用链级确认依据。
        for finding in report_data["findings"]:
            if finding.get("status") == "confirmed":
                finding["confirmationBasis"] = "reference-chain"
    print("静态分析完成（fake opencode）。")
    print("```json")
    print(json.dumps(report_data, ensure_ascii=False, indent=2))
    print("```")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
