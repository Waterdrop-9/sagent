#!/usr/bin/env python3
"""验证 paths MCP 后端能否对真实 ELF 返回结构化参数路径。"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="检查 query_sink_paths 静态后端")
    parser.add_argument("--python", default=sys.executable, help="提供 angr 的 Python")
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--sink-function", default="popen")
    parser.add_argument("--sink-argument", type=int, default=0)
    parser.add_argument("--max-depth", type=int, default=8)
    parser.add_argument("--max-nodes", type=int, default=5000)
    args = parser.parse_args()
    request = {
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "query_sink_paths", "arguments": {
            "sink_function": args.sink_function, "sink_argument": args.sink_argument,
            "max_depth": args.max_depth, "max_nodes": args.max_nodes,
        }},
    }
    environment = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[2] / "src")}
    process = subprocess.run(
        [args.python, "-m", "agent.path_server", "--binary", str(args.binary.resolve())],
        input=json.dumps(request) + "\n", text=True, capture_output=True,
        env=environment, timeout=180, check=False,
    )
    if process.returncode:
        print(process.stderr.strip(), file=sys.stderr)
        return process.returncode
    responses = [json.loads(line) for line in process.stdout.splitlines() if line.strip()]
    response = next((item for item in responses if item.get("id") == 1), None)
    if response is None:
        print("路径后端没有返回 JSON-RPC 响应", file=sys.stderr)
        return 2
    result = response.get("result", {})
    if result.get("isError"):
        print(json.dumps(result, ensure_ascii=False))
        return 1
    text = next((block.get("text", "") for block in result.get("content", []) if block.get("type") == "text"), "")
    payload = json.loads(text)
    print(json.dumps({
        "status": payload.get("status"),
        "sink": payload.get("sink"),
        "pathCount": len(payload.get("paths", [])),
        "limitations": payload.get("limitations", []),
    }, ensure_ascii=False, indent=2))
    return 0 if payload.get("status") in {"path_found", "no_path", "unknown", "unsupported"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
