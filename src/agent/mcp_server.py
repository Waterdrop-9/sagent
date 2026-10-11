"""供 Claude/OpenCode 启动的最小 MCP stdio 工具桥。"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _response(request_id: object, result: object) -> dict[str, object]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _error(request_id: object, code: int, message: str) -> dict[str, object]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def serve(fixture: Path) -> int:
    payload = json.loads(fixture.read_text(encoding="utf-8"))
    tools = [
        {
            "name": "query_sink_paths",
            "description": "从 sink 的敏感参数反向查询数据依赖路径。",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "sink_function": {"type": "string"},
                    "sink_argument": {"type": "integer", "minimum": 0},
                },
                "required": ["sink_function", "sink_argument"],
            },
        }
    ]
    for line in sys.stdin:
        if not line.strip():
            continue
        request = json.loads(line)
        method = request.get("method")
        request_id = request.get("id")
        if method == "notifications/initialized":
            continue
        if method == "initialize":
            result = {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "cwe78", "version": "0.1.0"},
            }
        elif method == "tools/list":
            result = {"tools": tools}
        elif method == "tools/call":
            try:
                params = request.get("params") or {}
                if params.get("name") != "query_sink_paths":
                    raise ValueError(f"未知工具: {params.get('name')}")
                arguments = params.get("arguments") or {}
                key = (arguments["sink_function"], int(arguments["sink_argument"]))
                matches = [
                    item for item in payload.get("paths", [])
                    if (item.get("sink_function"), item.get("sink_argument")) == key
                ]
                result = {
                    "content": [{"type": "text", "text": json.dumps(matches, ensure_ascii=False)}],
                    "isError": False,
                }
            except (KeyError, TypeError, ValueError) as exc:
                result = {
                    "content": [{"type": "text", "text": str(exc)}],
                    "isError": True,
                }
        elif method == "ping":
            result = {}
        else:
            if request_id is None:
                continue
            print(json.dumps(_error(request_id, -32601, f"未知 MCP 方法: {method}")), flush=True)
            continue
        if request_id is not None:
            print(json.dumps(_response(request_id, result), ensure_ascii=False), flush=True)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Sagent CWE 工具 MCP stdio server")
    parser.add_argument("--fixture", type=Path, required=True)
    args = parser.parse_args(argv)
    return serve(args.fixture)


if __name__ == "__main__":
    raise SystemExit(main())
