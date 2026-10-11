"""参数路径查询 MCP server。"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .path_query import AngrPathBackend, PathQuery, PathQueryError


def _reply(request_id: object, result: object) -> None:
    print(json.dumps({"jsonrpc": "2.0", "id": request_id, "result": result}, ensure_ascii=False), flush=True)


def serve(binary: Path) -> int:
    backend = AngrPathBackend()
    tools = [{
        "name": "query_sink_paths",
        "description": "从 sink 敏感参数反向查询参数定义链；结果不是完整污点证明。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "sink_function": {"type": "string"},
                "sink_argument": {"type": "integer", "minimum": 0},
                "max_depth": {"type": "integer", "minimum": 1, "default": 8},
                "max_nodes": {"type": "integer", "minimum": 1, "default": 5000},
            },
            "required": ["sink_function", "sink_argument"],
        },
    }]
    for line in sys.stdin:
        if not line.strip():
            continue
        request = json.loads(line)
        request_id = request.get("id")
        method = request.get("method")
        if method == "notifications/initialized":
            continue
        if method == "initialize":
            _reply(request_id, {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "sagent-paths", "version": "0.1.0"},
            })
        elif method == "tools/list":
            _reply(request_id, {"tools": tools})
        elif method == "tools/call":
            try:
                params = request.get("params") or {}
                args = params.get("arguments") or {}
                result = backend.query(binary, PathQuery(
                    sink_function=str(args["sink_function"]),
                    sink_argument=int(args["sink_argument"]),
                    max_depth=int(args.get("max_depth", 8)),
                    max_nodes=int(args.get("max_nodes", 5000)),
                ))
                _reply(request_id, {"content": [{"type": "text", "text": json.dumps(result, ensure_ascii=False)}]})
            except (KeyError, TypeError, ValueError, PathQueryError) as exc:
                _reply(request_id, {"isError": True, "content": [{"type": "text", "text": str(exc)}]})
        elif request_id is not None:
            print(json.dumps({"jsonrpc": "2.0", "id": request_id, "error": {"code": -32601, "message": f"未知 MCP 方法: {method}"}}), flush=True)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Sagent 参数路径查询 MCP server")
    parser.add_argument("--binary", type=Path, required=True)
    return serve(parser.parse_args(argv).binary)


if __name__ == "__main__":
    raise SystemExit(main())
