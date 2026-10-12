"""MCP stdio 代理：给实际工具响应附加可追溯证据 ID，并限制持久化规模。"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time

from .artifacts import MAX_JOURNAL_BYTES, MAX_TOOL_BYTES, write_json


def serve(command: list[str], directory: Path, server: str, group_id: str, binary_id: str) -> int:
    raw = directory / "raw"
    raw.mkdir(parents=True, exist_ok=True)
    journal = raw / f"{server}.jsonl"
    pending: dict[object, tuple[dict, float]] = {}
    output_lock = threading.Lock()
    max_calls = 32 if server == "paths" else 128
    count = 0
    used = 0
    child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             text=True, encoding="utf-8", start_new_session=True)

    def emit(value: dict) -> None:
        with output_lock:
            print(json.dumps(value, ensure_ascii=False), flush=True)

    def budget_result(reason: str) -> dict:
        write_json(raw / f"budget-{server}.json", {"reason": reason})
        return {"isError": True, "content": [{"type": "text", "text": "budget_exhausted: " + reason}]}

    def log_line(text: str) -> None:
        """关键动作落进本轮 analysis.log（run 目录），便于事后排查；失败不影响代理。"""
        try:
            with (directory / "analysis.log").open("a", encoding="utf-8") as stream:
                stream.write(text + "\n")
        except OSError:
            pass

    def responses() -> None:
        nonlocal used
        assert child.stdout is not None
        for line in child.stdout:
            try:
                response = json.loads(line)
            except json.JSONDecodeError:
                print(f"{server}: MCP stdout 包含无效 JSON", file=sys.stderr)
                continue
            entry = pending.pop(response.get("id"), None)
            if entry:
                request, started = entry
                if request.get("method") == "initialize" and "result" in response:
                    # MCP 会话版本只作一行日志，不单独生成 version 文件（减少产物杂音）。
                    log_line(f"{server}: MCP 会话初始化 serverInfo={json.dumps(response['result'].get('serverInfo', {}), ensure_ascii=False)}")
                if request.get("method") == "tools/call":
                    result = response.get("result", {"isError": True, "content": [
                        {"type": "text", "text": json.dumps(response.get("error", {}))}]})
                    record = {
                        "server": server, "tool": request["params"]["name"],
                        "arguments": request["params"].get("arguments", {}),
                        "analysisGroupID": group_id, "binaryID": binary_id,
                        "elapsedSeconds": round(time.monotonic() - started, 3), "result": result,
                    }
                    data = json.dumps(record, ensure_ascii=False).encode()
                    if len(data) > MAX_TOOL_BYTES or used + len(data) + 200 > MAX_JOURNAL_BYTES:
                        response = {"jsonrpc": "2.0", "id": response["id"], "result": budget_result("工具证据大小达到上限，请缩小查询范围")}
                    else:
                        evidence_id = "ev-" + hashlib.sha256(data).hexdigest()[:20]
                        record["evidenceID"] = evidence_id
                        encoded = json.dumps(record, ensure_ascii=False).encode() + b"\n"
                        with journal.open("ab") as stream:
                            stream.write(encoded)
                            stream.flush()
                        used += len(encoded)
                        response = {"jsonrpc": "2.0", "id": response["id"], "result": {
                            **result, "content": [*result.get("content", []), {
                                "type": "text", "text": f"本地证据 evidenceID={evidence_id}; binaryID={binary_id}; analysisGroupID={group_id}"
                            }],
                        }}
            emit(response)

    reader = threading.Thread(target=responses, daemon=True)
    reader.start()
    try:
        assert child.stdin is not None
        for line in sys.stdin:
            request = json.loads(line)
            if request.get("method") == "tools/call":
                if count >= max_calls or used >= MAX_JOURNAL_BYTES:
                    emit({"jsonrpc": "2.0", "id": request.get("id"), "result": budget_result("工具调用次数或证据字节预算耗尽")})
                    continue
                count += 1
            if "id" in request and "method" in request:
                pending[request["id"]] = (request, time.monotonic())
            child.stdin.write(line)
            child.stdin.flush()
    except (BrokenPipeError, ValueError) as exc:
        print(f"{server}: MCP 代理失败: {exc}", file=sys.stderr)
        return 1
    finally:
        if child.stdin:
            child.stdin.close()
        try:
            child.wait(timeout=3)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGTERM)
            try:
                child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait()
        reader.join(timeout=3)
        # 会话收尾：证据条数与字节量一行入账，便于判断本轮工具是否真实工作。
        log_line(f"{server}: 会话结束 记录证据={count} 条 字节={used}")
    return child.returncode or 0


def main() -> int:
    parser = argparse.ArgumentParser(description="工具证据记录代理")
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--server", choices=("ghidra", "paths"), required=True)
    parser.add_argument("--group-id", required=True)
    parser.add_argument("--binary-id", required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    return serve(command, args.directory, args.server, args.group_id, args.binary_id)


if __name__ == "__main__":
    raise SystemExit(main())
