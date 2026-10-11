"""基于 angr RDA 的受预算限制参数路径查询。"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class PathQuery:
    sink_function: str
    sink_argument: int
    max_depth: int = 8
    max_nodes: int = 5000


class PathQueryError(RuntimeError):
    """路径后端不可用或查询参数无效。"""


class AngrPathBackend:
    """只做静态定义链查询，不把结果直接解释为漏洞。"""

    def query(self, binary: str | Path, request: PathQuery) -> dict[str, Any]:
        try:
            import angr
        except ImportError as exc:
            raise PathQueryError("未安装 angr 路径后端") from exc

        binary_path = Path(binary).expanduser().resolve()
        if not binary_path.is_file():
            raise PathQueryError(f"分析目标不存在: {binary_path}")
        if request.sink_argument < 0:
            raise PathQueryError("sink_argument 不能为负数")
        if request.max_depth < 1 or request.max_nodes < 1:
            raise PathQueryError("max_depth 和 max_nodes 必须大于 0")

        project = angr.Project(str(binary_path), auto_load_libs=False)
        cfg = project.analyses.CFGFast(normalize=True)
        sink = self._resolve_function(cfg, request.sink_function)
        if sink is None:
            return self._result("unsupported", reason="找不到 sink 函数")

        callers = list(cfg.kb.callgraph.predecessors(sink.addr))
        if not callers:
            return self._result("unknown", reason="找不到 sink 调用者")

        paths: list[dict[str, Any]] = []
        limitations: set[str] = set()
        for caller_addr in callers:
            caller = cfg.kb.functions[caller_addr]
            for block_addr in caller.get_call_sites():
                if caller.get_call_target(block_addr) != sink.addr:
                    continue
                call_address = self._call_instruction(project, block_addr, sink.addr)
                if call_address is None:
                    limitations.add("无法定位调用指令")
                    continue
                result = self._query_callsite(
                    project,
                    caller,
                    call_address,
                    request.sink_argument,
                    request.max_depth,
                    request.max_nodes,
                )
                paths.extend(result[0])
                limitations.update(result[1])

        if paths:
            return {
                "status": "path_found",
                "sink": {
                    "functionID": hex(sink.addr),
                    "functionName": sink.name,
                    "argument": request.sink_argument,
                },
                "paths": paths,
                "limitations": sorted(limitations),
            }
        return self._result("unknown", reason="未得到可解释的参数定义链", limitations=limitations)

    @staticmethod
    def _resolve_function(cfg: Any, name_or_address: str) -> Any | None:
        try:
            address = int(name_or_address, 0)
        except ValueError:
            address = None
        if address is not None:
            return cfg.kb.functions.get(address)
        return cfg.kb.functions.function(name=name_or_address)

    @staticmethod
    def _call_instruction(project: Any, block_addr: int, target: int) -> int | None:
        block = project.factory.block(block_addr)
        for instruction in block.capstone.insns:
            if instruction.mnemonic.startswith("call") and instruction.op_str:
                try:
                    if int(instruction.op_str, 0) == target:
                        return instruction.address
                except ValueError:
                    continue
        return None

    @staticmethod
    def _query_callsite(
        project: Any,
        caller: Any,
        call_address: int,
        argument: int,
        max_depth: int,
        max_nodes: int,
    ) -> tuple[list[dict[str, Any]], set[str]]:
        if project.arch.name != "AMD64":
            return [], {f"暂不支持 {project.arch.name} 的 ABI 参数定位"}
        if argument > 5:
            return [], {"x86-64 只实现前六个寄存器参数"}
        import angr
        from angr.analyses.reaching_definitions import ObservationPointType

        register_names = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")
        offset, size = project.arch.registers[register_names[argument]]
        rda = project.analyses.ReachingDefinitions(
            subject=caller,
            observe_all=True,
            track_tmps=True,
            dep_graph=True,
        )
        before = [
            value
            for key, value in rda.observed_results.items()
            if key[0] == "insn" and key[1] == call_address and key[2] == ObservationPointType.OP_BEFORE
        ]
        if not before:
            before = [
                value
                for key, value in rda.observed_results.items()
                if key[0] == "insn" and key[1] == call_address
            ]
        if not before:
            return [], {"RDA 没有返回调用点状态"}

        definitions = before[-1].get_register_definitions(offset, size)
        if not definitions:
            return [], {"RDA 没有返回敏感参数定义"}
        paths = []
        limitations: set[str] = set()
        for definition in definitions:
            nodes = _walk_definitions(rda.dep_graph, definition, max_depth, max_nodes)
            if len(nodes) >= max_nodes:
                limitations.add("达到 max_nodes 预算")
            paths.append(
                {
                    "caller": caller.name,
                    "callerFunctionID": hex(caller.addr),
                    "callsiteAddress": hex(call_address),
                    "sinkArgument": argument,
                    "definitions": [_definition_dict(node) for node in nodes],
                }
            )
        limitations.add("RDA 仅提供定义链，source 可控性和跨函数完整性需继续验证")
        return paths, limitations

    @staticmethod
    def _result(status: str, reason: str | None = None, limitations: set[str] | None = None) -> dict[str, Any]:
        return {
            "status": status,
            "paths": [],
            "reason": reason,
            "limitations": sorted(limitations or set()),
        }


def _walk_definitions(graph: Any, root: Any, max_depth: int, max_nodes: int) -> list[Any]:
    seen = {root}
    queue = [(root, 0)]
    while queue and len(seen) < max_nodes:
        node, depth = queue.pop(0)
        if depth >= max_depth:
            continue
        for predecessor in graph.predecessors(node):
            if predecessor in seen:
                continue
            seen.add(predecessor)
            queue.append((predecessor, depth + 1))
            if len(seen) >= max_nodes:
                break
    return list(seen)


def _definition_dict(definition: Any) -> dict[str, Any]:
    location = getattr(definition, "codeloc", None)
    return {
        "atom": str(getattr(definition, "atom", "")),
        "address": hex(location.ins_addr) if location and location.ins_addr is not None else None,
        "functionID": hex(location.block_addr) if location and location.block_addr is not None else None,
    }
