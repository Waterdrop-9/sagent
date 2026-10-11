"""函数安全模型和路径查询记录。"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class PropagationMapping:
    """一次参数、返回值或调用点之间的传播映射。"""

    from_param: str
    to_function: str
    to_param: int | None
    callsite_address: str | None = None
    evidence_ids: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "fromParam": self.from_param,
            "toFunction": self.to_function,
            "toParam": self.to_param,
            "callsiteAddress": self.callsite_address,
            "evidenceIDs": list(self.evidence_ids),
        }


@dataclass(frozen=True)
class FunctionSecurityModel:
    """一个函数的安全角色、参数语义和证据引用。"""

    binary_id: str
    function_id: str
    function_name: str
    function_address: str | None = None
    roles: tuple[str, ...] = ()
    cwe_types: tuple[str, ...] = ()
    source_params: tuple[int, ...] = ()
    sink_params: tuple[int, ...] = ()
    propagation_map: tuple[PropagationMapping, ...] = ()
    status: str = "candidate"
    confidence: str = "low"
    evidence_ids: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.status not in {"candidate", "confirmed", "rejected", "unknown"}:
            raise ValueError(f"未知函数模型状态: {self.status}")
        if self.confidence not in {"low", "medium", "high"}:
            raise ValueError(f"未知函数模型置信度: {self.confidence}")

    def to_dict(self) -> dict[str, object]:
        return {
            "binaryID": self.binary_id,
            "functionID": self.function_id,
            "functionName": self.function_name,
            "functionAddress": self.function_address,
            "roles": list(self.roles),
            "cweTypes": list(self.cwe_types),
            "sourceParams": list(self.source_params),
            "sinkParams": list(self.sink_params),
            "propagationMap": [item.to_dict() for item in self.propagation_map],
            "status": self.status,
            "confidence": self.confidence,
            "evidenceIDs": list(self.evidence_ids),
            "limitations": list(self.limitations),
        }


@dataclass(frozen=True)
class PathQueryRecord:
    """一次 sink 参数查询的紧凑结果摘要。"""

    query_id: str
    binary_id: str
    sink_function_id: str
    sink_params: tuple[int, ...]
    result_status: str
    path_count: int = 0
    evidence_ids: tuple[str, ...] = ()
    coverage: dict[str, Any] = field(default_factory=dict)
    reason: str | None = None

    def __post_init__(self) -> None:
        allowed = {"path_found", "no_path", "unknown", "unsupported", "failed"}
        if self.result_status not in allowed:
            raise ValueError(f"未知路径查询状态: {self.result_status}")
        if self.path_count < 0:
            raise ValueError("path_count 不能为负数")

    def to_dict(self) -> dict[str, object]:
        return {
            "queryID": self.query_id,
            "binaryID": self.binary_id,
            "sinkFunctionID": self.sink_function_id,
            "sinkParams": list(self.sink_params),
            "resultStatus": self.result_status,
            "pathCount": self.path_count,
            "evidenceIDs": list(self.evidence_ids),
            "coverage": self.coverage,
            "reason": self.reason,
        }
