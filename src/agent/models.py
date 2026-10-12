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
        if not self.binary_id or not self.function_id:
            raise ValueError("函数模型需要 binaryID 和 functionID")
        if not set(self.roles) <= {"source", "sink", "sanitizer", "wrapper", "parser", "auth_boundary"}:
            raise ValueError("未知函数角色")
        for param in (*self.source_params, *self.sink_params):
            if type(param) is not int or param < 0:
                raise ValueError("参数编号必须是非负整数")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FunctionSecurityModel:
        """恢复紧凑模型；不从 finding 状态推断函数角色。"""
        roles: list[str] = []
        role_map = {
            "source": "source", "sink": "sink", "sink_wrapper": "sink",
            "sinkWrapper": "sink", "sink_candidate": "sink", "sinkCandidate": "sink",
            "propagation": "wrapper",
            "sourceWrapper": "wrapper", "authBoundary": "auth_boundary",
            "validator": "sanitizer", "sanitizer": "sanitizer",
            "wrapper": "wrapper", "parser": "parser", "auth_boundary": "auth_boundary",
        }
        for role in data.get("roles", ()):
            canonical = role_map.get(role)
            if canonical and canonical not in roles:
                roles.append(canonical)
            elif not canonical:
                raise ValueError(f"未知函数角色: {role}")
        raw_map = data.get("propagationMap", ())
        if raw_map is None:
            raw_map = ()
        if isinstance(raw_map, dict):
            raw_map = [
                {"fromParam": key, "toFunction": value, "toParam": None}
                for key, value in raw_map.items()
            ]
        if not isinstance(raw_map, list):
            raise ValueError("propagationMap 必须是数组或对象")
        return cls(
            binary_id=data["binaryID"], function_id=data["functionID"],
            function_name=data.get("functionName", data["functionID"]),
            function_address=data.get("functionAddress"), roles=tuple(roles),
            cwe_types=tuple(data.get("cweTypes", ())),
            source_params=tuple(data.get("sourceParams", ())), sink_params=tuple(data.get("sinkParams", ())),
            propagation_map=tuple(PropagationMapping(
                from_param=p["fromParam"], to_function=p["toFunction"],
                to_param=p.get("toParam"), callsite_address=p.get("callsiteAddress"),
                evidence_ids=tuple(p.get("evidenceIDs", ())),
            ) for p in raw_map),
            status=data.get("status", "candidate"), confidence=data.get("confidence", "low"),
            evidence_ids=tuple(data.get("evidenceIDs", ())), limitations=tuple(data.get("limitations", ())),
        )

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
