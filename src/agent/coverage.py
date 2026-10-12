"""分析覆盖账本：按组件和敏感参数检查结束条件。"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from .models import FunctionSecurityModel, PathQueryRecord


@dataclass(frozen=True)
class SurfaceRecord:
    surface_id: str
    category: str
    function_id: str | None
    status: str = "open"
    evidence_ids: tuple[str, ...] = ()
    reason: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "surfaceID": self.surface_id, "category": self.category,
            "functionID": self.function_id, "status": self.status,
            "evidenceIDs": list(self.evidence_ids), "reason": self.reason,
        }


@dataclass
class AnalysisCoverageLedger:
    """一个分析组的稀疏覆盖状态；canFinish 表示覆盖充分，而非允许输出部分报告。"""

    analysis_group_id: str
    binary_ids: tuple[str, ...]
    surfaces: dict[str, SurfaceRecord] = field(default_factory=dict)
    source_models: dict[tuple[str, str], FunctionSecurityModel] = field(default_factory=dict)
    sink_models: dict[tuple[str, str], FunctionSecurityModel] = field(default_factory=dict)
    path_queries: dict[str, PathQueryRecord] = field(default_factory=dict)
    unresolved_items: list[str] = field(default_factory=list)
    budget: dict[str, Any] = field(default_factory=dict)

    def register_surface(self, surface: SurfaceRecord) -> None:
        self.surfaces[surface.surface_id] = surface

    def register_function_model(self, model: FunctionSecurityModel) -> None:
        key = (model.binary_id, model.function_id)
        # 替换同一函数时也移除旧角色，避免残留 confirmed 模型。
        for role, models in (("source", self.source_models), ("sink", self.sink_models)):
            models.pop(key, None)
            if role in model.roles:
                models[key] = model

    def record_path_query(self, query: PathQueryRecord) -> None:
        self.path_queries[query.query_id] = query

    def add_unresolved(self, reason: str) -> None:
        if reason and reason not in self.unresolved_items:
            self.unresolved_items.append(reason)

    def finish_check(self) -> dict[str, object]:
        blockers: list[str] = []
        if not self.surfaces:
            blockers.append("缺少攻击面检查记录")
        for surface in self.surfaces.values():
            if surface.status not in {"checked", "rejected"}:
                blockers.append(f"攻击面未完成: {surface.surface_id} ({surface.status})")
            if surface.status == "unknown" and not surface.reason:
                blockers.append(f"unknown 攻击面缺少原因: {surface.surface_id}")
            if surface.status in {"checked", "rejected"} and not surface.evidence_ids:
                blockers.append(f"攻击面缺少证据: {surface.surface_id}")
        models = {**self.source_models, **self.sink_models}
        for key, model in models.items():
            identity = f"{model.binary_id}/{model.function_id}"
            if model.binary_id not in self.binary_ids:
                blockers.append(f"模型不在分析组内: {identity}")
            if model.status in {"candidate", "unknown"}:
                blockers.append(f"模型未完成: {identity} ({model.status})")
            if model.status in {"confirmed", "rejected"} and not model.evidence_ids:
                blockers.append(f"模型缺少证据: {identity}")
            if key not in self.sink_models or model.status != "confirmed":
                continue
            if not model.sink_params:
                blockers.append(f"confirmed sink 缺少敏感参数: {identity}")
            for param in model.sink_params:
                if not any(
                    query.binary_id == model.binary_id
                    and _same_function(query.sink_function_id, model)
                    and param in query.sink_params
                    for query in self.path_queries.values()
                ):
                    blockers.append(f"confirmed sink 尚未查询参数 {param}: {identity}")
        for query in self.path_queries.values():
            if query.result_status in {"unknown", "unsupported", "failed"}:
                blockers.append(f"查询未完成: {query.query_id} ({query.result_status})")
                if not query.reason:
                    blockers.append(f"查询缺少原因: {query.query_id}")
            if query.result_status in {"path_found", "no_path"} and not query.evidence_ids:
                blockers.append(f"查询缺少证据: {query.query_id}")
            if query.coverage.get("budgetExhausted"):
                blockers.append(f"budget_exhausted: {query.query_id}")
        if self.budget.get("exhausted"):
            blockers.append("budget_exhausted")
        if self.unresolved_items:
            blockers.append(f"存在待处理项: {len(self.unresolved_items)}")
        return {"canFinish": not blockers, "blockers": blockers}

    def to_dict(self) -> dict[str, object]:
        return {
            "analysisGroupID": self.analysis_group_id,
            "binaryIDs": list(self.binary_ids),
            "surfaces": _count_status(self.surfaces.values()),
            "sourceModels": _count_status(self.source_models.values()),
            "sinkModels": _count_status(self.sink_models.values()),
            "pathStats": _count_status(self.path_queries.values(), "result_status"),
            "unresolvedItems": list(self.unresolved_items),
            "budget": self.budget, "finishCheck": self.finish_check(),
        }


def ledger_from_report(
    report: dict[str, Any], analysis_group_id: str, binary_ids: tuple[str, ...],
    queries: Iterable[PathQueryRecord] = (),
) -> AnalysisCoverageLedger:
    """报告提供语义模型；查询只接受调用方读取的实际工具记录。"""
    ledger = AnalysisCoverageLedger(analysis_group_id, binary_ids)
    coverage = report["coverage"]
    for item in coverage.get("attackSurfaces", []):
        ledger.register_surface(SurfaceRecord(
            item["surfaceID"], item.get("category", "agent"), item.get("functionID"),
            item["status"], tuple(item.get("evidenceIDs", ())), item.get("reason"),
        ))
    for item in coverage.get("functionModels", []):
        ledger.register_function_model(FunctionSecurityModel.from_dict(item))
    for query in queries:
        ledger.record_path_query(query)
    for finding in report["findings"]:
        if finding["status"] in {"candidate", "inconclusive"}:
            ledger.add_unresolved(f"待复核 finding: {finding['binaryID']}/{finding['functionID']}")
    for item in report["unresolved"]:
        ledger.add_unresolved(item if isinstance(item, str) else item["reason"])
    return ledger


def _count_status(items: Iterable[Any], attr: str = "status") -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        value = getattr(item, attr)
        counts[value] = counts.get(value, 0) + 1
    counts["total"] = sum(counts.values())
    return counts


def _same_function(query_id: str, model: FunctionSecurityModel) -> bool:
    """允许工具用解析后的地址表示外部符号，仍要求 binaryID 相同。"""
    if query_id == model.function_id:
        return True
    if model.function_address and query_id == model.function_address:
        return True
    return query_id.rsplit("/", 1)[-1] == model.function_id
