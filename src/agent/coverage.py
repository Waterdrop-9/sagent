"""分析覆盖账本：限制 Agent 提前结束分析。"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

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
            "surfaceID": self.surface_id,
            "category": self.category,
            "functionID": self.function_id,
            "status": self.status,
            "evidenceIDs": list(self.evidence_ids),
            "reason": self.reason,
        }


@dataclass
class AnalysisCoverageLedger:
    """一个分析组的稀疏覆盖状态和结束门禁。"""

    analysis_group_id: str
    binary_ids: tuple[str, ...]
    surfaces: dict[str, SurfaceRecord] = field(default_factory=dict)
    source_models: dict[str, FunctionSecurityModel] = field(default_factory=dict)
    sink_models: dict[str, FunctionSecurityModel] = field(default_factory=dict)
    path_queries: dict[str, PathQueryRecord] = field(default_factory=dict)
    unresolved_items: list[str] = field(default_factory=list)
    budget: dict[str, int] = field(default_factory=dict)

    def register_surface(self, surface: SurfaceRecord) -> None:
        self.surfaces[surface.surface_id] = surface

    def register_function_model(self, model: FunctionSecurityModel) -> None:
        if "source" in model.roles:
            self.source_models[model.function_id] = model
        if "sink" in model.roles:
            self.sink_models[model.function_id] = model

    def record_path_query(self, query: PathQueryRecord) -> None:
        self.path_queries[query.query_id] = query

    def add_unresolved(self, reason: str) -> None:
        if reason and reason not in self.unresolved_items:
            self.unresolved_items.append(reason)

    def finish_check(self) -> dict[str, object]:
        blockers: list[str] = []
        if any(surface.status == "open" for surface in self.surfaces.values()):
            blockers.append("仍有未检查攻击面")
        for model in self.sink_models.values():
            if model.status == "confirmed" and not any(
                query.sink_function_id == model.function_id
                and query.result_status in {"path_found", "no_path", "unknown", "unsupported", "failed"}
                for query in self.path_queries.values()
            ):
                blockers.append(f"confirmed sink 尚未查询: {model.function_id}")
        if self.unresolved_items:
            blockers.append(f"存在待处理项: {len(self.unresolved_items)}")
        return {"canFinish": not blockers, "blockers": blockers}

    def to_dict(self) -> dict[str, object]:
        surface_counts = _count_status(self.surfaces.values())
        source_counts = _count_status(self.source_models.values())
        sink_counts = _count_status(self.sink_models.values())
        path_counts = _count_status(self.path_queries.values(), attr="result_status")
        return {
            "analysisGroupID": self.analysis_group_id,
            "binaryIDs": list(self.binary_ids),
            "surfaces": surface_counts,
            "sourceModels": source_counts,
            "sinkModels": sink_counts,
            "pathStats": path_counts,
            "unresolvedItems": list(self.unresolved_items),
            "budget": self.budget,
            "finishCheck": self.finish_check(),
        }


def _count_status(items: object, attr: str = "status") -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:  # type: ignore[union-attr]
        value = getattr(item, attr)
        counts[value] = counts.get(value, 0) + 1
    counts["total"] = sum(counts.values())
    return counts
