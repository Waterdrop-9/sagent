"""把 elf.py 分析组压缩为 Agent 可消费的工作上下文。"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from elf import AnalysisGroup, ElfError, build_analysis_groups


class AnalysisContextError(ValueError):
    """分析组无法构建或上下文输入无效。"""


@dataclass(frozen=True)
class AnalysisGroupContext:
    """一个分析组的紧凑、可序列化摘要。"""

    analysis_group_id: str
    root: dict[str, object]
    components: tuple[dict[str, object], ...]
    dependencies: tuple[dict[str, object], ...]
    pending_dependencies: int

    def to_dict(self) -> dict[str, object]:
        return {
            "analysisGroupID": self.analysis_group_id,
            "root": self.root,
            "components": list(self.components),
            "dependencies": list(self.dependencies),
            "pendingDependencies": self.pending_dependencies,
        }


def build_contexts(
    input_path: str | Path,
    dependency_roots: Iterable[str | Path] = (),
) -> tuple[AnalysisGroupContext, ...]:
    try:
        groups = build_analysis_groups(input_path, dependency_roots)
    except ElfError as exc:
        raise AnalysisContextError(str(exc)) from exc
    return tuple(_compact_group(group) for group in groups)


def render_contexts(contexts: tuple[AnalysisGroupContext, ...]) -> str:
    """渲染短 JSON 摘要；不放入反编译文本和完整工具产物。"""

    return json.dumps(
        {"analysisGroups": [context.to_dict() for context in contexts]},
        ensure_ascii=False,
        indent=2,
    )


def _compact_group(group: AnalysisGroup) -> AnalysisGroupContext:
    root = group.root.to_dict()
    root["binaryID"] = root.pop("sha256")
    root["path"] = Path(str(root["path"])).name

    components = []
    for component in group.components:
        data = component.to_dict()
        data["binaryID"] = data.pop("sha256")
        data["path"] = Path(str(data["path"])).name
        components.append(
            {
                "binaryID": data["binaryID"],
                "path": data["path"],
                "type": data["type"],
                "machine": data["machine"],
                "class": data["class"],
                "needed": data["needed"],
            }
        )

    dependencies = []
    pending = 0
    for edge in group.edges:
        item = {
            "source": edge.source.name,
            "requested": edge.requested,
            "target": edge.target.name if edge.target else None,
            "knownLibrary": edge.known_library,
            "reason": edge.reason,
        }
        dependencies.append(item)
        if edge.target is None and not edge.known_library:
            pending += 1

    analysis_group_id = "group-" + hashlib.sha256(
        (group.root.digest + "\0" + "\0".join(sorted(c.digest for c in group.components))).encode()
    ).hexdigest()[:16]
    return AnalysisGroupContext(
        analysis_group_id=analysis_group_id,
        root=root,
        components=tuple(components),
        dependencies=tuple(dependencies),
        pending_dependencies=pending,
    )
