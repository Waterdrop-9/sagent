"""最小的静态事实驱动 Agent loop 原型。

本模块不调用模型，也不执行样本。内存工具后端用于验证任务、证据和
CWE 插件接口；真实环境可以用 Ghidra 适配器实现同一个工具接口。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass(frozen=True)
class DependencyStep:
    """一条有静态证据支持的参数级数据依赖边。"""

    caller: str
    caller_argument: int
    callee: str
    callee_argument: int
    evidence: str


@dataclass(frozen=True)
class FunctionFact:
    function_id: str
    name: str
    source_arguments: tuple[int, ...] = ()
    sink_arguments: tuple[int, ...] = ()
    summary: str = ""


@dataclass(frozen=True)
class DataDependencyPath:
    source: tuple[str, int]
    sink: tuple[str, int]
    steps: tuple[DependencyStep, ...]


@dataclass(frozen=True)
class AnalysisTask:
    kind: str
    target: str
    arguments: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ToolArtifact:
    task: AnalysisTask
    value: Any


@dataclass(frozen=True)
class Evidence:
    kind: str
    subject: str
    detail: str


@dataclass(frozen=True)
class Finding:
    cwe: str
    title: str
    path: DataDependencyPath
    confidence: str
    limitations: tuple[str, ...] = ()


@dataclass
class AnalysisState:
    goal: str
    cwe: str
    pending_tasks: list[AnalysisTask] = field(default_factory=list)
    artifacts: list[ToolArtifact] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    hypotheses: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    failures: list[str] = field(default_factory=list)


class StaticAnalysisTool(Protocol):
    def query_sink_paths(
        self, sink_function: str, sink_argument: int
    ) -> tuple[DataDependencyPath, ...]: ...


class CwePlugin(Protocol):
    cwe_id: str
    knowledge_prompt: str

    def initial_tasks(self) -> tuple[AnalysisTask, ...]: ...

    def follow_up_tasks(
        self, artifact: ToolArtifact, state: AnalysisState
    ) -> tuple[AnalysisTask, ...]: ...

    def interpret(
        self, artifact: ToolArtifact, state: AnalysisState
    ) -> tuple[Finding, ...]: ...

    def is_complete(self, state: AnalysisState) -> bool: ...


class AgentLoop:
    """执行一次有预算的工具驱动分析循环。"""

    def __init__(
        self,
        tool: StaticAnalysisTool,
        plugin: CwePlugin,
        *,
        max_steps: int = 20,
    ) -> None:
        if max_steps < 1:
            raise ValueError("max_steps 必须大于 0")
        self.tool = tool
        self.plugin = plugin
        self.max_steps = max_steps

    def run(self, goal: str) -> AnalysisState:
        state = AnalysisState(
            goal=goal,
            cwe=self.plugin.cwe_id,
            pending_tasks=list(self.plugin.initial_tasks()),
        )
        for _ in range(self.max_steps):
            if self.plugin.is_complete(state) or not state.pending_tasks:
                break
            task = state.pending_tasks.pop(0)
            try:
                artifact = self._execute(task)
            except (KeyError, ValueError) as exc:
                state.failures.append(f"{task.kind}:{task.target}: {exc}")
                continue

            state.artifacts.append(artifact)
            if not self._validate(artifact, state):
                continue
            state.findings.extend(self.plugin.interpret(artifact, state))
            state.pending_tasks.extend(self.plugin.follow_up_tasks(artifact, state))
        return state

    def _execute(self, task: AnalysisTask) -> ToolArtifact:
        if task.kind != "query_paths":
            raise ValueError(f"不支持的任务类型: {task.kind}")
        argument = task.arguments.get("sink_argument")
        if not isinstance(argument, int):
            raise ValueError("query_paths 缺少 sink_argument")
        paths = self.tool.query_sink_paths(task.target, argument)
        return ToolArtifact(task, paths)

    @staticmethod
    def _validate(artifact: ToolArtifact, state: AnalysisState) -> bool:
        if not isinstance(artifact.value, tuple):
            state.failures.append(f"{artifact.task.target}: 工具结果不是路径元组")
            return False
        for path in artifact.value:
            if not isinstance(path, DataDependencyPath):
                state.failures.append(f"{artifact.task.target}: 路径结果类型无效")
                return False
            if not path.steps:
                state.failures.append(f"{artifact.task.target}: 路径缺少数据依赖证据")
                return False
            state.evidence.extend(
                Evidence("data_dependency", step.caller, step.evidence)
                for step in path.steps
            )
        return True


class InMemoryStaticTool:
    """用固定事实模拟 sink 驱动的反向数据依赖查询。"""

    def __init__(self, paths: tuple[DataDependencyPath, ...]) -> None:
        self._paths = paths

    def query_sink_paths(
        self, sink_function: str, sink_argument: int
    ) -> tuple[DataDependencyPath, ...]:
        return tuple(
            path
            for path in self._paths
            if path.sink == (sink_function, sink_argument)
        )


class Cwe78Plugin:
    cwe_id = "CWE-78"
    knowledge_prompt = (
        "判断命令注入时，确认外部可控输入是否沿数据依赖路径到达命令执行 sink；"
        "检查固定命令、白名单和有效转义，并要求每个结论有路径证据。"
    )

    def __init__(self, sinks: tuple[tuple[str, int], ...]) -> None:
        self.sinks = sinks

    def initial_tasks(self) -> tuple[AnalysisTask, ...]:
        return tuple(
            AnalysisTask("query_paths", function, {"sink_argument": argument})
            for function, argument in self.sinks
        )

    def follow_up_tasks(
        self, artifact: ToolArtifact, state: AnalysisState
    ) -> tuple[AnalysisTask, ...]:
        # 首版只验证路径查询闭环；后续可在这里加入按需函数查询。
        return ()

    def interpret(
        self, artifact: ToolArtifact, state: AnalysisState
    ) -> tuple[Finding, ...]:
        findings: list[Finding] = []
        for path in artifact.value:
            source_function, source_argument = path.source
            if source_function.startswith("external_"):
                findings.append(
                    Finding(
                        cwe=self.cwe_id,
                        title="外部输入到命令执行 sink 的候选路径",
                        path=path,
                        confidence="candidate",
                        limitations=(
                            "首版 source 标记来自静态 fixture，尚未接入真实输入识别和 sanitizer 判断",
                        ),
                    )
                )
                state.hypotheses.append(
                    f"{source_function}[{source_argument}] 可能控制 {path.sink[0]}[{path.sink[1]}]"
                )
        return tuple(findings)

    def is_complete(self, state: AnalysisState) -> bool:
        return not state.pending_tasks and bool(state.artifacts)


def demo() -> AnalysisState:
    path = DataDependencyPath(
        source=("external_http_param", 0),
        sink=("system", 0),
        steps=(
            DependencyStep(
                "handle_request",
                1,
                "build_command",
                0,
                "handle_request.arg1 -> build_command.arg0",
            ),
            DependencyStep(
                "build_command",
                0,
                "system",
                0,
                "build_command.return -> system.arg0",
            ),
        ),
    )
    plugin = Cwe78Plugin((("system", 0),))
    return AgentLoop(InMemoryStaticTool((path,)), plugin).run("检查 HTTP 参数是否到达命令执行")


if __name__ == "__main__":
    result = demo()
    print(f"CWE={result.cwe} findings={len(result.findings)} evidence={len(result.evidence)}")
    for finding in result.findings:
        print(
            f"{finding.title}: "
            f"{finding.path.source[0]} -> {finding.path.sink[0]} "
            f"({finding.confidence})"
        )
