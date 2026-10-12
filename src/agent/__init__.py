"""Sagent 的生产级 Agent 底座适配和 CWE 插件原型。"""

from .plugins import Cwe78Plugin, CwePlugin, plugin_for_cwe, supported_cwes
from .external_poc import ExternalPocAdapter
from .runtime import AgentRequest, AgentResponse, ClaudeCodeRuntime, OpenCodeRuntime
from .models import FunctionSecurityModel, PathQueryRecord, PropagationMapping
from .coverage import AnalysisCoverageLedger, SurfaceRecord

__all__ = [
    "AgentRequest",
    "AgentResponse",
    "ClaudeCodeRuntime",
    "OpenCodeRuntime",
    "Cwe78Plugin",
    "CwePlugin",
    "ExternalPocAdapter",
    "plugin_for_cwe",
    "supported_cwes",
    "FunctionSecurityModel",
    "PathQueryRecord",
    "PropagationMapping",
    "AnalysisCoverageLedger",
    "SurfaceRecord",
]
