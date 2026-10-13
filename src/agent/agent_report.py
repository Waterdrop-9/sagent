"""Agent 报告解析和边界校验；覆盖是否充分由本地账本判断。"""

from __future__ import annotations

import json
from typing import Any

from .models import FunctionSecurityModel

MAX_REPORT_BYTES = 512 * 1024
MAX_CANDIDATES = 128


class AgentReportError(ValueError):
    """Agent 输出不是可审计的结构化报告。"""


def parse_report(text: str) -> dict[str, Any]:
    """允许 JSON 前后有 Markdown，但不从非法报告内部挑选另一个对象。"""
    if len(text.encode("utf-8")) > MAX_REPORT_BYTES:
        raise AgentReportError("报告超过 512 KiB 预算")
    decoder = json.JSONDecoder()
    index = 0
    while index < len(text):
        start = text.find("{", index)
        if start < 0:
            break
        try:
            value, length = decoder.raw_decode(text[start:])
        except json.JSONDecodeError:
            index = start + 1
            continue
        if isinstance(value, dict) and {"findings", "unresolved", "coverage"} & value.keys():
            validate_report(value)
            return value
        index = start + length
    raise AgentReportError("Agent 输出中没有有效 JSON 报告")


def _strings(value: Any, label: str, *, nonempty: bool = False) -> None:
    if not isinstance(value, list) or any(not isinstance(x, str) or not x.strip() for x in value):
        raise AgentReportError(f"{label} 必须是非空字符串数组")
    if nonempty and not value:
        raise AgentReportError(f"{label} 不能为空")


def _identity(item: dict[str, Any], label: str) -> None:
    for key in ("binaryID", "functionID"):
        if not isinstance(item.get(key), str) or not item[key].strip():
            raise AgentReportError(f"{label} 缺少 {key}")


def validate_report(report: dict[str, Any]) -> None:
    missing = {"findings", "unresolved", "coverage"} - set(report)
    if missing:
        raise AgentReportError(f"报告缺少字段: {sorted(missing)}")
    for key in ("findings", "unresolved"):
        if not isinstance(report[key], list) or len(report[key]) > MAX_CANDIDATES:
            raise AgentReportError(f"{key} 必须是数组且不超过 {MAX_CANDIDATES} 项")
    if not isinstance(report["coverage"], dict):
        raise AgentReportError("报告 coverage 必须是对象")
    for index, finding in enumerate(report["findings"]):
        label = f"findings[{index}]"
        if not isinstance(finding, dict):
            raise AgentReportError(f"{label} 必须是对象")
        _identity(finding, label)
        if finding.get("status") not in {"confirmed", "rejected"}:
            raise AgentReportError(f"{label} status 无效")
        if finding.get("confidence") not in {"low", "medium", "high"}:
            raise AgentReportError(f"{label} confidence 无效")
        basis = finding.get("confirmationBasis")
        if basis is not None and basis not in {"taint-path", "reference-chain"}:
            raise AgentReportError(f"{label} confirmationBasis 无效")
        _strings(finding.get("evidenceIDs"), label + ".evidenceIDs", nonempty=True)
        _strings(finding.get("limitations", []), label + ".limitations")
    for item in report["unresolved"]:
        reason = item.get("reason") if isinstance(item, dict) else item
        if not isinstance(reason, str) or not reason.strip():
            raise AgentReportError("unresolved 项需要非空原因字符串或 reason 字段")
    coverage = report["coverage"]
    for key in ("attackSurfaces", "functionModels"):
        values = coverage.get(key, [])
        if not isinstance(values, list) or len(values) > MAX_CANDIDATES:
            raise AgentReportError(f"coverage.{key} 必须是数组且不超过 {MAX_CANDIDATES} 项")
        if any(not isinstance(x, dict) for x in values):
            raise AgentReportError(f"coverage.{key} 项必须是对象")
    identities = set()
    for item in coverage.get("attackSurfaces", []):
        identity = item.get("surfaceID")
        if not isinstance(identity, str) or not identity or identity in identities:
            raise AgentReportError("攻击面 surfaceID 必须非空且不能重复")
        identities.add(identity)
        if item.get("status") not in {"open", "checked", "rejected", "unknown"}:
            raise AgentReportError("攻击面 status 无效")
        _strings(item.get("evidenceIDs", []), "攻击面 evidenceIDs")
        if item.get("reason") is not None and not isinstance(item["reason"], str):
            raise AgentReportError("攻击面 reason 必须是字符串")
    identities.clear()
    for item in coverage.get("functionModels", []):
        _identity(item, "函数模型")
        identity = (item["binaryID"], item["functionID"])
        if identity in identities:
            raise AgentReportError("函数模型 binaryID/functionID 不能重复")
        identities.add(identity)
        for key in ("roles", "cweTypes", "evidenceIDs", "limitations"):
            _strings(item.get(key, []), f"函数模型 {key}")
        for key in ("sourceParams", "sinkParams"):
            if not isinstance(item.get(key, []), list):
                raise AgentReportError(f"函数模型 {key} 必须是数组")
        if item.get("propagationMap", []) is not None and not isinstance(item.get("propagationMap", []), (list, dict)):
            raise AgentReportError("函数模型 propagationMap 必须是数组或对象")
        try:
            FunctionSecurityModel.from_dict(item)
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise AgentReportError(f"函数模型无效: {exc}") from exc


def apply_confirmation_policy(report: dict[str, Any], mode: str) -> int:
    """按确认标准模式执行运行时硬门禁。

    precision 模式把 confirmationBasis=reference-chain 的 confirmed finding
    降级为 unresolved（模型自觉不可依赖，硬门禁保证 precision 语义）。
    recall 模式不做任何修改。返回降级条数。
    """
    if mode != "precision":
        return 0
    kept: list[dict[str, Any]] = []
    downgraded: list[dict[str, Any]] = []
    for finding in report["findings"]:
        if finding.get("confirmationBasis") == "reference-chain":
            downgraded.append(finding)
        else:
            kept.append(finding)
    for finding in downgraded:
        report["unresolved"].append(
            f"precision 确认标准拒绝引用链级确认: {finding['binaryID']}/{finding['functionID']}"
            "（confirmationBasis=reference-chain，需污点级证据）"
        )
    report["findings"] = kept
    return len(downgraded)
