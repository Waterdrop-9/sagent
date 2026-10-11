"""Agent 报告解析和最小结构校验。"""

from __future__ import annotations

import json
from typing import Any


class AgentReportError(ValueError):
    """Agent 输出不是可审计的结构化报告。"""


def parse_report(text: str) -> dict[str, Any]:
    """从纯 JSON 或 Markdown code fence 中提取报告对象。"""
    decoder = json.JSONDecoder()
    for index, char in enumerate(text):
        if char != "{":
            continue
        try:
            value, _ = decoder.raw_decode(text[index:])
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            validate_report(value)
            return value
    raise AgentReportError("Agent 输出中没有有效 JSON 报告")


def validate_report(report: dict[str, Any]) -> None:
    required = {"findings", "unresolved", "coverage"}
    missing = required - set(report)
    if missing:
        raise AgentReportError(f"报告缺少字段: {sorted(missing)}")
    if not isinstance(report["findings"], list):
        raise AgentReportError("报告 findings 必须是数组")
    if not isinstance(report["unresolved"], list):
        raise AgentReportError("报告 unresolved 必须是数组")
    if not isinstance(report["coverage"], dict):
        raise AgentReportError("报告 coverage 必须是对象")
    allowed_status = {"confirmed", "candidate", "inconclusive", "rejected"}
    for index, finding in enumerate(report["findings"]):
        if not isinstance(finding, dict):
            raise AgentReportError(f"findings[{index}] 必须是对象")
        if finding.get("status") not in allowed_status:
            raise AgentReportError(f"findings[{index}] status 无效")
        if not finding.get("evidenceIDs"):
            raise AgentReportError(f"findings[{index}] 缺少 evidenceIDs")
