"""有界工具记录和报告产物；原始证据与 Agent 判断分别保存。"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .agent_report import MAX_REPORT_BYTES, parse_report
from .coverage import ledger_from_report
from .models import PathQueryRecord

MAX_TOOL_BYTES = 128 * 1024
MAX_JOURNAL_BYTES = 4 * 1024 * 1024
MAX_CONTEXT_BYTES = 32 * 1024


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def write_jsonl(path: Path, values: list[dict[str, Any]]) -> None:
    path.write_text("".join(json.dumps(x, ensure_ascii=False) + "\n" for x in values), encoding="utf-8")


class ArtifactStore:
    """每次运行单独目录；同一工具单进程追加原始 JSONL，不按函数分文件。"""

    def __init__(self, directory: Path) -> None:
        self.directory = directory

    def initialize(self, context: dict[str, Any], target: Path) -> None:
        self.directory.mkdir(parents=True, exist_ok=False)
        write_json(self.directory / "manifest.json", {
            "schemaVersion": 1, "analysisGroup": context, "target": str(target),
        })

    def records(self) -> list[dict[str, Any]]:
        records = []
        for tool in ("ghidra", "paths"):
            path = self.directory / "raw" / f"{tool}.jsonl"
            if not path.exists():
                continue
            if path.stat().st_size > MAX_JOURNAL_BYTES + MAX_TOOL_BYTES:
                raise ValueError(f"工具记录超过预算: {tool}")
            for number, line in enumerate(path.read_bytes().splitlines(), 1):
                try:
                    item = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"工具记录损坏: {path}:{number}") from exc
                item["rawRef"] = f"raw/{tool}.jsonl:{number}"
                item["sha256"] = hashlib.sha256(line).hexdigest()
                records.append(item)
        return records

    def finalize(self, report: dict[str, Any]) -> dict[str, Any]:
        manifest = json.loads((self.directory / "manifest.json").read_text())
        context = manifest["analysisGroup"]
        group_id = context["analysisGroupID"]
        binary_ids = tuple(dict.fromkeys(
            [context["root"]["binaryID"], *[c["binaryID"] for c in context["components"]]]
        ))
        records = self.records()
        evidence = {r["evidenceID"]: r for r in records
                    if r["analysisGroupID"] == group_id and r["binaryID"] in binary_ids}
        queries = []
        for record in records:
            if record["server"] != "paths" or record["tool"] != "query_sink_paths":
                continue
            result = record["result"]
            payload = _path_payload(result)
            sink = payload.get("sink", {})
            queries.append(PathQueryRecord(
                query_id=record["evidenceID"], binary_id=record["binaryID"],
                sink_function_id=sink.get("functionID", record["arguments"].get("sink_function", "unknown")),
                sink_params=(record["arguments"].get("sink_argument", 0),),
                result_status=payload.get("status", "failed"),
                path_count=len(payload.get("paths", [])), evidence_ids=(record["evidenceID"],),
                coverage=payload.get("coverage", {}),
                reason=payload.get("reason") or "; ".join(payload.get("limitations", [])) or None,
            ))
        ledger = ledger_from_report(report, group_id, binary_ids, queries)
        if context["pendingDependencies"]:
            ledger.add_unresolved(f"存在未解析依赖: {context['pendingDependencies']}")
        if len(binary_ids) > 1:
            ledger.add_unresolved("当前工具只加载 root binary，本地依赖及跨组件路径尚未覆盖")
        referenced = set()
        invalid_references = set()
        objects = [*report["findings"], *report["coverage"].get("attackSurfaces", []),
                   *report["coverage"].get("functionModels", [])]
        for item in objects:
            valid_ids = []
            for evidence_id in item.get("evidenceIDs", []):
                record = evidence.get(evidence_id)
                if not record or (item.get("binaryID") and item["binaryID"] != record["binaryID"]):
                    ledger.add_unresolved(f"证据引用无法核验: {evidence_id}")
                    invalid_references.add(evidence_id)
                    continue
                if record["result"].get("isError"):
                    ledger.add_unresolved(f"引用的工具执行失败: {evidence_id}")
                    invalid_references.add(evidence_id)
                    continue
                valid_ids.append(evidence_id)
                referenced.add(evidence_id)
            if item.get("binaryID") and item["binaryID"] not in binary_ids:
                ledger.add_unresolved(f"对象不在分析组内: {item['binaryID']}")
            # 报告里不再保留无法核验的 evidenceID。finding 由下方"全部有效"门槛
            # 整体移出，这里只剔除函数模型/攻击面上的坏引用，保留对象本身。
            if item not in report["findings"] and valid_ids != list(item.get("evidenceIDs", [])):
                item["evidenceIDs"] = valid_ids
            # propagationMap 条目里的证据引用同样必须可核验；含坏引用的条目整体
            # 剔除（与 finding 门槛一致：证据不实的传播声明不留在报告里）。
            if "propagationMap" in item:
                kept_entries = []
                for entry in item["propagationMap"]:
                    entry_ids = entry.get("evidenceIDs", [])
                    valid_entry = all(
                        eid in evidence and not evidence[eid]["result"].get("isError")
                        for eid in entry_ids
                    )
                    if valid_entry:
                        kept_entries.append(entry)
                        continue
                    for eid in entry_ids:
                        if eid not in evidence:
                            ledger.add_unresolved(f"传播关系证据引用无法核验: {eid}")
                        elif evidence[eid]["result"].get("isError"):
                            ledger.add_unresolved(f"传播关系引用的工具执行失败: {eid}")
                if kept_entries != item["propagationMap"]:
                    item["propagationMap"] = kept_entries
        final_findings = []
        for finding in report["findings"]:
            valid_evidence = all(
                evidence_id in evidence
                and evidence_id in referenced
                and evidence_id not in invalid_references
                and not evidence[evidence_id]["result"].get("isError")
                for evidence_id in finding.get("evidenceIDs", ())
            )
            if not valid_evidence:
                ledger.add_unresolved(
                    f"finding 未达到最终状态门槛: {finding['binaryID']}/{finding['functionID']}"
                )
                continue
            final_findings.append(finding)
        report["findings"] = final_findings
        budgets = list((self.directory / "raw").glob("budget-*.json"))
        ledger.budget = {"maxCandidateFunctions": 128, "maxSinkQueries": 32,
                         "maxEvidenceBytesPerTool": MAX_JOURNAL_BYTES, "exhausted": bool(budgets)}
        if not report["coverage"].get("functionModels"):
            ledger.add_unresolved("缺少 source/sink 模型枚举记录")
        report["unresolved"] = list(dict.fromkeys([
            *(item if isinstance(item, str) else item["reason"] for item in report["unresolved"]),
            *ledger.unresolved_items,
        ]))
        report["coverageLedger"] = ledger.to_dict()
        report["analysisStatus"] = "complete" if ledger.finish_check()["canFinish"] else "inconclusive"
        report["analysisGroupID"] = group_id
        write_json(self.directory / "state" / "coverage-ledger.json", report["coverageLedger"])
        write_json(self.directory / "state" / "findings.json", report["findings"])
        write_jsonl(self.directory / "candidates.jsonl", report["coverage"].get("functionModels", []))
        write_jsonl(self.directory / "queries.jsonl", [q.to_dict() for q in queries])
        write_jsonl(self.directory / "evidence.jsonl", [
            {k: evidence[e][k] for k in ("evidenceID", "analysisGroupID", "binaryID", "server", "tool", "rawRef", "sha256")}
            for e in sorted(referenced | {q.query_id for q in queries}) if e in evidence
        ])
        write_json(self.directory / "report.json", report)
        return report

    def resume_context(self, context: dict[str, Any]) -> str:
        manifest = json.loads((self.directory / "manifest.json").read_text())
        if manifest["analysisGroup"] != context:
            raise ValueError("恢复目录的分析组、组件哈希或依赖范围与当前输入不一致")
        report_path = self.directory / "report.json"
        if not report_path.exists():
            # 中断时仍可复用已落盘的工具引用，不要求存在最终报告。
            value = {"interrupted": True, "evidence": [
                {k: r[k] for k in ("evidenceID", "tool", "arguments")} for r in self.records()
            ][:32]}
        else:
            if report_path.stat().st_size > MAX_REPORT_BYTES * 2:
                raise ValueError("恢复报告超过大小预算")
            report = parse_report(report_path.read_text())
            value = {"analysisStatus": report.get("analysisStatus"),
                     "unresolved": report["unresolved"][:16],
                     "blockers": report.get("coverageLedger", {}).get("finishCheck", {}).get("blockers", [])[:16],
                     "findings": report["findings"][:16],
                     "functionModels": report["coverage"].get("functionModels", [])[:16]}
        text = json.dumps(value, ensure_ascii=False)
        if len(text.encode()) > MAX_CONTEXT_BYTES:
            text = json.dumps({"resumeDirectory": str(self.directory),
                               "reason": "恢复摘要超过 32 KiB，按需读取原目录；未展示项仍待处理"}, ensure_ascii=False)
        return text


def _path_payload(result: dict[str, Any]) -> dict[str, Any]:
    for block in result.get("content", []):
        if block.get("type") == "text":
            try:
                payload = json.loads(block["text"])
            except (ValueError, KeyError):
                continue
            if isinstance(payload, dict) and payload.get("status") in {
                "path_found", "no_path", "unknown", "unsupported", "failed"
            }:
                return payload
    return {"status": "failed", "reason": "路径工具没有返回有效结构化结果"}
