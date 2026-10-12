"""启动真实 Agent，逐分析组保留工具证据并核验最终覆盖。"""

from __future__ import annotations

import argparse
import json
import logging
import shutil
import tempfile
from pathlib import Path
from uuid import uuid4

from .analysis_context import AnalysisContextError, build_contexts, render_contexts
from .agent_report import AgentReportError, MAX_REPORT_BYTES, parse_report
from .artifacts import ArtifactStore, write_json
from .config import ConfigError, agent_environment, load_config, load_ghidra_config
from .poc_stage import PocStageAdapter, PocStageError
from .plugins import plugin_for_cwe, supported_cwes, write_runtime_config
from .runtime import AgentRuntimeError, AgentRequest, runtime_from_name

LOG = logging.getLogger(__name__)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="二进制静态分析 Agent")
    parser.add_argument("--config", type=Path, default=Path("config.toml"))
    parser.add_argument("--target", type=Path, required=True, help="待分析 ELF 或目录")
    parser.add_argument("--dependency-root", action="append", type=Path, default=[])
    parser.add_argument("--goal", required=True, help="人工分析目标")
    parser.add_argument("--cwe", choices=supported_cwes(), default="CWE-78", help="本次运行的 CWE 类型")
    parser.add_argument("--output", type=Path, default=Path("analysis"), help="产物根目录")
    parser.add_argument("--resume", type=Path, help="此前单个分析组的运行目录")
    parser.add_argument("--poc", action="store_true", help="对 confirmed findings 接入外部 PoC 阶段")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    args.target = args.target.expanduser().resolve()
    try:
        config = load_config(args.config)
        contexts = build_contexts(args.target, args.dependency_root)
        ghidra = load_ghidra_config()
        if args.resume and len(contexts) != 1:
            raise AnalysisContextError("--resume 需要单 ELF 输入；每个分析组独立恢复")
        plugin = plugin_for_cwe(args.cwe)
        runtime = runtime_from_name(config.agent.runtime, timeout=config.agent.timeout)
        poc_requested = args.poc or config.poc.enabled
        poc_adapter = None
        if poc_requested:
            if config.poc.prompt_file is None:
                raise ConfigError("启用 PoC 阶段需要配置 poc.prompt_file")
            poc_adapter = PocStageAdapter(config.poc.prompt_file)
        source_root = Path(__file__).resolve().parents[1]
        reports = []
        failed = False
        for context in contexts:
            directory = args.output.resolve() / context.analysis_group_id / ("run-" + uuid4().hex[:12])
            store = ArtifactStore(directory)
            resume_text = ""
            if args.resume:
                resume_text = ArtifactStore(args.resume.resolve()).resume_context(context.to_dict())
            prompt = plugin.build_user_prompt(args.goal, context.root_path, render_contexts((context,)))
            if resume_text:
                prompt += "\n\n上次运行摘要（继续核验未完成项，不可当作新增工具事实）：\n" + resume_text
            if not args.dry_run:
                store.initialize(context.to_dict(), context.root_path)
                if args.resume and (args.resume / "raw").exists():
                    shutil.copytree(args.resume / "raw", directory / "raw")
                LOG.info("开始分析 group=%s target=%s artifacts=%s", context.analysis_group_id, context.root_path.name, directory)
            with tempfile.TemporaryDirectory(prefix="agent-") as temporary:
                config_path = write_runtime_config(
                    plugin, config.agent.runtime, context.root_path, source_root,
                    Path(temporary) / "mcp.json", ghidra=ghidra,
                    provider=config.agent.provider, model=config.agent.model,
                    api_key=config.agent.api_key, base_url=config.agent.base_url,
                    artifact_dir=directory, analysis_group_id=context.analysis_group_id,
                    binary_id=context.root["binaryID"],
                )
                request = AgentRequest(
                    system_prompt=plugin.system_prompt, user_prompt=prompt,
                    mcp_config=config_path, cwd=Path.cwd(), model=config.agent.model,
                    provider=config.agent.provider, base_url=config.agent.base_url,
                    environment=agent_environment(config.agent),
                )
                if args.dry_run:
                    preview = {"command": runtime.build_command(request),
                               "mcpConfig": json.loads(config_path.read_text())}
                    text = json.dumps(preview, ensure_ascii=False, indent=2)
                    if config.agent.api_key:
                        text = text.replace(config.agent.api_key, "<redacted>")
                    print(text)
                    continue
                try:
                    response = runtime.run(request)
                    # 模型原文独立保存，不以规范化报告覆盖它。
                    if len(response.text.encode()) > MAX_REPORT_BYTES:
                        write_json(directory / "raw" / "budget-agent.json", {"reason": "Agent 报告超过 512 KiB"})
                        raise AgentReportError("Agent 报告超过 512 KiB，已保留工具记录供恢复")
                    (directory / "raw").mkdir(exist_ok=True)
                    (directory / "raw" / "agent.txt").write_text(response.text, encoding="utf-8")
                    report = store.finalize(parse_report(response.text))
                    confirmed_findings = [
                        finding for finding in report["findings"]
                        if finding.get("status") == "confirmed"
                    ]
                    if poc_adapter and confirmed_findings:
                        try:
                            poc_prompt = poc_adapter.build_prompt(
                                context.root_path, args.cwe, confirmed_findings, directory
                            )
                            poc_request = AgentRequest(
                                system_prompt="", user_prompt=poc_prompt, mcp_config=config_path,
                                cwd=directory, model=config.agent.model,
                                provider=config.agent.provider, base_url=config.agent.base_url,
                                environment=agent_environment(config.agent),
                            )
                            poc_response = runtime.run(poc_request)
                            poc_directory = directory / "poc"
                            poc_directory.mkdir(parents=True, exist_ok=True)
                            (poc_directory / "external-stage-response.md").write_text(
                                poc_response.text, encoding="utf-8"
                            )
                            report["poc"] = {
                                "status": "generated",
                                "directory": str(poc_directory),
                                "findingCount": len(confirmed_findings),
                            }
                        except (AgentRuntimeError, PocStageError) as exc:
                            report["poc"] = {
                                "status": "failed", "reason": str(exc),
                                "findingCount": len(confirmed_findings),
                            }
                    elif poc_adapter:
                        report["poc"] = {
                            "status": "skipped_no_confirmed_findings",
                            "findingCount": 0,
                        }
                    if poc_adapter:
                        write_json(directory / "report.json", report)
                    report["artifactDirectory"] = str(directory)
                    reports.append(report)
                    LOG.info("分析结束 group=%s status=%s", context.analysis_group_id, report["analysisStatus"])
                except (AgentRuntimeError, AgentReportError, PocStageError, OSError, ValueError) as exc:
                    failed = True
                    error = {"analysisGroupID": context.analysis_group_id, "analysisStatus": "inconclusive",
                             "error": str(exc), "artifactDirectory": str(directory)}
                    write_json(directory / "error.json", error)
                    reports.append(error)
                    LOG.error("分析失败 group=%s reason=%s", context.analysis_group_id, exc)
        if not args.dry_run:
            print(json.dumps(reports[0] if len(reports) == 1 else {"analysisGroups": reports}, ensure_ascii=False, indent=2))
        return 1 if failed else 0
    except (ConfigError, AnalysisContextError, AgentReportError, OSError, ValueError) as exc:
        parser.error(str(exc))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
