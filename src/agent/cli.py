"""启动真实 Agent，逐分析组保留工具证据并核验最终覆盖。"""

from __future__ import annotations

import argparse
import json
import logging
import shutil
import tempfile
import time
from pathlib import Path
from typing import Any
from uuid import uuid4

from .analysis_context import AnalysisContextError, build_contexts, render_contexts
from .agent_report import AgentReportError, MAX_REPORT_BYTES, parse_report
from .artifacts import ArtifactStore, write_json
from .config import AgentConfig, ConfigError, agent_environment, load_config, load_ghidra_config
from .poc_stage import PocStageAdapter, PocStageError
from .plugins import plugin_for_cwe, supported_cwes, write_runtime_config
from .runtime import AgentRuntimeError, AgentRequest, runtime_from_name

LOG = logging.getLogger(__name__)


def _agent_request(
    agent: AgentConfig,
    *,
    system_prompt: str,
    user_prompt: str,
    mcp_config: Path,
    cwd: Path,
) -> AgentRequest:
    """按本地配置组装一次 Agent 请求；分析与 PoC 两个阶段共用同一套填充逻辑。"""
    return AgentRequest(
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        mcp_config=mcp_config,
        cwd=cwd,
        model=agent.model,
        provider=agent.provider,
        base_url=agent.base_url,
        environment=agent_environment(agent),
    )


def _poc_manifest_base(
    confirmed_findings: list[dict[str, Any]], files: list[str] | None = None
) -> dict[str, Any]:
    """PoC 账目的公共字段；files 是 poc/ 交付物索引，失败时为 []。"""
    return {
        "stage": "poc",
        "findingCount": len(confirmed_findings),
        "findingIDs": [
            f"{item['binaryID']}/{item['functionID']}" for item in confirmed_findings
        ],
        "files": files if files is not None else [],
        "executed": False,
    }


def _attach_run_log(directory: Path) -> logging.Handler:
    """把本轮日志追加进 run 目录的 analysis.log，便于事后按轮次排查。"""
    handler = logging.FileHandler(directory / "analysis.log", encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logging.getLogger().addHandler(handler)
    return handler


def _detach_run_log(handler: logging.Handler | None) -> None:
    if handler is not None:
        root = logging.getLogger()
        root.removeHandler(handler)
        handler.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="二进制静态分析 Agent")
    parser.add_argument("--config", type=Path, default=Path("config.toml"))
    parser.add_argument("--target", type=Path, required=True, help="待分析 ELF 或目录")
    parser.add_argument("--dependency-root", action="append", type=Path, default=[])
    parser.add_argument("--goal", required=True, help="人工分析目标")
    # 默认 all：一次运行覆盖全部支持的 CWE，不必每次手工指定单个类型。
    parser.add_argument(
        "--cwe",
        choices=[*supported_cwes(), "all"],
        default="all",
        help="本次运行的 CWE 类型；all 表示依次运行全部支持的 CWE（默认）",
    )
    parser.add_argument("--output", type=Path, default=Path("analysis"), help="产物根目录")
    parser.add_argument("--resume", type=Path, help="此前单个分析组的运行目录")
    parser.add_argument("--poc", action="store_true", help="对 confirmed findings 接入独立的 PoC 阶段")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    run_started = time.monotonic()
    args.target = args.target.expanduser().resolve()
    try:
        config = load_config(args.config)
        contexts = build_contexts(args.target, args.dependency_root)
        ghidra = load_ghidra_config()
        if args.resume and len(contexts) != 1:
            raise AnalysisContextError("--resume 需要单 ELF 输入；每个分析组独立恢复")
        cwes = supported_cwes() if args.cwe == "all" else [args.cwe]
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
            for cwe in cwes:
                plugin = plugin_for_cwe(cwe)
                directory = args.output.resolve() / context.analysis_group_id / ("run-" + uuid4().hex[:12])
                store = ArtifactStore(directory)
                resume_text = ""
                if args.resume:
                    resume_text = ArtifactStore(args.resume.resolve()).resume_context(context.to_dict())
                prompt = plugin.build_user_prompt(args.goal, context.root_path, render_contexts((context,)))
                if resume_text:
                    prompt += "\n\n上次运行摘要（继续核验未完成项，不可当作新增工具事实）：\n" + resume_text
                run_log = None
                if not args.dry_run:
                    store.initialize(context.to_dict(), context.root_path)
                    if args.resume and (args.resume / "raw").exists():
                        shutil.copytree(args.resume / "raw", directory / "raw")
                    run_log = _attach_run_log(directory)
                    LOG.info(
                        "开始分析 group=%s cwe=%s target=%s artifacts=%s",
                        context.analysis_group_id, cwe, context.root_path.name, directory,
                    )
                with tempfile.TemporaryDirectory(prefix="agent-") as temporary:
                    config_path = write_runtime_config(
                        plugin, config.agent.runtime, context.root_path, source_root,
                        Path(temporary) / "mcp.json", ghidra=ghidra,
                        provider=config.agent.provider, model=config.agent.model,
                        api_key=config.agent.api_key, base_url=config.agent.base_url,
                        artifact_dir=directory, analysis_group_id=context.analysis_group_id,
                        binary_id=context.root["binaryID"],
                    )
                    request = _agent_request(
                        config.agent,
                        system_prompt=plugin.system_prompt,
                        user_prompt=prompt,
                        mcp_config=config_path,
                        # cwd 指向本轮的产物目录：opencode 的项目配置与模型写的文件
                        # 都落在 cwd 下，指向 run 目录可保证一轮产物自包含、不污染仓库根。
                        cwd=directory,
                    )
                    if args.dry_run:
                        preview = {"cwe": cwe, "command": runtime.build_command(request),
                                   "mcpConfig": json.loads(config_path.read_text())}
                        text = json.dumps(preview, ensure_ascii=False, indent=2)
                        if config.agent.api_key:
                            text = text.replace(config.agent.api_key, "<redacted>")
                        print(text)
                        continue
                    try:
                        analysis_started = time.monotonic()
                        response = runtime.run(request)
                        # 模型原文独立保存，不以规范化报告覆盖它。
                        if len(response.text.encode()) > MAX_REPORT_BYTES:
                            write_json(directory / "raw" / "budget-agent.json", {"reason": "Agent 报告超过 512 KiB"})
                            raise AgentReportError("Agent 报告超过 512 KiB，已保留工具记录供恢复")
                        (directory / "raw").mkdir(exist_ok=True)
                        (directory / "raw" / "agent.txt").write_text(response.text, encoding="utf-8")
                        report = store.finalize(parse_report(response.text))
                        report["cwe"] = cwe
                        confirmed_findings = [
                            finding for finding in report["findings"]
                            if finding.get("status") == "confirmed"
                        ]
                        if poc_adapter and confirmed_findings:
                            poc_directory = directory / "poc"
                            poc_directory.mkdir(parents=True, exist_ok=True)
                            try:
                                started = time.monotonic()
                                LOG.info(
                                    "开始 PoC 阶段 group=%s findings=%d cwd=%s",
                                    context.analysis_group_id, len(confirmed_findings), poc_directory,
                                )
                                poc_prompt = poc_adapter.build_prompt(
                                    context.root_path, cwe, confirmed_findings, poc_directory
                                )
                                # request/response/manifest 只记流程账目，不落进 poc/，
                                # 保证 poc/ 里只有模型生成的 PoC 报告。
                                (directory / "poc-request.md").write_text(
                                    poc_prompt, encoding="utf-8"
                                )
                                poc_request = _agent_request(
                                    config.agent,
                                    system_prompt="",
                                    user_prompt=poc_prompt,
                                    mcp_config=config_path,
                                    cwd=poc_directory,
                                )
                                poc_response = runtime.run(poc_request)
                                (directory / "poc-response.md").write_text(
                                    poc_response.text, encoding="utf-8"
                                )
                                # 自动清点 poc/ 里的交付物（只数普通文件），
                                # 让 manifest 成为产物索引：查看结果时不用翻目录。
                                poc_files = sorted(
                                    path.name for path in poc_directory.iterdir()
                                    if path.is_file()
                                )
                                manifest = _poc_manifest_base(confirmed_findings, poc_files)
                                manifest.update({
                                    "runtime": poc_response.runtime,
                                    "request": "poc-request.md",
                                    "response": "poc-response.md",
                                    "usage": poc_response.usage,
                                })
                                write_json(directory / "poc-manifest.json", manifest)
                                report["poc"] = {
                                    "status": "generated",
                                    "directory": str(poc_directory),
                                    "findingCount": len(confirmed_findings),
                                }
                                poc_usage = poc_response.usage or {}
                                LOG.info(
                                    "PoC 阶段结束 group=%s 耗时=%.1fs files=%d tokens_in=%s tokens_out=%s",
                                    context.analysis_group_id, time.monotonic() - started,
                                    len(poc_files), poc_usage.get("tokens_input"), poc_usage.get("tokens_output"),
                                )
                            except (AgentRuntimeError, PocStageError) as exc:
                                # 失败也写 run 级账目，且字段形状与成功一致（files 为空），
                                # 消费方按 files 索引时不会遇到缺失字段。
                                write_json(directory / "poc-manifest.json", {
                                    **_poc_manifest_base(confirmed_findings),
                                    "status": "failed",
                                    "error": str(exc),
                                })
                                report["poc"] = {
                                    "status": "failed", "reason": str(exc),
                                    "findingCount": len(confirmed_findings),
                                }
                                LOG.error(
                                    "PoC 阶段失败 group=%s reason=%s",
                                    context.analysis_group_id, exc,
                                )
                        elif poc_adapter:
                            report["poc"] = {
                                "status": "skipped_no_confirmed_findings",
                                "findingCount": 0,
                            }
                        # 开销观测：elapsedSeconds 覆盖分析+PoC 两个阶段的墙钟时间，
                        # usage 来自底座（opencode 读本地会话库，读不到为 None）。
                        report["elapsedSeconds"] = round(time.monotonic() - analysis_started, 1)
                        report["usage"] = response.usage
                        if poc_adapter:
                            write_json(directory / "report.json", report)
                        report["artifactDirectory"] = str(directory)
                        reports.append(report)
                        usage = response.usage or {}
                        LOG.info(
                            "分析结束 group=%s cwe=%s status=%s 耗时=%.1fs tokens_in=%s tokens_out=%s",
                            context.analysis_group_id, cwe, report["analysisStatus"],
                            report["elapsedSeconds"], usage.get("tokens_input"), usage.get("tokens_output"),
                        )
                    except (AgentRuntimeError, AgentReportError, PocStageError, OSError, ValueError) as exc:
                        failed = True
                        error = {"analysisGroupID": context.analysis_group_id, "cwe": cwe,
                                 "analysisStatus": "inconclusive",
                                 "elapsedSeconds": round(time.monotonic() - analysis_started, 1),
                                 "error": str(exc), "artifactDirectory": str(directory)}
                        # 报告解析/校验失败时底座开销仍然存在，一并记账便于事后核算；
                        # 底座调用本身失败时没有 response，usage 不写。
                        if "response" in locals():
                            error["usage"] = response.usage
                        write_json(directory / "error.json", error)
                        reports.append(error)
                        LOG.error("分析失败 group=%s cwe=%s reason=%s", context.analysis_group_id, cwe, exc)
                    finally:
                        _detach_run_log(run_log)
        if not args.dry_run:
            failures = sum(1 for report in reports if "error" in report)
            LOG.info(
                "运行全部结束 groups=%d 成功=%d 失败=%d 总耗时=%.1fs",
                len(reports), len(reports) - failures, failures,
                time.monotonic() - run_started,
            )
            print(json.dumps(reports[0] if len(reports) == 1 else {"analysisGroups": reports}, ensure_ascii=False, indent=2))
        return 1 if failed else 0
    except (ConfigError, AnalysisContextError, AgentReportError, OSError, ValueError) as exc:
        parser.error(str(exc))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
