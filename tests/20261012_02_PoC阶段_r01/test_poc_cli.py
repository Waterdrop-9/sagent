"""PoC 阶段端到端测试：用 fake opencode 驱动真实 cli.py 全链路。

覆盖 handoff 检查项 2-4：cli.py 只从最终 findings 筛 confirmed；PoC 请求
cwd 是 <run>/poc/；request/response/manifest 在 run 目录顶层独立保存，
poc/ 目录里只有模型生成的 PoC 报告。测试不执行样本。
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

EXPECTED_GROUP = "group-6aeb5375a9c368ad"
BINARY_ID = "df9980a8c721e7098b09420b1ae9d0152023cf429281aab2d8b3335a7dad07f3"


def run_cli(
    output: Path,
    config: Path,
    mode: str | None = None,
    cwe: str | None = "CWE-78",
    workers: int = 1,
    resume: Path | None = None,
    force: bool = False,
    confirmation: str = "recall",
) -> subprocess.CompletedProcess:
    """以 fake opencode 作为 PATH 中的 opencode 运行真实 CLI。

    cwe 为 None 时不传 --cwe，用于验证默认跑全部支持 CWE 的行为。
    resume 非 None 时传 --resume（断点续跑）。
    """
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT / "src")
    env.pop("AGENT_PATH_BACKEND_PYTHON", None)
    fake_bin = Path(tempfile.mkdtemp(prefix="fake-bin-"))
    wrapper = fake_bin / "opencode"
    wrapper.write_text(
        f"#!/bin/sh\nexec {sys.executable} '{ROOT / 'tests/20261012_02_PoC阶段_r01/fake_opencode.py'}' \"$@\"\n"
    )
    wrapper.chmod(0o755)
    env["PATH"] = f"{fake_bin}{os.pathsep}{env.get('PATH', '')}"
    if mode:
        env["FAKE_OPENCODE_MODE"] = mode
    command = [
        sys.executable, "-m", "agent.cli",
        "--config", str(config),
        "--target", str(ROOT / "data/01_simple_demo/server"),
        "--dependency-root", str(ROOT / "data/01_simple_demo"),
        "--goal", "验证 PoC 阶段端到端流程",
    ]
    if cwe is not None:
        command += ["--cwe", cwe]
    command += ["--poc", "--output", str(output)]
    if resume is not None:
        command += ["--resume", str(resume)]
    if force:
        command += ["--force"]
    if workers != 1:
        command += ["--workers", str(workers)]
    command += ["--confirmation", confirmation]
    return subprocess.run(
        command, cwd=ROOT, env=env, text=True, capture_output=True, timeout=300
    )


class PocCliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.output = base / "out"
        self.config = base / "config.toml"
        self.config.write_text(
            f"""[agent]
runtime = "opencode"
provider = "deepseek"
model = "deepseek-flash"
api_key = "test-key"
base_url = "https://example.invalid/v1"
timeout = 300

[poc]
enabled = false
prompt_file = "{ROOT / 'prompts/poc-stage.md'}"
""",
            encoding="utf-8",
        )

    def run_dir(self) -> Path:
        runs = list((self.output / EXPECTED_GROUP).glob("run-*"))
        self.assertEqual(len(runs), 1, f"应有且仅有一个运行目录: {[p.name for p in runs]}")
        return runs[0]

    def test_confirmed_finding_triggers_poc_with_poc_cwd(self):
        result = run_cli(self.output, self.config)
        self.assertEqual(result.returncode, 0, result.stderr)
        run = self.run_dir()
        self.assertFalse((run / "error.json").exists())
        report = json.loads((run / "report.json").read_text())
        self.assertEqual(report["poc"]["status"], "generated")
        self.assertEqual(report["poc"]["findingCount"], 1)
        self.assertEqual(report["findings"][0]["status"], "confirmed")
        # 多二进制组自带 unresolved 项，覆盖门禁应判 inconclusive 而不是失败。
        self.assertEqual(report["analysisStatus"], "inconclusive")
        self.assertTrue(any("本地依赖及跨组件路径尚未覆盖" in item for item in report["unresolved"]))
        # 工具记录与模型原文都落盘。
        self.assertTrue((run / "raw" / "agent.txt").exists())
        self.assertTrue((run / "raw" / "ghidra.jsonl").exists())
        self.assertTrue((run / "raw" / "paths.jsonl").exists())
        # request/response/manifest 账目在 run 目录顶层，poc/ 里只有 PoC 报告。
        poc = run / "poc"
        request = (run / "poc-request.md").read_text(encoding="utf-8")
        self.assertIn('"status": "confirmed"', request)
        self.assertIn("ev-fake-paths-1", request)
        self.assertIn("doSystem", request)
        response = (run / "poc-response.md").read_text(encoding="utf-8")
        self.assertIn("poc response from fake opencode", response)
        # PoC 请求的工作目录必须是 <run>/poc/，而不是仓库根或运行目录。
        self.assertIn(f"cwd={poc.resolve()}", response)
        manifest = json.loads((run / "poc-manifest.json").read_text())
        self.assertEqual(manifest, {
            "stage": "poc",
            "runtime": "opencode",
            "findingCount": 1,
            "findingIDs": [f"{BINARY_ID}/doSystem"],
            "request": "poc-request.md",
            "response": "poc-response.md",
            "usage": None,
            "files": ["doSystem.CWE-78.md", "doSystem.CWE-78.py"],
            "executed": False,
        })
        # 开销观测字段恒存在：fake 底座没有会话库，usage 为 None。
        self.assertIsInstance(report["elapsedSeconds"], (int, float))
        self.assertIsNone(report["usage"])
        self.assertTrue((run / "analysis.log").exists())
        self.assertIn("运行全部结束", result.stderr)
        # 日志信息密度：进度前缀 [1/1]、工具证据计数、MCP 服务器清单、结论行。
        self.assertIn("[1/1]", result.stderr)
        self.assertIn("工具证据 ghidra=2 paths=1", result.stderr)
        self.assertIn("mcp_servers=", result.stderr)
        self.assertIn("findings=1 confirmed=1 rejected=0 unresolved=1 poc_status=generated poc_files=2", result.stderr)
        # poc/ 目录干净：只有模型生成的 PoC 报告和验证脚本，没有账目文件。
        self.assertEqual(
            {path.name for path in poc.iterdir()},
            {"doSystem.CWE-78.md", "doSystem.CWE-78.py"},
        )

    def test_invalid_report_writes_error_ledger_with_usage(self):
        # 底座输出不含报告 JSON 时：error.json 记账（含 elapsedSeconds/usage），
        # 返回码非 0，日志里有明确失败原因（可 grep 监视）。
        result = run_cli(self.output, self.config, mode="invalid")
        self.assertEqual(result.returncode, 1, result.stderr)
        run = self.run_dir()
        error = json.loads((run / "error.json").read_text(encoding="utf-8"))
        self.assertEqual(error["analysisStatus"], "inconclusive")
        self.assertEqual(error["cwe"], "CWE-78")
        self.assertIn("没有有效 JSON 报告", error["error"])
        self.assertIsInstance(error["elapsedSeconds"], (int, float))
        self.assertIsNone(error["usage"])
        self.assertIn("分析失败", result.stderr)
        self.assertTrue((run / "analysis.log").exists())

    def test_no_confirmed_finding_skips_poc(self):
        result = run_cli(self.output, self.config, mode="skip")
        self.assertEqual(result.returncode, 0, result.stderr)
        run = self.run_dir()
        report = json.loads((run / "report.json").read_text())
        self.assertEqual(report["poc"], {
            "status": "skipped_no_confirmed_findings",
            "findingCount": 0,
            "files": [],
        })
        self.assertEqual(report["findings"][0]["status"], "rejected")
        self.assertFalse((run / "poc").exists())
        self.assertFalse((run / "poc-request.md").exists())
        self.assertFalse((run / "poc-manifest.json").exists())
        self.assertIn('"status": "skipped_no_confirmed_findings"', result.stdout)


class CweDefaultTests(unittest.TestCase):
    """--cwe 缺省时依次运行全部支持的 CWE，每个 CWE 一个独立 run 目录。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.output = base / "out"
        self.config = base / "config.toml"
        self.config.write_text(
            f"""[agent]
runtime = "opencode"
provider = "deepseek"
model = "deepseek-flash"
api_key = "test-key"
base_url = "https://example.invalid/v1"
timeout = 300

[poc]
enabled = false
prompt_file = "{ROOT / 'prompts/poc-stage.md'}"
""",
            encoding="utf-8",
        )

    def test_default_runs_all_supported_cwes(self):
        from agent.plugins import supported_cwes

        expected = supported_cwes()
        result = run_cli(self.output, self.config, mode="skip", cwe=None)
        self.assertEqual(result.returncode, 0, result.stderr)
        runs = sorted((self.output / EXPECTED_GROUP).glob("run-*"))
        self.assertEqual(len(runs), len(expected))
        seen = []
        for run in runs:
            report = json.loads((run / "report.json").read_text(encoding="utf-8"))
            self.assertIn(report["cwe"], expected)
            seen.append(report["cwe"])
            # skip 模式下没有 confirmed finding，PoC 应跳过而不是报错。
            self.assertEqual(report["poc"], {
                "status": "skipped_no_confirmed_findings",
                "findingCount": 0,
                "files": [],
            })
        self.assertEqual(sorted(seen), sorted(expected))

    def test_workers_pool_runs_all_supported_cwes(self):
        """--workers>1 走进程池：每个 (分析组,CWE) 任务独立子进程，产物与串行一致。"""
        from agent.plugins import supported_cwes

        expected = supported_cwes()
        result = run_cli(self.output, self.config, mode="skip", cwe=None, workers=2)
        self.assertEqual(result.returncode, 0, result.stderr)
        runs = sorted((self.output / EXPECTED_GROUP).glob("run-*"))
        self.assertEqual(len(runs), len(expected))
        seen = []
        for run in runs:
            report = json.loads((run / "report.json").read_text(encoding="utf-8"))
            self.assertIn(report["cwe"], expected)
            seen.append(report["cwe"])
            self.assertEqual(report["poc"]["status"], "skipped_no_confirmed_findings")
            self.assertTrue((run / "analysis.log").exists())
        self.assertEqual(sorted(seen), sorted(expected))
        # 每个任务日志都带自己的进度前缀。
        self.assertIn("运行全部结束", result.stderr)


class StartupRetryTests(unittest.TestCase):
    """standalone 会话启动竞态的退避重试：第一次失败后自动重试并成功。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.output = base / "out"
        self.config = base / "config.toml"
        self.config.write_text(
            f"""[agent]
runtime = "opencode"
provider = "deepseek"
model = "deepseek-flash"
api_key = "test-key"
base_url = "https://example.invalid/v1"
timeout = 300

[poc]
enabled = false
prompt_file = "{ROOT / 'prompts/poc-stage.md'}"
""",
            encoding="utf-8",
        )

    def test_startup_race_is_retried(self):
        # 真实故障：两个 `opencode run --standalone` 几乎同时启动时，第二个
        # 报 "Standalone server exited before reporting readiness" 退出码 1。
        # fake 底座第一次打印该错误返回 1，第二次正常输出报告。
        result = run_cli(self.output, self.config, mode="flaky-server")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("底座会话启动竞态", result.stderr)
        runs = list((self.output / EXPECTED_GROUP).glob("run-*"))
        self.assertEqual(len(runs), 1)
        report = json.loads(
            (runs[0] / "report.json").read_text(encoding="utf-8")
        )
        self.assertEqual(report["cwe"], "CWE-78")
        self.assertEqual(
            report["findings"][0]["status"], "confirmed"
        )

    def test_malformed_report_is_retried_once(self):
        # 真实故障：模型在 JSON 字符串里夹未转义引号（run-4560cc488c0c 的
        # CWE-606 报告解码失败）。fake 底座第一次输出坏 JSON，第二次输出
        # 有效报告——报告级重试应把本轮救回来。
        result = run_cli(self.output, self.config, mode="bad-json-once")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("报告无效", result.stderr)
        runs = list((self.output / EXPECTED_GROUP).glob("run-*"))
        self.assertEqual(len(runs), 1)
        report = json.loads(
            (runs[0] / "report.json").read_text(encoding="utf-8")
        )
        self.assertEqual(report["findings"][0]["status"], "confirmed")


class RuntimeEnvTests(unittest.TestCase):
    """运行时环境修复的回归测试：过期的 PWD 必须被修正为实际 cwd。"""

    def test_stale_pwd_is_fixed_to_actual_cwd(self):
        # 真实故障：shell 的 PWD 指向仓库根，opencode 用它做项目发现，
        # 读不到 cwd/.opencode/opencode.json，报 "Model unavailable"。
        from agent.runtime import AgentRequest, _CliRuntime

        class _ProbeRuntime(_CliRuntime):
            def build_command(self, request: AgentRequest) -> tuple:
                return (self.executable,)

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        workdir = Path(tmp.name) / "sub"
        workdir.mkdir()
        probe = Path(tmp.name) / "probe.sh"
        probe.write_text('#!/bin/sh\necho "PWD=$PWD"\n')
        probe.chmod(0o755)
        response = _ProbeRuntime(str(probe), timeout=60).run(AgentRequest(
            system_prompt="",
            user_prompt="",
            cwd=workdir,
            environment={"PWD": "/stale/directory"},
        ))
        self.assertEqual(response.text.strip(), f"PWD={workdir.resolve()}")


class ResumeTests(unittest.TestCase):
    """断点续跑：--resume 原地续跑，按阶段跳过已完成部分，不重复调用 Agent。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.output = base / "out"
        self.config = base / "config.toml"
        self.config.write_text(
            f"""[agent]
runtime = "opencode"
provider = "deepseek"
model = "deepseek-flash"
api_key = "test-key"
base_url = "https://example.invalid/v1"
timeout = 300

[poc]
enabled = false
prompt_file = "{ROOT / 'prompts/poc-stage.md'}"
""",
            encoding="utf-8",
        )

    def _first_run(self) -> tuple[Path, subprocess.CompletedProcess]:
        """跑一次 confirmed 模式，返回 (run 目录, 结果)。"""
        result = run_cli(self.output, self.config)
        self.assertEqual(result.returncode, 0, result.stderr)
        runs = list((self.output / EXPECTED_GROUP).glob("run-*"))
        self.assertEqual(len(runs), 1)
        return runs[0], result

    def test_resume_with_report_json_skips_agent_and_poc(self):
        run, _ = self._first_run()
        self.assertTrue((run / "report.json").exists())
        self.assertTrue((run / "poc-manifest.json").exists())
        result = run_cli(self.output, self.config, resume=run)
        self.assertEqual(result.returncode, 0, result.stderr)
        # 分析阶段复用归档报告：不再调用底座，也就没有工具证据计数。
        self.assertIn("断点续跑：复用已有 report.json，跳过分析阶段", result.stderr)
        self.assertIn("断点续跑：PoC 阶段已有产物，跳过", result.stderr)
        self.assertNotIn("工具证据", result.stderr)
        self.assertIn("分析结束（复用）", result.stderr)
        # PoC 交付物与账目保持不变。
        report = json.loads((run / "report.json").read_text(encoding="utf-8"))
        self.assertEqual(report["poc"]["status"], "generated")
        self.assertEqual(
            {path.name for path in (run / "poc").iterdir()},
            {"doSystem.CWE-78.md", "doSystem.CWE-78.py"},
        )
        manifest = json.loads((run / "poc-manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["stage"], "poc")
        self.assertEqual(manifest["files"], ["doSystem.CWE-78.md", "doSystem.CWE-78.py"])

    def test_resume_without_report_json_refinalizes_agent_output(self):
        run, _ = self._first_run()
        (run / "report.json").unlink()
        result = run_cli(self.output, self.config, resume=run)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("直接重新 finalize（不重复调用 Agent）", result.stderr)
        self.assertNotIn("工具证据", result.stderr)
        report = json.loads((run / "report.json").read_text(encoding="utf-8"))
        # 重新 finalize 走证据门禁，报告结论应与首次一致（fake 证据齐全）。
        self.assertEqual(report["findings"][0]["status"], "confirmed")
        self.assertEqual(report["cwe"], "CWE-78")
        # PoC 产物还在：跳过 PoC 阶段，不重复生成。
        self.assertIn("断点续跑：PoC 阶段已有产物，跳过", result.stderr)
        self.assertTrue((run / "poc" / "doSystem.CWE-78.md").exists())

    def test_batch_rerun_skips_completed_checkpoint(self):
        run, _ = self._first_run()
        checkpoint = self.output / EXPECTED_GROUP / "completed-CWE-78.json"
        self.assertTrue(checkpoint.exists())
        # 同一 --output 与 goal 重跑：任务级断点命中，直接复用归档报告。
        result = run_cli(self.output, self.config)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("断点续跑：跳过已完成任务", result.stderr)
        self.assertIn("复用=1", result.stderr)
        # 没有新增 run 目录，旧产物原样保留。
        runs = list((self.output / EXPECTED_GROUP).glob("run-*"))
        self.assertEqual([path.resolve() for path in runs], [run.resolve()])
        self.assertIn('"status": "generated"', result.stdout)

    def test_force_reruns_resumed_task(self):
        run, _ = self._first_run()
        result = run_cli(self.output, self.config, resume=run, force=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        # --force 忽略断点：重新调用 Agent（工具证据计数再次出现）。
        self.assertIn("工具证据", result.stderr)
        self.assertNotIn("复用已有 report.json", result.stderr)
        report = json.loads((run / "report.json").read_text(encoding="utf-8"))
        self.assertEqual(report["findings"][0]["status"], "confirmed")


class ConfirmationPolicyTests(unittest.TestCase):
    """确认标准：recall 接受引用链级 confirmed，precision 运行时降级为 unresolved。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.output = base / "out"
        self.config = base / "config.toml"
        self.config.write_text(
            f"""[agent]
runtime = "opencode"
provider = "deepseek"
model = "deepseek-flash"
api_key = "test-key"
base_url = "https://example.invalid/v1"
timeout = 300

[poc]
enabled = false
prompt_file = "{ROOT / 'prompts/poc-stage.md'}"
""",
            encoding="utf-8",
        )

    def _report(self, output: Path) -> dict:
        runs = list((output / EXPECTED_GROUP).glob("run-*"))
        self.assertEqual(len(runs), 1)
        return json.loads((runs[0] / "report.json").read_text(encoding="utf-8"))

    def test_recall_default_confirms_reference_chain_finding(self):
        result = run_cli(self.output, self.config, mode="recall-basis", confirmation="recall")
        self.assertEqual(result.returncode, 0, result.stderr)
        report = self._report(self.output)
        self.assertEqual(report["confirmationMode"], "recall")
        self.assertEqual(len(report["findings"]), 1)
        self.assertEqual(report["findings"][0]["status"], "confirmed")
        self.assertEqual(report["findings"][0]["confirmationBasis"], "reference-chain")

    def test_precision_downgrades_reference_chain_finding(self):
        result = run_cli(self.output, self.config, mode="recall-basis", confirmation="precision")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("precision 确认标准：1 条引用链级 finding 降级为 unresolved", result.stderr)
        report = self._report(self.output)
        self.assertEqual(report["confirmationMode"], "precision")
        self.assertEqual(report["findings"], [])
        self.assertTrue(
            any("precision 确认标准拒绝引用链级确认" in item for item in report["unresolved"])
        )

    def test_precision_keeps_taint_path_finding(self):
        result = run_cli(self.output, self.config, confirmation="precision")
        self.assertEqual(result.returncode, 0, result.stderr)
        report = self._report(self.output)
        self.assertEqual(report["confirmationMode"], "precision")
        self.assertEqual(len(report["findings"]), 1)
        self.assertEqual(report["findings"][0]["status"], "confirmed")


class RiskChainsCliTests(unittest.TestCase):
    """阶段 M 编排：每个 run 目录先物化候选链再调用 Agent（执行者分层）。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.output = base / "out"
        self.config = base / "config.toml"
        self.config.write_text(
            f"""[agent]
runtime = "opencode"
provider = "deepseek"
model = "deepseek-flash"
api_key = "test-key"
base_url = "https://example.invalid/v1"
timeout = 300

[poc]
enabled = false
prompt_file = "{ROOT / 'prompts/poc-stage.md'}"
""",
            encoding="utf-8",
        )

    def test_run_dir_materializes_candidate_chains_before_agent(self):
        result = run_cli(self.output, self.config)
        self.assertEqual(result.returncode, 0, result.stderr)
        runs = list((self.output / EXPECTED_GROUP).glob("run-*"))
        self.assertEqual(len(runs), 1)
        doc = json.loads((runs[0] / "risk-chains.json").read_text(encoding="utf-8"))
        self.assertEqual(doc["phase"], "M")
        self.assertEqual(doc["cwe"], "CWE-78")
        # 无 angr 环境退化为导入表/PLT 链：libauth 的 system 导入必然产生候选。
        chains = doc["chains"]
        self.assertTrue(chains, "阶段 M 应至少物化一条候选链")
        self.assertTrue(
            any(
                chain["sink"]["binary"] == "libauth.so" and chain["sink"]["symbol"] == "system"
                for chain in chains
            ),
            f"缺少 libauth system 候选链: {[c['sink'] for c in chains]}",
        )
        self.assertIn("候选链物化 chains=", result.stderr)


if __name__ == "__main__":
    unittest.main()
