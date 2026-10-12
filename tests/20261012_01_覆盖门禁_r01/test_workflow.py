import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'src'))

from agent.agent_report import AgentReportError, parse_report
from agent.analysis_context import build_contexts
from agent.artifacts import ArtifactStore
from agent.coverage import AnalysisCoverageLedger, SurfaceRecord, ledger_from_report
from agent.models import FunctionSecurityModel, PathQueryRecord
from agent.poc_stage import PocStageAdapter
from agent.plugins import Cwe78Plugin, plugin_for_cwe, supported_cwes
from agent.runtime import AgentRequest, OpenCodeRuntime, _CliRuntime


class CoverageTests(unittest.TestCase):
    def ledger(self):
        ledger = AnalysisCoverageLedger('g', ('a', 'b'))
        ledger.register_surface(SurfaceRecord('network', 'network', None, 'checked', ('ev',)))
        ledger.register_function_model(FunctionSecurityModel(
            'a', '0x100', 'sink', roles=('sink',), sink_params=(0, 1), status='confirmed', evidence_ids=('ev',)))
        return ledger

    def test_every_parameter_and_binary_must_match(self):
        ledger = self.ledger()
        ledger.record_path_query(PathQueryRecord('q1', 'a', '0x100', (0,), 'path_found', evidence_ids=('ev',)))
        ledger.record_path_query(PathQueryRecord('q2', 'b', '0x100', (1,), 'path_found', evidence_ids=('ev',)))
        self.assertFalse(ledger.finish_check()['canFinish'])
        ledger.record_path_query(PathQueryRecord('q3', 'a', '0x100', (1,), 'path_found', evidence_ids=('ev',)))
        self.assertTrue(ledger.finish_check()['canFinish'])

    def test_external_sink_address_matches_tool_result(self):
        ledger = AnalysisCoverageLedger('g', ('a',))
        ledger.register_surface(SurfaceRecord('network', 'network', None, 'checked', ('ev',)))
        ledger.register_function_model(FunctionSecurityModel(
            'a', '<EXTERNAL>::popen', 'popen', function_address='0x401380',
            roles=('sink',), sink_params=(0,), status='confirmed', evidence_ids=('ev',)))
        ledger.record_path_query(PathQueryRecord('q', 'a', '0x401380', (0,), 'path_found', evidence_ids=('ev',)))
        self.assertTrue(ledger.finish_check()['canFinish'])

    def test_empty_candidate_unknown_and_budget_cannot_finish(self):
        self.assertFalse(AnalysisCoverageLedger('g', ('a',)).finish_check()['canFinish'])
        ledger = self.ledger()
        ledger.record_path_query(PathQueryRecord('q', 'a', '0x100', (0, 1), 'unknown'))
        self.assertTrue(any('缺少原因' in x for x in ledger.finish_check()['blockers']))
        ledger.record_path_query(PathQueryRecord('q', 'a', '0x100', (0, 1), 'path_found', evidence_ids=('ev',), coverage={'budgetExhausted': True}))
        self.assertFalse(ledger.finish_check()['canFinish'])

    def test_models_roundtrip_and_distinct_binary_identity(self):
        a = FunctionSecurityModel('a', '0x100', 'sink', roles=('sink',), sink_params=(0,))
        self.assertEqual(FunctionSecurityModel.from_dict(a.to_dict()), a)
        ledger = self.ledger()
        ledger.register_function_model(FunctionSecurityModel('b', '0x100', 'sink', roles=('sink',)))
        self.assertEqual(len(ledger.sink_models), 2)
        ledger.register_function_model(FunctionSecurityModel('b', '0x100', 'source', roles=('source',)))
        self.assertEqual(len(ledger.sink_models), 1)

    def test_inconclusive_finding_is_not_function_model(self):
        report = {'findings': [{'status': 'inconclusive', 'binaryID': 'a', 'functionID': 'f'}],
                  'coverage': {}, 'unresolved': []}
        ledger = ledger_from_report(report, 'g', ('a',))
        self.assertFalse(ledger.sink_models)
        self.assertFalse(ledger.finish_check()['canFinish'])


class ReportTests(unittest.TestCase):
    def test_parse_preface_without_accepting_nested_report(self):
        report = {'findings': [], 'coverage': {}, 'unresolved': []}
        self.assertEqual(parse_report('note {}\n```json\n' + json.dumps(report) + '\n```'), report)
        with self.assertRaises(AgentReportError):
            parse_report(json.dumps({'findings': 'bad', 'nested': report}))

    def test_invalid_evidence_and_model(self):
        finding = {'status': 'candidate', 'binaryID': 'a', 'functionID': 'f', 'confidence': 'low', 'evidenceIDs': ['fake']}
        with self.assertRaises(AgentReportError):
            parse_report(json.dumps({'findings': [finding], 'coverage': {}, 'unresolved': []}))
        with self.assertRaises(AgentReportError):
            parse_report(json.dumps({'findings': [], 'unresolved': [], 'coverage': {'functionModels': [
                {'binaryID': 'a', 'functionID': 'f', 'sinkParams': [True]}]}}))

    def test_propagation_map_accepts_from_to_alias(self):
        # 真实故障：模型把 propagationMap 项的 fromParam/toFunction 写成 from/to
        # （run-87248cd335b0 报 "函数模型无效: 'fromParam'"）。解析层容忍这两个
        # 别名，但键名契约以 prompts/common/report-schema.md 为准。
        model = FunctionSecurityModel.from_dict({
            'binaryID': 'b', 'functionID': 'f',
            'propagationMap': [
                {'from': '0x401be7 popen', 'to': '0x401c6d pclose', 'toParam': None},
                {'fromParam': 'argv[1]', 'toFunction': 'popen', 'toParam': 0},
            ],
        })
        self.assertEqual(model.propagation_map[0].from_param, '0x401be7 popen')
        self.assertEqual(model.propagation_map[0].to_function, '0x401c6d pclose')
        self.assertEqual(model.propagation_map[1].from_param, 'argv[1]')
        self.assertEqual(model.propagation_map[1].to_param, 0)

    def test_final_finding_status_has_no_intermediate_state(self):
        for status in ('candidate', 'inconclusive'):
            with self.assertRaises(AgentReportError):
                parse_report(json.dumps({'findings': [{
                    'status': status, 'binaryID': 'a', 'functionID': 'f',
                    'confidence': 'low', 'evidenceIDs': ['ev'], 'limitations': [],
                }], 'coverage': {}, 'unresolved': []}))

    def test_all_supported_cwe_prompts_load(self):
        self.assertEqual(set(supported_cwes()), {'CWE-78', 'CWE-134', 'CWE-190', 'CWE-606', 'CWE-415', 'CWE-416'})
        for cwe in supported_cwes():
            self.assertIn(cwe, plugin_for_cwe(cwe).system_prompt)

    def test_poc_prompt_is_not_loaded(self):
        self.assertNotIn('CWE-78 PoC 规则', Cwe78Plugin().system_prompt)
        self.assertNotIn('"confidence": "candidate', Cwe78Plugin().system_prompt)

    def test_poc_stage_adapter_only_accepts_confirmed_findings(self):
        adapter = PocStageAdapter(ROOT / 'prompts/poc-stage.md')
        prompt = adapter.build_prompt(Path('/tmp/server'), 'CWE-78', [
            {'status': 'confirmed', 'binaryID': 'b', 'functionID': 'f', 'evidenceIDs': ['ev']}
        ], Path('/tmp/artifacts'))
        # 模板契约：只处理 confirmed、引用已有 evidenceID、生成静态审计材料、
        # 写入当前 poc/ 工作目录、保持 executed=false，不重判漏洞或重发现 source/sink。
        self.assertIn('只处理 confirmed finding', prompt)
        self.assertIn('只引用 finding 里已有的 evidenceIDs', prompt)
        self.assertIn('人工验证步骤', prompt)
        self.assertIn('/tmp/artifacts', prompt)
        self.assertIn('executed 保持 false', prompt)
        self.assertIn('不重新发现 source/sink', prompt)
        self.assertIn('不做覆盖账本判定', prompt)
        self.assertNotIn('6. PoC 生成', prompt)
        # vh 报告叙事结构（借鉴 vulnhunter 的 PoC prompt 思想）：
        # 基本信息/触发条件/输入形态(PoC 骨架)/调用路径/关键参数/证据引用/限制与不确定性。
        self.assertIn('基本信息', prompt)
        self.assertIn('触发条件', prompt)
        self.assertIn('输入形态', prompt)
        self.assertIn('调用路径', prompt)
        self.assertIn('关键参数', prompt)
        self.assertIn('证据引用', prompt)
        self.assertIn('限制与不确定性', prompt)
        # poc/ 目录只写 PoC 报告和验证脚本，脚本只生成不执行。
        self.assertIn('poc/ 目录里只写 PoC 报告和验证脚本', prompt)
        self.assertIn('<functionID>.CWE-78.py', prompt)
        self.assertIn('仅供授权环境测试', prompt)
        self.assertIn('超时和异常处理', prompt)
        self.assertIn('验证脚本只生成不执行', prompt)
        # --cwe 参数化：文件名里的 CWE 编号跟随本次运行，不能硬编码 CWE-78。
        prompt_cwe134 = adapter.build_prompt(Path('/tmp/server'), 'CWE-134', [
            {'status': 'confirmed', 'binaryID': 'b', 'functionID': 'f', 'evidenceIDs': ['ev']}
        ], Path('/tmp/artifacts'))
        self.assertIn('<functionID>.CWE-134.py', prompt_cwe134)
        self.assertIn('<functionID>.CWE-134.md', prompt_cwe134)
        with self.assertRaises(ValueError):
            adapter.build_prompt(Path('/tmp/server'), 'CWE-78', [], Path('/tmp/artifacts'))
        with self.assertRaises(ValueError):
            adapter.build_prompt(Path('/tmp/server'), 'CWE-78', [
                {'status': 'candidate', 'binaryID': 'b', 'functionID': 'f', 'evidenceIDs': ['ev']}
            ], Path('/tmp/artifacts'))

    def test_poc_prompt_runs_through_opencode_runtime(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake = Path(tmp) / 'opencode-fake'
            fake.write_text('#!/bin/sh\nprintf "poc response from opencode\\n"\n')
            fake.chmod(0o755)
            runtime = OpenCodeRuntime(executable=str(fake), timeout=5)
            response = runtime.run(AgentRequest(
                system_prompt='', user_prompt='confirmed finding poc', cwd=Path(tmp),
                model='model', provider='provider', mcp_config=None,
            ))
        self.assertEqual(response.runtime, 'opencode')
        self.assertEqual(response.text, 'poc response from opencode')
        self.assertIn('confirmed finding poc', response.command)


class ArtifactTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.context = build_contexts(ROOT / 'data/01_simple_demo/server')[0]
        self.store = ArtifactStore(Path(self.tmp.name) / 'run')
        self.store.initialize(self.context.to_dict(), self.context.root_path)
        self.report = {'findings': [], 'unresolved': [], 'coverage': {'attackSurfaces': [], 'functionModels': []}}

    def test_self_reported_query_does_not_satisfy_gate(self):
        model = FunctionSecurityModel(self.context.root['binaryID'], '0x100', 'sink', roles=('sink',),
                                      sink_params=(0,), status='confirmed', evidence_ids=('invented',))
        self.report['coverage']['functionModels'] = [model.to_dict()]
        self.report['coverage']['pathQueries'] = [{'sinkFunctionID': '0x100', 'resultStatus': 'path_found'}]
        report = self.store.finalize(self.report)
        self.assertEqual(report['analysisStatus'], 'inconclusive')
        self.assertEqual(report['coverageLedger']['pathStats']['total'], 0)
        self.assertIn('证据引用无法核验: invented', report['coverageLedger']['unresolvedItems'])
        self.assertTrue((self.store.directory / 'report.json').exists())

    def test_invalid_confirmed_finding_is_removed_to_unresolved(self):
        self.report['findings'] = [{
            'status': 'confirmed', 'binaryID': self.context.root['binaryID'],
            'functionID': 'f', 'confidence': 'high', 'evidenceIDs': ['invented'],
            'limitations': [],
        }]
        report = self.store.finalize(self.report)
        self.assertEqual(report['findings'], [])
        self.assertTrue(any('finding 未达到最终状态门槛' in item for item in report['unresolved']))

    def test_model_and_surface_hallucinated_evidence_is_stripped(self):
        # 真实故障：run-80e26d98d2d7 的函数模型/攻击面引用了一个代理从未签发的
        # evidenceID（findings 被门槛移出，但模型/攻击面上的坏引用留在报告里）。
        # 修复后坏引用从模型/攻击面剔除，只保留可核验的引用，并记 unresolved。
        raw = self.store.directory / 'raw'
        raw.mkdir(exist_ok=True)
        (raw / 'ghidra.jsonl').write_text(json.dumps({
            'evidenceID': 'ev-fake-ghidra-1', 'server': 'ghidra',
            'tool': 'decompile_function', 'arguments': {},
            'analysisGroupID': self.context.analysis_group_id,
            'binaryID': self.context.root['binaryID'],
            'elapsedSeconds': 1, 'result': {'status': 'ok'},
        }) + '\n')
        self.report['coverage']['functionModels'] = [{
            'binaryID': self.context.root['binaryID'], 'functionID': '0x100',
            'roles': ['sink'], 'sinkParams': [0], 'status': 'confirmed',
            'evidenceIDs': ['invented', 'ev-fake-ghidra-1'], 'propagationMap': [
                {'fromParam': 'a', 'toFunction': '0x200', 'toParam': 0,
                 'evidenceIDs': ['invented']},
            ],
        }]
        self.report['coverage']['attackSurfaces'] = [{
            'surfaceID': 's', 'category': 'network', 'functionID': '0x100',
            'status': 'checked', 'evidenceIDs': ['invented'],
        }]
        report = self.store.finalize(self.report)
        self.assertEqual(
            report['coverage']['functionModels'][0]['evidenceIDs'], ['ev-fake-ghidra-1']
        )
        # 坏引用在 propagationMap 条目内：整个条目被剔除。
        self.assertEqual(
            report['coverage']['functionModels'][0]['propagationMap'], []
        )
        self.assertEqual(
            report['coverage']['attackSurfaces'][0]['evidenceIDs'], []
        )
        self.assertTrue(any('证据引用无法核验: invented' in item for item in report['unresolved']))
        self.assertTrue(any('传播关系证据引用无法核验: invented' in item for item in report['unresolved']))

    def test_resume_checks_group_and_preserves_original(self):
        self.store.finalize(self.report)
        text = self.store.resume_context(self.context.to_dict())
        self.assertLess(len(text.encode()), 32769)
        changed = copy.deepcopy(self.context.to_dict())
        changed['root']['binaryID'] = 'different'
        with self.assertRaises(ValueError):
            self.store.resume_context(changed)

    def test_interrupted_run_can_resume_and_corruption_is_not_silent(self):
        self.assertTrue(json.loads(self.store.resume_context(self.context.to_dict()))['interrupted'])
        raw = self.store.directory / 'raw'
        raw.mkdir()
        (raw / 'paths.jsonl').write_text('{incomplete')
        with self.assertRaises(ValueError):
            self.store.records()

    def test_proxy_records_actual_tool_response(self):
        server = Path(self.tmp.name) / 'fake_mcp.py'
        server.write_text('import sys,json\nfor line in sys.stdin:\n r=json.loads(line)\n print(json.dumps({"jsonrpc":"2.0","id":r["id"],"result":{"content":[{"type":"text","text":"observed"}]}}),flush=True)\n')
        command = [sys.executable, '-m', 'agent.evidence_proxy', '--directory', str(self.store.directory),
                   '--server', 'ghidra', '--group-id', self.context.analysis_group_id,
                   '--binary-id', self.context.root['binaryID'], '--', sys.executable, str(server)]
        import os
        result = subprocess.run(command, input=json.dumps({'id': 1, 'method': 'tools/call', 'params': {'name': 'inspect', 'arguments': {}}})+'\n',
                                text=True, capture_output=True, env={**os.environ, 'PYTHONPATH': str(ROOT / 'src')}, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        response = json.loads(result.stdout)
        records = self.store.records()
        self.assertEqual(len(records), 1)
        self.assertIn(records[0]['evidenceID'], response['result']['content'][-1]['text'])
        self.assertEqual(records[0]['result']['content'][0]['text'], 'observed')


class _ProbeRuntime(_CliRuntime):
    """把命令收敛成打印 PWD 的探针脚本，用来验证环境修复。"""

    def build_command(self, request: AgentRequest) -> tuple[str, ...]:
        return (self.executable,)


class RuntimeEnvTests(unittest.TestCase):
    def test_stale_pwd_is_fixed_to_actual_cwd(self):
        """调用方 shell 可能携带过期的 PWD；opencode 等项目发现依赖它。"""
        with tempfile.TemporaryDirectory() as tmp:
            workdir = Path(tmp) / 'sub'
            workdir.mkdir()
            probe = Path(tmp) / 'probe.sh'
            probe.write_text('#!/bin/sh\nprintf "PWD=$PWD\\n"\n')
            probe.chmod(0o755)
            runtime = _ProbeRuntime(executable=str(probe), timeout=5)
            response = runtime.run(AgentRequest(
                system_prompt='', user_prompt='', cwd=workdir,
                model=None, provider=None, mcp_config=None,
                environment={'PWD': '/stale/pwd'},
            ))
        self.assertIn(f'PWD={workdir.resolve()}', response.text)


if __name__ == '__main__':
    unittest.main()
