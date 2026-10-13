import copy
import json
import os
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

    def test_wrapper_sink_accepts_query_on_underlying_callee(self):
        # 真实场景（run-6950c30b7959）：confirmed sink 模型是 wrapper
        # doSystem@0x401ba2，模型查询的是它实际调用的 popen@0x401380；
        # 查询结果 paths[].callerFunctionID 正是 wrapper 的 functionID，
        # 证据链同样覆盖了该参数，不应报"尚未查询参数 0"。
        ledger = AnalysisCoverageLedger('g', ('a',))
        ledger.register_surface(SurfaceRecord('network', 'network', None, 'checked', ('ev',)))
        ledger.register_function_model(FunctionSecurityModel(
            'a', '0x401ba2', 'doSystem', function_address='0x401ba2',
            roles=('sink',), sink_params=(0,), status='confirmed', evidence_ids=('ev',)))
        ledger.record_path_query(PathQueryRecord(
            'q', 'a', '0x401380', (0,), 'path_found',
            evidence_ids=('ev',), callers=('0x401ba2',)))
        self.assertTrue(ledger.finish_check()['canFinish'])

    def test_wrapper_sink_still_blocked_without_caller_match(self):
        # 查询的路径里 caller 不是 wrapper 时不能冒充覆盖：依然要报未查询。
        ledger = AnalysisCoverageLedger('g', ('a',))
        ledger.register_surface(SurfaceRecord('network', 'network', None, 'checked', ('ev',)))
        ledger.register_function_model(FunctionSecurityModel(
            'a', '0x401ba2', 'doSystem', function_address='0x401ba2',
            roles=('sink',), sink_params=(0,), status='confirmed', evidence_ids=('ev',)))
        ledger.record_path_query(PathQueryRecord(
            'q', 'a', '0x401380', (0,), 'path_found',
            evidence_ids=('ev',), callers=('0x402000',)))
        blockers = ledger.finish_check()['blockers']
        self.assertTrue(any('尚未查询参数 0' in b for b in blockers), blockers)

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

    def test_params_accept_dict_form_with_param_index(self):
        # 真实故障：CWE-606 夹具运行（run-cf00f1168783）连续两次报告无效
        # "函数模型无效: 参数编号必须是非负整数"——模型把 sourceParams/sinkParams
        # 写成带 api/paramIndex/note 的对象数组。能取出非负 paramIndex 就按编号收起，
        # 取不出的对象与负编号仍然拒绝。
        report = {'findings': [], 'unresolved': [], 'coverage': {'functionModels': [
            {'binaryID': 'a', 'functionID': 'f', 'propagationMap': [],
             'sourceParams': [{'api': 'recv', 'paramIndex': 1, 'note': 'x'}],
             'sinkParams': [2]}]}}
        parse_report(json.dumps(report))
        model = FunctionSecurityModel.from_dict(report['coverage']['functionModels'][0])
        self.assertEqual(model.source_params, (1,))
        self.assertEqual(model.sink_params, (2,))
        for bad in ([{'api': 'recv'}], [{'paramIndex': -1}], 'not-a-list'):
            with self.assertRaises(AgentReportError):
                parse_report(json.dumps({'findings': [], 'unresolved': [], 'coverage': {
                    'functionModels': [
                        {'binaryID': 'a', 'functionID': 'f', 'propagationMap': [],
                         'sourceParams': bad}]}}))

    def test_final_finding_status_has_no_intermediate_state(self):
        for status in ('candidate', 'inconclusive'):
            with self.assertRaises(AgentReportError):
                parse_report(json.dumps({'findings': [{
                    'status': status, 'binaryID': 'a', 'functionID': 'f',
                    'confidence': 'low', 'evidenceIDs': ['ev'], 'limitations': [],
                }], 'coverage': {}, 'unresolved': []}))

    def test_confirmation_basis_is_validated(self):
        finding = {'status': 'confirmed', 'binaryID': 'a', 'functionID': 'f',
                   'confidence': 'high', 'evidenceIDs': ['ev'], 'limitations': []}
        for basis in ('taint-path', 'reference-chain', None):
            report = copy.deepcopy({'findings': [finding], 'coverage': {}, 'unresolved': []})
            if basis is not None:
                report['findings'][0]['confirmationBasis'] = basis
            self.assertEqual(parse_report(json.dumps(report))['findings'][0].get('confirmationBasis'), basis)
        report = copy.deepcopy({'findings': [finding], 'coverage': {}, 'unresolved': []})
        report['findings'][0]['confirmationBasis'] = 'guess'
        with self.assertRaises(AgentReportError):
            parse_report(json.dumps(report))

    def test_confirmation_policy_gate_by_mode(self):
        from agent.agent_report import apply_confirmation_policy
        report = {'findings': [{
            'status': 'confirmed', 'binaryID': 'a', 'functionID': 'doSystem',
            'confidence': 'high', 'evidenceIDs': ['ev'],
            'confirmationBasis': 'reference-chain', 'limitations': [],
        }], 'coverage': {}, 'unresolved': []}
        recall = copy.deepcopy(report)
        self.assertEqual(apply_confirmation_policy(recall, 'recall'), 0)
        self.assertEqual(len(recall['findings']), 1)
        precision = copy.deepcopy(report)
        self.assertEqual(apply_confirmation_policy(precision, 'precision'), 1)
        self.assertEqual(precision['findings'], [])
        self.assertTrue(any('precision 确认标准拒绝引用链级确认' in item for item in precision['unresolved']))

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

    def test_build_command_drops_standalone_for_old_opencode(self):
        # opencode 1.15.x 没有 `run --standalone`（实测传入直接打帮助退出）；
        # 2.x 有。命令按 help 输出自适应。
        with tempfile.TemporaryDirectory() as tmp:
            fake = Path(tmp) / 'opencode-fake'
            fake.write_text('#!/bin/sh\nprintf -- "--model some help text\\n"\n')
            fake.chmod(0o755)
            runtime = OpenCodeRuntime(executable=str(fake), timeout=5)
            request = AgentRequest(
                system_prompt='sys', user_prompt='task', cwd=Path(tmp),
                model='deepseek-flash', provider='deepseek', mcp_config=None,
            )
            old_cmd = runtime.build_command(request)
            self.assertNotIn('--standalone', old_cmd)

            fake.write_text('#!/bin/sh\nprintf -- "--standalone private server\\n"\n')
            fake.chmod(0o755)
            new_runtime = OpenCodeRuntime(executable=str(fake), timeout=5)
            new_cmd = new_runtime.build_command(request)
            self.assertIn('--standalone', new_cmd)
            self.assertIn('--model', new_cmd)
            self.assertIn('deepseek/deepseek-flash', new_cmd)


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

    def test_cross_binary_evidence_attributed_to_root_binary_is_kept(self):
        # 真实故障：run-656dc86af251（recall 验证）里模型把 auth_log 链归属 libauth，
        # 但 Ghidra 会话只加载 root binary，所有工具记录的 binaryID=server；
        # 旧的 binaryID 强相等核验把 6 条真实证据判为"无法核验"，且 invalid_references
        # 全局连坐，把 server 侧的 doSystem 链（共享 get_program_info/list_imports
        # 证据）一并踢出。修复后核验只看 evidenceID 是否真实可查。
        manifest_path = self.store.directory / 'manifest.json'
        manifest = json.loads(manifest_path.read_text())
        component_id = 'c' * 64
        manifest['analysisGroup']['components'].append({
            'binaryID': component_id, 'path': 'libauth.so',
        })
        manifest_path.write_text(json.dumps(manifest))
        raw = self.store.directory / 'raw'
        raw.mkdir(exist_ok=True)
        (raw / 'ghidra.jsonl').write_text(json.dumps({
            'evidenceID': 'ev-root-1', 'server': 'ghidra',
            'tool': 'get_program_info', 'arguments': {},
            'analysisGroupID': self.context.analysis_group_id,
            'binaryID': self.context.root['binaryID'],
            'elapsedSeconds': 1, 'result': {'status': 'ok'},
        }) + '\n')
        self.report['findings'] = [
            {
                'status': 'confirmed', 'binaryID': component_id,
                'functionID': '0x1459', 'confidence': 'high',
                'evidenceIDs': ['ev-root-1'], 'limitations': [],
            },
            {
                'status': 'confirmed', 'binaryID': self.context.root['binaryID'],
                'functionID': '0x401ba2', 'confidence': 'high',
                'evidenceIDs': ['ev-root-1'], 'limitations': [],
            },
        ]
        report = self.store.finalize(self.report)
        self.assertEqual(
            [(f['binaryID'], f['functionID']) for f in report['findings']],
            [(component_id, '0x1459'), (self.context.root['binaryID'], '0x401ba2')],
        )
        self.assertFalse(any('证据引用无法核验' in item for item in report['unresolved']))

    def test_component_ghidra_journal_is_loaded_and_cited(self):
        # 任务 D（多二进制 Ghidra）：组件的独立会话写 raw/ghidra-<prefix>.jsonl，
        # records() 必须把后缀日志一并读入，finalize 才能核验组件证据。
        manifest_path = self.store.directory / 'manifest.json'
        manifest = json.loads(manifest_path.read_text())
        component_id = 'c' * 64
        manifest['analysisGroup']['components'].append({
            'binaryID': component_id, 'path': 'libauth.so',
        })
        manifest_path.write_text(json.dumps(manifest))
        raw = self.store.directory / 'raw'
        raw.mkdir(exist_ok=True)
        (raw / f'ghidra-{component_id[:8]}.jsonl').write_text(json.dumps({
            'evidenceID': 'ev-comp-1', 'server': f'ghidra-{component_id[:8]}',
            'tool': 'decompile_function', 'arguments': {},
            'analysisGroupID': self.context.analysis_group_id,
            'binaryID': component_id,
            'elapsedSeconds': 1, 'result': {'status': 'ok'},
        }) + '\n')
        self.report['findings'] = [{
            'status': 'confirmed', 'binaryID': component_id,
            'functionID': '0x1459', 'confidence': 'high',
            'evidenceIDs': ['ev-comp-1'], 'limitations': [],
        }]
        report = self.store.finalize(self.report)
        self.assertEqual(
            [(f['binaryID'], f['functionID']) for f in report['findings']],
            [(component_id, '0x1459')],
        )
        self.assertFalse(any('证据引用无法核验' in item for item in report['unresolved']))

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


class PluginMcpTests(unittest.TestCase):
    """多二进制 Ghidra 会话（任务 D）：mcp 配置形状与证据代理的 binary-id 映射。"""

    @staticmethod
    def _ghidra_config(command=None):
        from agent.config import GhidraMcpConfig
        return GhidraMcpConfig(
            mode='headless', server='http://127.0.0.1:8080', uvx='uvx',
            python='/usr/bin/python3', package='ghidra_mcp', command=command,
            ready_timeout=120,
            install_dir=Path('/opt/ghidra'), extension_jar=Path('/tmp/GhidraMCP.jar'),
        )

    def test_mcp_config_emits_per_component_ghidra_sessions(self):
        plugin = Cwe78Plugin()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'server'
            root.write_bytes(b'')
            libauth = Path(tmp) / 'libauth.so'
            libauth.write_bytes(b'')
            config = plugin.mcp_config(
                root, ROOT / 'src', ghidra=self._ghidra_config(),
                artifact_dir=Path(tmp) / 'artifacts',
                analysis_group_id='group-x', binary_id='a' * 64,
                ghidra_sessions=(('b' * 64, libauth),),
            )
        servers = config['opencode']['mcp']['servers']
        self.assertEqual(set(servers), {'ghidra', 'ghidra-' + 'b' * 8})
        root_command = servers['ghidra']['command']
        comp_command = servers['ghidra-' + 'b' * 8]['command']
        # 根会话：--binary 指向 root、证据代理 --binary-id 用根 ID
        self.assertIn(str(root.resolve()), root_command)
        self.assertIn('a' * 64, root_command)
        self.assertNotIn('b' * 64, root_command)
        # 组件会话：--binary 指向组件路径、证据代理 --binary-id 用组件 ID
        self.assertIn(str(libauth.resolve()), comp_command)
        self.assertIn('b' * 64, comp_command)
        self.assertNotIn('a' * 64, comp_command)
        # 两会话共用同一 run 目录与 analysis group
        for command in (root_command, comp_command):
            self.assertIn('--group-id', command)
            self.assertIn('group-x', command)

    def test_mcp_config_direct_command_overrides_uvx(self):
        # 容器等无 uvx/网络的部署：GHIDRA_MCP_COMMAND 直接给出启动命令，
        # 不再走 uvx --from 拉包路径。
        plugin = Cwe78Plugin()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'server'
            root.write_bytes(b'')
            config = plugin.mcp_config(
                root, ROOT / 'src',
                ghidra=self._ghidra_config(
                    command='/opt/sagent-venv/bin/python -m ghidra_mcp.cli'),
                binary_id='a' * 64,
            )
        servers = config['opencode']['mcp']['servers']
        command = servers['ghidra']['command']
        self.assertEqual(
            command[:4],
            ['/opt/sagent-venv/bin/python', '-m', 'ghidra_mcp.cli', '--ready-timeout'],
        )
        self.assertNotIn('uvx', command)
        self.assertIn('--headless', command)
        self.assertIn(str(root.resolve()), command)
        # 同时保留 --ghidra-install-dir 与 --extension-jar 转发
        self.assertIn('--ghidra-install-dir', command)
        self.assertIn('/opt/ghidra', command)
        self.assertIn('--extension-jar', command)

    def test_mcp_config_paths_server_with_component_sessions(self):
        # 真实故障：paths 后端在场时证据代理的 binary-id 映射曾 KeyError
        # （paths 不是 Ghidra 会话，必须沿用根 binaryID）。
        plugin = Cwe78Plugin()
        old = os.environ.get('AGENT_PATH_BACKEND_PYTHON')
        os.environ['AGENT_PATH_BACKEND_PYTHON'] = sys.executable
        try:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / 'server'
                root.write_bytes(b'')
                libauth = Path(tmp) / 'libauth.so'
                libauth.write_bytes(b'')
                config = plugin.mcp_config(
                    root, ROOT / 'src', ghidra=self._ghidra_config(),
                    artifact_dir=Path(tmp) / 'artifacts',
                    analysis_group_id='group-x', binary_id='a' * 64,
                    ghidra_sessions=(('b' * 64, libauth),),
                )
        finally:
            if old is None:
                del os.environ['AGENT_PATH_BACKEND_PYTHON']
            else:
                os.environ['AGENT_PATH_BACKEND_PYTHON'] = old
        servers = config['opencode']['mcp']['servers']
        self.assertIn('paths', servers)
        self.assertIn('a' * 64, servers['paths']['command'])
        self.assertNotIn('b' * 64, servers['paths']['command'])


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
