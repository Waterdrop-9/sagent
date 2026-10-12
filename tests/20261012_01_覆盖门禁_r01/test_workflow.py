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
from agent.external_poc import ExternalPocAdapter
from agent.plugins import Cwe78Plugin, plugin_for_cwe, supported_cwes


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

    def test_external_poc_adapter_only_accepts_confirmed_findings(self):
        prompt_dir = Path('/Users/xpf/Desktop/二进制/vulnhunter_v2_local/config/foolish')
        if not prompt_dir.is_dir():
            self.skipTest('外部 prompt 目录不在当前机器')
        adapter = ExternalPocAdapter(prompt_dir)
        prompt = adapter.build_prompt(Path('/tmp/server'), 'CWE-78', [
            {'status': 'confirmed', 'binaryID': 'b', 'functionID': 'f', 'evidenceIDs': ['ev']}
        ], Path('/tmp/artifacts'))
        self.assertIn('03 搜查命令注入', prompt)
        with self.assertRaises(ValueError):
            adapter.build_prompt(Path('/tmp/server'), 'CWE-78', [], Path('/tmp/artifacts'))


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


if __name__ == '__main__':
    unittest.main()
