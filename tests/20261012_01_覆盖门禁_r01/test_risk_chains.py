"""阶段 M（risk_chains.py）单元测试：动态符号、sink/source 枚举、链物化、去重、
机械证据合同（自签 evidenceID 落盘 raw/paths.jsonl）、finalize 集成、M2 降级。
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from agent.analysis_context import build_contexts
from agent.artifacts import ArtifactStore
from agent.models import FunctionSecurityModel
from agent.risk_chains import (
    CallGraphView,
    RiskChainsError,
    _apply_classification,
    classify_with_llm,
    dedup_chains,
    enumerate_sink_sites,
    materialize_chains,
    read_dynamic_symbols,
    run_path_queries,
    run_phase_m,
)

ROOT = Path(__file__).resolve().parents[2]
DEMO = ROOT / "data" / "01_simple_demo"
LIBS = DEMO / "libs"


class FakeBackend:
    """伪造 AngrPathBackend：任何查询都返回 path_found（函数调用后由 chain 更新引用）。"""

    def query(self, binary, request):
        return {
            "status": "path_found",
            "sink": {
                "functionID": "0x1400",
                "functionName": request.sink_function,
                "argument": request.sink_argument,
            },
            "paths": [{
                "caller": "doSystem",
                "callerFunctionID": "0x1200",
                "callsiteAddress": "0x1205",
                "sinkArgument": request.sink_argument,
                "definitions": [{"atom": "%rax", "address": "0x1210", "functionID": "0x1200"}],
            }],
            "limitations": [],
        }


class DynamicSymbolTests(unittest.TestCase):
    def test_read_dynamic_symbols_demo(self):
        dyn = read_dynamic_symbols(DEMO / "server")
        self.assertIn("system", dyn["imported"])
        self.assertIn("popen", dyn["imported"])
        self.assertIn("recv", dyn["imported"])
        self.assertNotIn("system", dyn["defined"])  # root 无导出

        auth = read_dynamic_symbols(LIBS / "libauth.so")
        self.assertIn("system", auth["imported"])
        self.assertIn("auth_verify", auth["defined"])
        self.assertIn("auth_log", auth["defined"])

        log = read_dynamic_symbols(LIBS / "liblog.so")
        self.assertIn("log_init", log["defined"])
        self.assertIn("fopen", log["imported"])

    def test_read_dynamic_symbols_rejects_non_elf(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "junk"
            path.write_bytes(b"not an elf at all")
            with self.assertRaises(RiskChainsError):
                read_dynamic_symbols(path)


class EnumerationTests(unittest.TestCase):
    def test_enumerate_sink_sites_cwe78(self):
        imports = {"system": [0x401050], "popen": [0x401058], "printf": [0x401060]}
        sites = enumerate_sink_sites("b" * 64, "server", imports, "CWE-78")
        self.assertEqual(
            {(s["symbol"], s["family"]) for s in sites},
            {("system", "command_execution"), ("popen", "command_execution")},
        )
        for site in sites:
            self.assertEqual(site["argument"], 0)
            self.assertIsNone(site["caller"])

    def test_enumerate_sink_sites_cwe134(self):
        sites = enumerate_sink_sites("b" * 64, "server", {"printf": [0x401060]}, "CWE-134")
        self.assertEqual([(s["symbol"], s["family"]) for s in sites], [("printf", "format_string")])


class MaterializeTests(unittest.TestCase):
    def _dyn(self):
        return {
            "server": {
                "defined": {},
                "imported": {"recv": [0x9000], "popen": [0x9008], "system": [0x9010]},
            },
            "libauth.so": {
                "defined": {"auth_verify": 0x2000, "auth_log": 0x2100},
                "imported": {"system": [0x3000]},
            },
        }

    def _cfg(self):
        return CallGraphView(
            functions={
                0x1000: "main", 0x1100: "remoteExec", 0x1200: "doSystem",
                0x1300: "recv", 0x1400: "popen", 0x1500: "system",
            },
            callers={
                0x1400: (0x1200,), 0x1300: (0x1100,), 0x1200: (0x1100,),
                0x1100: (0x1000,), 0x1500: (0x1000,),
            },
        )

    def _binary_id_of(self, name):
        return {"server": "r" * 64, "libauth.so": "l" * 64}[name]

    def test_materialize_callgraph_chains(self):
        chains = materialize_chains("CWE-78", self._binary_id_of, self._dyn(), "server", self._cfg())
        popen = [c for c in chains if c["sink"]["symbol"] == "popen"]
        # 反向 BFS 命中断点后继续回溯：popen 得到两条链（源 remoteExec 与更深的 main）。
        self.assertEqual(len(popen), 2)
        self.assertTrue(all(c["mechanicalBasis"] == "callgraph" for c in popen))
        by_source = {c["sources"][0]["name"]: c for c in popen}
        self.assertEqual([(h["from"], h["to"]) for h in by_source["remoteExec"]["hops"]],
                         [("remoteExec", "doSystem")])
        self.assertEqual([(h["from"], h["to"]) for h in by_source["main"]["hops"]],
                         [("remoteExec", "doSystem"), ("main", "remoteExec")])

        system = [c for c in chains if c["sink"]["symbol"] == "system" and c["sink"]["binary"] == "server"]
        self.assertEqual(len(system), 1)
        self.assertEqual(system[0]["sink"]["caller"], "main")
        self.assertEqual(system[0]["hops"], [])
        self.assertEqual([s["kind"] for s in system[0]["sources"]], ["entry"])

    def test_materialize_component_import_table_chain(self):
        chains = materialize_chains("CWE-78", self._binary_id_of, self._dyn(), "server", self._cfg())
        lib = [c for c in chains if c["sink"]["binary"] == "libauth.so"]
        self.assertEqual(len(lib), 1)
        self.assertEqual(lib[0]["mechanicalBasis"], "import_table")
        self.assertEqual(
            {s["name"] for s in lib[0]["sources"]}, {"auth_verify", "auth_log"}
        )

    def test_materialize_without_cfg_degrades_to_import_table(self):
        dyn = self._dyn()
        dyn["server"]["imported"]["auth_verify"] = [0x9020]  # root 导入组件导出
        chains = materialize_chains("CWE-78", self._binary_id_of, dyn, "server", None)
        root = [c for c in chains if c["sink"]["binary"] == "server"]
        self.assertTrue(all(c["mechanicalBasis"] == "import_table" for c in root))
        self.assertTrue(any(c["mechanicalBasis"] == "plt_link" for c in chains))


class DedupTests(unittest.TestCase):
    def _chain(self, symbol, sources, hops):
        return {
            "chainID": "chain-x",
            "sink": {
                "binaryID": "b", "binary": "x", "symbol": symbol, "family": "f",
                "argument": 0, "address": "0x9", "caller": "c", "callerAddress": "0x9",
            },
            "sources": sources,
            "hops": hops,
            "evidenceIDs": [],
            "mechanicalBasis": "callgraph",
            "semanticHints": None,
            "dedupedFrom": None,
        }

    @staticmethod
    def _src(name):
        return {"kind": "entry", "name": name, "address": None, "binary": "x", "binaryID": "b"}

    def test_exact_duplicate(self):
        a = self._chain("system", [self._src("main")], [])
        chains, stats = dedup_chains([a, self._chain("system", [self._src("main")], [])])
        self.assertEqual(len(chains), 1)
        self.assertEqual(stats, {"exact": 1, "subsumed": 0, "merged": 0})

    def test_short_chain_subsumed_by_longer(self):
        h1 = {"from": "a", "to": "b", "binary": "x", "kind": "callgraph"}
        h2 = {"from": "b", "to": "c", "binary": "x", "kind": "callgraph"}
        short = self._chain("system", [self._src("main")], [])
        long = self._chain("system", [self._src("main")], [h1, h2])
        chains, stats = dedup_chains([short, long])
        self.assertEqual(len(chains), 1)
        self.assertEqual(chains[0]["hops"], [h1, h2])
        self.assertEqual(stats["subsumed"], 1)

    def test_shared_downstream_sources_merged(self):
        h1 = {"from": "a", "to": "b", "binary": "x", "kind": "callgraph"}
        m1 = self._chain("popen", [self._src("s1")], [h1])
        m2 = self._chain("popen", [self._src("s2")], [h1])
        chains, stats = dedup_chains([m1, m2])
        self.assertEqual(len(chains), 1)
        self.assertEqual({s["name"] for s in chains[0]["sources"]}, {"s1", "s2"})
        self.assertEqual(stats["merged"], 1)


class EvidenceContractTests(unittest.TestCase):
    def _chain(self, binary_id, symbol="system"):
        return {
            "chainID": "c1",
            "sink": {
                "binaryID": binary_id, "binary": "server", "symbol": symbol,
                "family": "command_execution", "argument": 0,
                "address": "0x1", "caller": "main", "callerAddress": "0x2",
            },
            "sources": [],
            "hops": [],
            "evidenceIDs": [],
            "mechanicalBasis": "callgraph",
            "semanticHints": None,
            "dedupedFrom": None,
        }

    def test_run_path_queries_writes_self_signed_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            workdir = Path(tmp)
            chains = [self._chain("r" * 64)]
            updated, stats = run_path_queries(
                workdir, "group-test", {"r" * 64: Path("nowhere")}, chains,
                backend=FakeBackend(),
            )
            self.assertEqual(stats["pathQueries"], 1)
            self.assertEqual(stats["evidenceCount"], 1)
            evidence_id = updated[0]["evidenceIDs"][0]
            self.assertTrue(evidence_id.startswith("ev-"))

            lines = [
                json.loads(line)
                for line in (workdir / "raw" / "paths.jsonl").read_text().splitlines()
            ]
            self.assertEqual(len(lines), 1)
            record = lines[0]
            self.assertEqual(record["server"], "paths")
            self.assertEqual(record["tool"], "query_sink_paths")
            self.assertEqual(record["analysisGroupID"], "group-test")
            self.assertEqual(record["binaryID"], "r" * 64)
            self.assertEqual(record["evidenceID"], evidence_id)
            self.assertEqual(record["arguments"]["sink_function"], "system")
            payload = json.loads(record["result"]["content"][0]["text"])
            self.assertEqual(payload["status"], "path_found")


class FinalizeIntegrationTests(unittest.TestCase):
    """阶段 M 的机械证据必须能被 ArtifactStore.finalize 正常核验（同一合同）。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.context = build_contexts(DEMO / "server")[0]
        self.store = ArtifactStore(Path(self.tmp.name) / "run")
        self.store.initialize(self.context.to_dict(), self.context.root_path)

    def _emit_and_cite(self):
        chain = {
            "chainID": "c1",
            "sink": {
                "binaryID": self.context.root["binaryID"], "binary": "server",
                "symbol": "system", "family": "command_execution", "argument": 0,
                "address": "0x1", "caller": "main", "callerAddress": "0x2",
            },
            "sources": [], "hops": [], "evidenceIDs": [],
            "mechanicalBasis": "callgraph", "semanticHints": None, "dedupedFrom": None,
        }
        updated, stats = run_path_queries(
            self.store.directory, self.context.analysis_group_id,
            {self.context.root["binaryID"]: self.context.root_path},
            [chain], backend=FakeBackend(),
        )
        return updated[0]["evidenceIDs"][0]

    def test_phase_m_evidence_survives_finalize(self):
        evidence_id = self._emit_and_cite()
        model = FunctionSecurityModel(
            self.context.root["binaryID"], "0x100", "system",
            roles=("sink",), sink_params=(0,), status="confirmed",
            evidence_ids=(evidence_id,),
        )
        report = {
            "findings": [{
                "status": "confirmed", "binaryID": self.context.root["binaryID"],
                "functionID": "0x401ba2", "confidence": "high",
                "evidenceIDs": [evidence_id], "limitations": [],
            }],
            "unresolved": [],
            "coverage": {
                "attackSurfaces": [{
                    "surfaceID": "s1", "category": "network", "status": "checked",
                    "evidenceIDs": [evidence_id],
                }],
                "functionModels": [model.to_dict()],
            },
        }
        report = self.store.finalize(report)
        self.assertEqual(len(report["findings"]), 1)
        self.assertFalse(any("证据引用无法核验" in item for item in report["unresolved"]))
        self.assertFalse(any("finding 未达到最终状态门槛" in item for item in report["unresolved"]))
        self.assertEqual(report["coverage"]["functionModels"][0]["evidenceIDs"], [evidence_id])


class M2FallbackTests(unittest.TestCase):
    def test_classify_with_llm_degrades_on_failure(self):
        def boom(messages):
            raise RuntimeError("llm down")

        self.assertIsNone(classify_with_llm(boom, {}))

    def test_classify_with_llm_parses_and_applies_hints(self):
        def ok(messages):
            return (
                "前缀噪声 "
                '{"libClass": {"server": "common"}, '
                '"wrapperHints": [{"binary": "server", "symbol": "doSystem", "hint": "命令执行 wrapper"}]}'
                " 后缀噪声"
            )

        classification = classify_with_llm(ok, {})
        self.assertEqual(classification["libClass"]["server"], "common")
        chain = {
            "chainID": "c1",
            "sink": {
                "binaryID": "b", "binary": "server", "symbol": "doSystem",
                "family": "command_execution", "argument": 0,
                "address": "0x1", "caller": "main", "callerAddress": "0x2",
            },
            "sources": [], "hops": [], "evidenceIDs": [],
            "mechanicalBasis": "callgraph", "semanticHints": None, "dedupedFrom": None,
        }
        chains = _apply_classification([chain], classification)
        self.assertEqual(chains[0]["semanticHints"]["libClass"], "common")
        self.assertEqual(chains[0]["semanticHints"]["wrapperHint"], "命令执行 wrapper")


class PhaseMTests(unittest.TestCase):
    def test_run_phase_m_without_angr_falls_back(self):
        context = build_contexts(DEMO / "server", [DEMO / "libs"])[0]
        component_paths = {
            c["binaryID"]: LIBS / c["path"]
            for c in context.components if c["path"] != "server"
        }
        with tempfile.TemporaryDirectory() as tmp:
            summary = run_phase_m(
                context, "CWE-78", Path(tmp),
                component_paths=component_paths, backend=FakeBackend(), cfg=None,
            )
            doc = json.loads((Path(tmp) / "risk-chains.json").read_text())
            self.assertEqual(doc["analysisGroupID"], context.analysis_group_id)
            self.assertEqual(doc["cwe"], "CWE-78")
            sinks = {(c["sink"]["binary"], c["sink"]["symbol"]) for c in doc["chains"]}
            self.assertIn(("libauth.so", "system"), sinks)  # 组件内 sink（导入表级）
            self.assertTrue(any(c["mechanicalBasis"] == "plt_link" for c in doc["chains"]))
            self.assertGreaterEqual(doc["stats"]["evidenceCount"], 1)
            self.assertFalse(doc["stats"]["m2Used"])
            self.assertEqual(summary["chainCount"], len(doc["chains"]))


if __name__ == "__main__":
    unittest.main()
