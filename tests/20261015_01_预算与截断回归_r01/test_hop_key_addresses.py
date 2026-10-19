"""回归：hop 身份必须包含调用点地址。

旧实现只按 (from, to, kind) 的函数名做键：同名函数的不同调用点、以及递归函数
在不同层级上的重复出现，都会被当成同一条链而被精确去重合并。
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from agent.risk_chains import _hop_key, dedup_chains  # noqa: E402


def _chain(chain_id: str, hop: dict) -> dict:
    return {
        "chainID": chain_id,
        "sink": {"binaryID": "bin-1", "symbol": "free", "address": "0x1000"},
        "sources": [{"binary": "bin-1", "name": "recv", "kind": "import"}],
        "hops": [hop],
        "evidenceIDs": [],
        "mechanicalBasis": "callgraph",
        "semanticHints": None,
        "dedupedFrom": None,
    }


class HopKeyAddressTest(unittest.TestCase):
    def test_same_names_different_addresses_stay_distinct(self) -> None:
        left = {
            "from": "recurse_dirlist", "fromAddress": "0x401000",
            "to": "recurse_dirlist", "toAddress": "0x401010", "kind": "callgraph",
        }
        right = {
            "from": "recurse_dirlist", "fromAddress": "0x402000",
            "to": "recurse_dirlist", "toAddress": "0x402010", "kind": "callgraph",
        }
        self.assertNotEqual(_hop_key({"hops": [left]}), _hop_key({"hops": [right]}))

        kept, stats = dedup_chains([_chain("chain-a", left), _chain("chain-b", right)])
        self.assertEqual(stats["exact"], 0)
        self.assertEqual(len(kept), 2)

    def test_identical_hops_still_dedup(self) -> None:
        hop = {
            "from": "handler", "fromAddress": "0x401000",
            "to": "free", "toAddress": "0x500000", "kind": "callgraph",
        }
        kept, stats = dedup_chains([_chain("chain-a", hop), _chain("chain-b", dict(hop))])
        self.assertEqual(stats["exact"], 1)
        self.assertEqual(len(kept), 1)

    def test_legacy_hops_without_addresses_fall_back_to_names(self) -> None:
        legacy = {"from": "handler", "to": "free", "kind": "callgraph"}
        self.assertEqual(
            _hop_key({"hops": [legacy]}),
            (("handler", "handler", "free", "free", "callgraph"),),
        )


if __name__ == "__main__":
    unittest.main()
