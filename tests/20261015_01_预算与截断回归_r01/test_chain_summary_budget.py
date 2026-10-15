"""回归：候选链摘要必须按字节预算截断，且截断后仍是合法 JSON。

旧实现用 `len(text.encode())` 判预算、却用 `text[:BUDGET]` 按字符切片，
中文场景下实际字节数可达预算的数倍，且序列化 JSON 会被切成无法解析的文本。
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from agent.cli import _chains_summary_payload  # noqa: E402


def _chain(index: int) -> dict:
    return {
        "chainID": f"chain-{index:012d}",
        "sink": {"symbol": "recv", "argument": 2, "caller": f"处理函数_{index}"},
        "sources": [{"kind": "import", "name": "recv", "binary": "libbtservice.z.so"}],
        "hops": [{"from": f"函数_{index}", "to": "recv", "kind": "callgraph"}],
        "evidenceIDs": [f"ev-{index:020d}"],
    }


class ChainsSummaryBudgetTest(unittest.TestCase):
    def test_small_payload_keeps_every_chain(self) -> None:
        chains = [_chain(i) for i in range(3)]
        text, omitted = _chains_summary_payload(chains, 16 * 1024)
        self.assertEqual(omitted, 0)
        self.assertEqual(len(json.loads(text)["candidateChains"]), 3)

    def test_budget_measured_in_bytes_for_non_ascii(self) -> None:
        chains = [_chain(i) for i in range(40)]
        budget = 4096
        text, omitted = _chains_summary_payload(chains, budget)
        self.assertLessEqual(len(text.encode("utf-8")), budget)
        self.assertGreater(omitted, 0)
        # 截断后仍可解析，而不是被切一半的 JSON。
        kept = json.loads(text)["candidateChains"]
        self.assertEqual(len(kept), len(chains) - omitted)

    def test_budget_smaller_than_one_chain_returns_empty_valid_json(self) -> None:
        text, omitted = _chains_summary_payload([_chain(0)], 8)
        self.assertEqual(json.loads(text), {"candidateChains": []})
        self.assertEqual(omitted, 1)

    def test_no_chains(self) -> None:
        text, omitted = _chains_summary_payload([], 16 * 1024)
        self.assertEqual(json.loads(text), {"candidateChains": []})
        self.assertEqual(omitted, 0)


if __name__ == "__main__":
    unittest.main()
