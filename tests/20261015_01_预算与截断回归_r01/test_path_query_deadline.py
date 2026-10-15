"""回归：不可中断的分析（angr RDA）必须有墙钟预算。

实测在 lrzip 上 RDA 可挂死超过 431 s：`max_depth`/`max_nodes` 只约束
`_walk_definitions`，不约束 RDA 本身。这里验证超时降级路径而不是阻塞。
"""

from __future__ import annotations

import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from agent.path_query import AngrPathBackend  # noqa: E402


class DeadlineTest(unittest.TestCase):
    def test_fast_call_returns_value(self) -> None:
        value, note = AngrPathBackend._run_with_deadline(lambda: 42, 5, "分析")
        self.assertEqual(value, 42)
        self.assertIsNone(note)

    def test_slow_call_degrades_with_limitation(self) -> None:
        started = time.monotonic()
        value, note = AngrPathBackend._run_with_deadline(
            lambda: time.sleep(30), 0.5, "RDA 定义链分析"
        )
        self.assertIsNone(value)
        self.assertIn("预算", note or "")
        self.assertLess(time.monotonic() - started, 5)

    def test_exception_propagates_to_caller(self) -> None:
        def boom() -> None:
            raise ValueError("rda failed")

        with self.assertRaises(ValueError):
            AngrPathBackend._run_with_deadline(boom, 5, "分析")


if __name__ == "__main__":
    unittest.main()
