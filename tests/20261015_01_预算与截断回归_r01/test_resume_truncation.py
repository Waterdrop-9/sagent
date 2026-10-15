"""回归：恢复摘要的列表截断必须显式，避免"未展示"被当成"不存在"。"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from agent.artifacts import _RESUME_ITEM_LIMIT, _summarize_fields  # noqa: E402


class ResumeTruncationTest(unittest.TestCase):
    def test_within_limit_has_no_truncation_record(self) -> None:
        shown, truncated = _summarize_fields({"findings": list(range(_RESUME_ITEM_LIMIT))})
        self.assertEqual(len(shown["findings"]), _RESUME_ITEM_LIMIT)
        self.assertEqual(truncated, {})

    def test_over_limit_records_total(self) -> None:
        fields = {
            "findings": list(range(_RESUME_ITEM_LIMIT + 5)),
            "unresolved": [1],
        }
        shown, truncated = _summarize_fields(fields)
        self.assertEqual(len(shown["findings"]), _RESUME_ITEM_LIMIT)
        self.assertEqual(shown["unresolved"], [1])
        self.assertEqual(
            truncated,
            {"findings": {"total": _RESUME_ITEM_LIMIT + 5, "shown": _RESUME_ITEM_LIMIT}},
        )

    def test_empty_fields_are_kept(self) -> None:
        shown, truncated = _summarize_fields({"blockers": []})
        self.assertEqual(shown, {"blockers": []})
        self.assertEqual(truncated, {})


if __name__ == "__main__":
    unittest.main()
