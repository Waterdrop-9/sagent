import sys
import shutil
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from elf import build_analysis_groups  # noqa: E402


DATA = ROOT / "data" / "01_simple_demo"


class ElfDependencyExperiment(unittest.TestCase):
    def test_directory_builds_one_group_per_program(self) -> None:
        groups = build_analysis_groups(DATA)
        self.assertEqual({group.root.path.name for group in groups}, {"client", "server"})

        all_edges = [edge for group in groups for edge in group.edges]
        resolved_targets = {edge.target.name for edge in all_edges if edge.target}
        self.assertIn("libauth.so", resolved_targets)
        self.assertIn("liblog.so", resolved_targets)

    def test_single_elf_does_not_scan_parent_directory(self) -> None:
        group = build_analysis_groups(DATA / "server")[0]
        self.assertEqual(group.root.path.name, "server")
        self.assertTrue(any(edge.requested == "libauth.so" and not edge.target for edge in group.edges))
        self.assertTrue(any(edge.requested == "libc.so.6" and edge.known_library for edge in group.edges))

    def test_single_elf_uses_explicit_dependency_root(self) -> None:
        group = build_analysis_groups(DATA / "server", [DATA])[0]
        resolved_targets = {edge.target.name for edge in group.edges if edge.target}
        self.assertIn("liblog.so", resolved_targets)

    def test_runpath_origin_wins_over_same_name_outside_origin(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            wrong = Path(temporary) / "other"
            wrong.mkdir()
            shutil.copy2(DATA / "libs/libauth.so", wrong / "libauth.so")
            # 两个内容不同的候选会触发冲突；runpath=$ORIGIN/libs 只能保留项目内库。
            changed = wrong / "libauth.so"
            payload = bytearray(changed.read_bytes())
            payload[-1] ^= 1
            changed.write_bytes(payload)
            group = build_analysis_groups(DATA / "server", [DATA, wrong])[0]
            edge = next(edge for edge in group.edges if edge.requested == "libauth.so")
            self.assertEqual(edge.target, DATA / "libs/libauth.so")
            self.assertIn("RPATH/RUNPATH", edge.reason or "")


if __name__ == "__main__":
    unittest.main()
