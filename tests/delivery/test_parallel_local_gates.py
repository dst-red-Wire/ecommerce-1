import importlib.util
from pathlib import Path
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("repoctl_parallel_test", ROOT / "scripts/repoctl.py")
assert SPEC and SPEC.loader
REPOCTL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPOCTL)


class ParallelLocalGateTest(unittest.TestCase):
    def test_parallelism_is_bounded_by_gate_cpu_memory_and_four(self):
        with mock.patch.object(REPOCTL.os, "cpu_count", return_value=32), mock.patch.object(
            REPOCTL.os, "sysconf", side_effect=[8 * 1024**3 // 4096, 4096]
        ):
            self.assertLessEqual(REPOCTL._local_parallelism(20), 4)

    def test_invalid_override_cannot_exceed_resource_bound(self):
        with mock.patch.dict(REPOCTL.os.environ, {"REPOCTL_LOCAL_JOBS": "99"}), mock.patch.object(
            REPOCTL.os, "cpu_count", return_value=2
        ), mock.patch.object(REPOCTL.os, "sysconf", side_effect=[4 * 1024**3 // 4096, 4096]):
            self.assertEqual(2, REPOCTL._local_parallelism(5))


if __name__ == "__main__":
    unittest.main()
