import importlib.util
import os
import signal
import sys
import tempfile
import time
from pathlib import Path
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("repoctl_parallel_test", ROOT / "scripts/repoctl.py")
assert SPEC and SPEC.loader
REPOCTL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPOCTL)


class ParallelLocalGateTest(unittest.TestCase):
    def test_windows_resource_probe_falls_back_without_sysconf(self):
        with (
            mock.patch.object(REPOCTL.os, "cpu_count", return_value=8),
            mock.patch.object(REPOCTL.os, "sysconf", side_effect=AttributeError("sysconf unavailable")),
            mock.patch.object(Path, "read_text", side_effect=OSError("no procfs")),
        ):
            cpu, memory = REPOCTL._local_resources()
        self.assertEqual(8, cpu)
        self.assertEqual(1024**3, memory)

    def test_windows_parallel_runner_uses_process_group_and_taskkill(self):
        process = mock.Mock(pid=4242, returncode=0)
        process.poll.side_effect = [None, 0, 0, 0]
        process.wait.return_value = 0
        popen = mock.Mock(return_value=process)
        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch.object(REPOCTL, "CONTEXT", Path(directory)),
            mock.patch.object(REPOCTL, "ROOT", Path(directory)),
            mock.patch.object(REPOCTL, "_local_parallelism", return_value=1),
            mock.patch.object(REPOCTL, "_local_resources", return_value=(2, 4 * 1024**3)),
            mock.patch.object(REPOCTL.os, "name", "nt"),
            mock.patch.object(REPOCTL.subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200, create=True),
            mock.patch.object(REPOCTL.subprocess, "Popen", popen),
            mock.patch.object(REPOCTL.subprocess, "run") as run,
        ):
            self.assertTrue(REPOCTL._run_independent_gates([("windows", ["cmd", "/c", "exit", "0"])], [], {}))
        self.assertEqual(0x00000200, popen.call_args.kwargs["creationflags"])
        self.assertNotIn("start_new_session", popen.call_args.kwargs)
        commands = [call.args[0] for call in run.call_args_list]
        self.assertTrue(any(command[:4] == ["taskkill", "/PID", "4242", "/T"] for command in commands))

    def test_parallelism_is_bounded_by_gate_cpu_memory_and_four(self):
        with (
            mock.patch.object(REPOCTL.os, "cpu_count", return_value=32),
            mock.patch.object(REPOCTL.os, "sysconf", side_effect=[8 * 1024**3 // 4096, 4096]),
        ):
            self.assertLessEqual(REPOCTL._local_parallelism(20), 4)

    def test_invalid_override_cannot_exceed_resource_bound(self):
        with (
            mock.patch.dict(REPOCTL.os.environ, {"REPOCTL_LOCAL_JOBS": "99"}),
            mock.patch.object(REPOCTL.os, "cpu_count", return_value=2),
            mock.patch.object(REPOCTL.os, "sysconf", side_effect=[4 * 1024**3 // 4096, 4096]),
        ):
            self.assertEqual(2, REPOCTL._local_parallelism(5))

    def test_inherited_workers_are_clamped_and_smaller_limits_preserved(self):
        for inherited, expected in (("99", "2"), ("1", "1"), ("0", "2"), ("-1", "2"), ("bad", "2")):
            with (
                self.subTest(inherited=inherited),
                tempfile.TemporaryDirectory() as directory,
                mock.patch.object(REPOCTL, "CONTEXT", Path(directory)),
                mock.patch.object(REPOCTL, "ROOT", Path(directory)),
                mock.patch.object(REPOCTL, "_local_parallelism", return_value=2),
                mock.patch.object(REPOCTL, "_local_resources", return_value=(4, 8 * 1024**3)),
            ):
                env = dict(os.environ, GOMAXPROCS=inherited, ANSIBLE_FORKS=inherited)
                command = [
                    sys.executable,
                    "-c",
                    "import os; assert os.environ['GOMAXPROCS'] == "
                    + repr(expected)
                    + "; assert os.environ['ANSIBLE_FORKS'] == "
                    + repr(expected),
                ]
                self.assertTrue(REPOCTL._run_independent_gates([("workers", command)], [], env))
                self.assertEqual(inherited, env["GOMAXPROCS"])

    def test_cgroup_quota_and_available_memory_bound_jobs(self):
        values = {
            "/proc/self/cgroup": "0::/\n",
            "/sys/fs/cgroup/cpu.max": "100000 100000",
            "/sys/fs/cgroup/memory.max": str(2 * 1024**3),
            "/sys/fs/cgroup/memory.current": str(1024**3),
        }

        def read(path, *args, **kwargs):
            if str(path) in values:
                return values[str(path)]
            raise FileNotFoundError(path)

        with (
            mock.patch.object(Path, "read_text", read),
            mock.patch.object(REPOCTL.os, "cpu_count", return_value=64),
            mock.patch.object(REPOCTL.os, "sched_getaffinity", return_value=set(range(64))),
            mock.patch.object(REPOCTL.os, "sysconf", side_effect=[32 * 1024**3 // 4096, 4096]),
        ):
            self.assertEqual(1, REPOCTL._local_parallelism(10))

    def test_mutation_is_recorded_as_failure_before_evidence_write(self):
        captured = []
        with (
            mock.patch.object(REPOCTL, "git", return_value="head"),
            mock.patch.object(REPOCTL, "worktree_tree_sha", side_effect=["before", "before", "after"]),
            mock.patch.object(REPOCTL, "changed_paths", return_value=[]),
            mock.patch.object(REPOCTL, "affected", return_value=[]),
            mock.patch.object(REPOCTL, "_global_gate_commands", return_value=[]),
            mock.patch.object(REPOCTL, "_run_independent_gates", return_value=True),
            mock.patch.object(
                REPOCTL,
                "write_evidence",
                side_effect=lambda base, head, paths, components, records, verification: captured.append(
                    (records, verification)
                ),
            ),
        ):
            self.assertEqual(1, REPOCTL.verify_change("base", "WORKTREE"))
        records, verification = captured[0]
        self.assertEqual("FAIL", records[-1]["status"])
        self.assertFalse(verification["tree_stable"])

    def test_spawn_failure_reaps_already_started_gate(self):
        processes = []
        original = REPOCTL.subprocess.Popen

        def spawn(*args, **kwargs):
            if processes:
                raise OSError("simulated process exhaustion")
            process = original(*args, **kwargs)
            processes.append(process)
            return process

        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch.object(REPOCTL, "CONTEXT", Path(directory)),
            mock.patch.object(REPOCTL, "_local_parallelism", return_value=2),
            mock.patch.object(REPOCTL.subprocess, "Popen", side_effect=spawn),
        ):
            with self.assertRaises(OSError):
                REPOCTL._run_independent_gates(
                    [
                        ("one", [sys.executable, "-c", "import time; time.sleep(60)"]),
                        ("two", [sys.executable, "-c", "pass"]),
                    ],
                    [],
                    os.environ.copy(),
                )
        self.assertIsNotNone(processes[0].returncode)

    def test_failure_kills_descendant_after_its_gate_exits(self):
        with tempfile.TemporaryDirectory() as directory:
            context = Path(directory)
            pidfile = context / "child.pid"
            child = (
                "import os, signal, time; from pathlib import Path; "
                "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                f"Path({str(pidfile)!r}).write_text(str(os.getpid())); time.sleep(60)"
            )
            parent = (
                "import subprocess, sys, time; from pathlib import Path; "
                f"subprocess.Popen([sys.executable, '-c', {child!r}]); "
                f"p=Path({str(pidfile)!r}); "
                "exec('while not p.exists(): time.sleep(0.01)'); sys.exit(1)"
            )
            pid = None
            try:
                with mock.patch.object(REPOCTL, "CONTEXT", context), mock.patch.object(REPOCTL, "ROOT", context):
                    self.assertFalse(
                        REPOCTL._run_independent_gates(
                            [("failed-parent", [sys.executable, "-c", parent])], [], os.environ.copy()
                        )
                    )
                pid = int(pidfile.read_text())
                for _ in range(100):
                    stat = Path(f"/proc/{pid}/stat")
                    if not stat.exists() or stat.read_text().split()[2] == "Z":
                        break
                    time.sleep(0.01)
                else:
                    self.fail("gate descendant survived cancellation")
            finally:
                if pid is None and pidfile.exists():
                    pid = int(pidfile.read_text())
                if pid is not None:
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass


if __name__ == "__main__":
    unittest.main()
