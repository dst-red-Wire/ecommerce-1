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
    def test_windows_resources_use_affinity_and_available_memory_without_sysconf(self):
        import ctypes

        def memory(pointer):
            pointer._obj.available_phys = 6 * 1024**3
            return 1

        def affinity(process, mask, system):
            mask._obj.value = 0b1010
            return 1

        kernel = mock.Mock()
        kernel.GlobalMemoryStatusEx.side_effect = memory
        kernel.GetProcessAffinityMask.side_effect = affinity
        kernel.GetCurrentProcess.return_value = 1
        with (
            mock.patch.object(REPOCTL.sys, "platform", "win32"),
            mock.patch.object(ctypes, "WinDLL", return_value=kernel, create=True),
            mock.patch.object(REPOCTL.os, "sysconf", side_effect=AssertionError("POSIX API on Windows")),
            mock.patch.object(REPOCTL.os, "cpu_count", return_value=8),
        ):
            self.assertEqual((2, 6 * 1024**3), REPOCTL._local_resources())

    def test_windows_jobs_terminate_descendants_even_after_leader_exit(self):
        import ctypes

        kernel = mock.Mock()
        kernel.CreateJobObjectW.return_value = 123
        kernel.SetInformationJobObject.return_value = 1
        kernel.AssignProcessToJobObject.return_value = 1
        kernel.TerminateJobObject.return_value = 1
        kernel.CloseHandle.return_value = 1
        with mock.patch.object(ctypes, "WinDLL", return_value=kernel, create=True):
            job = REPOCTL._WindowsJob()
            process = mock.Mock(_handle=456, returncode=1)
            job.attach(process)
            job.close()
            job.close()
        kernel.AssignProcessToJobObject.assert_called_once_with(123, 456)
        kernel.TerminateJobObject.assert_called_once_with(123, 1)
        kernel.CloseHandle.assert_called_once_with(123)
        limits = kernel.SetInformationJobObject.call_args.args[2]._obj
        self.assertEqual(0x2000, limits.basic.flags)

    def test_windows_dispatch_never_calls_killpg(self):
        for code in (0, 1):
            with tempfile.TemporaryDirectory() as directory:
                job = mock.Mock()
                with (
                    self.subTest(exit_code=code),
                    mock.patch.object(REPOCTL.sys, "platform", "win32"),
                    mock.patch.object(REPOCTL, "_WindowsJob", return_value=job),
                    mock.patch.object(REPOCTL, "_local_resources", return_value=(2, 4 * 1024**3)),
                    mock.patch.object(REPOCTL, "CONTEXT", Path(directory)),
                    mock.patch.object(REPOCTL, "ROOT", Path(directory)),
                    mock.patch.object(REPOCTL.os, "killpg", side_effect=AssertionError("POSIX killpg on Windows")),
                ):
                    self.assertEqual(
                        code == 0,
                        REPOCTL._run_independent_gates(
                            [("windows", [sys.executable, "-c", f"raise SystemExit({code})"])],
                            [],
                            os.environ.copy(),
                        ),
                    )
                job.attach.assert_called_once()
                job.close.assert_called_once()

    def test_windows_job_assignment_failure_cannot_start_the_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "gate-started"
            job = mock.Mock()
            job.attach.side_effect = OSError("assignment refused")
            with (
                mock.patch.object(REPOCTL.sys, "platform", "win32"),
                mock.patch.object(REPOCTL, "_WindowsJob", return_value=job),
                open(os.devnull, "w") as output,
            ):
                with self.assertRaisesRegex(OSError, "assignment refused"):
                    REPOCTL._start_gate_process(
                        [sys.executable, "-c", f"from pathlib import Path; Path({str(marker)!r}).touch()"],
                        output,
                        os.environ.copy(),
                    )
            self.assertFalse(marker.exists())
            job.close.assert_called_once()
            self.assertIsNotNone(job.attach.call_args.args[0].returncode)

    def test_windows_wrapper_cannot_import_checkout_modules_before_job_assignment(self):
        with tempfile.TemporaryDirectory() as directory:
            context = Path(directory)
            marker = context / "uncontained-import"
            (context / "subprocess.py").write_text(f"from pathlib import Path; Path({str(marker)!r}).touch()\n")
            job = mock.Mock()

            def attach(process):
                time.sleep(0.2)
                self.assertIsNone(process.poll())
                self.assertFalse(marker.exists())

            job.attach.side_effect = attach
            with (
                mock.patch.object(REPOCTL.sys, "platform", "win32"),
                mock.patch.object(REPOCTL, "ROOT", context),
                mock.patch.object(REPOCTL, "_WindowsJob", return_value=job),
                open(os.devnull, "w") as output,
            ):
                process, returned_job = REPOCTL._start_gate_process(
                    [sys.executable, "-I", "-S", "-c", "pass"], output, os.environ.copy()
                )
                try:
                    self.assertEqual(0, process.wait(timeout=5))
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.wait()
                    returned_job.close()
            self.assertFalse(marker.exists())

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
        self._check_descendant_cleanup(new_session=False)

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux subreaper regression")
    def test_failure_kills_detached_descendant_after_its_gate_exits(self):
        self._check_descendant_cleanup(new_session=True)

    def _check_descendant_cleanup(self, new_session):
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
                f"subprocess.Popen([sys.executable, '-c', {child!r}], start_new_session={new_session!r}); "
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
