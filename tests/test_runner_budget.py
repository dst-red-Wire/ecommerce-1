"""Behavioral tests for bounded runner process execution."""

from __future__ import annotations

import os
import signal
import sys
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from pathlib import Path

from scripts.runner_budget import BudgetedRunner, RunnerBudget, run_workload


def budget(**overrides: object) -> RunnerBudget:
    values: dict[str, object] = {
        "global_timeout_seconds": 3.0,
        "subprocess_timeout_seconds": 1.0,
        "cpu_seconds": 2,
        "memory_bytes": 256 * 1024 * 1024,
        "max_concurrency": 2,
    }
    values.update(overrides)
    return RunnerBudget.from_mapping(values)


def python(command: str, *arguments: str) -> list[str]:
    return [sys.executable, "-c", command, *arguments]


class RunnerBudgetTests(unittest.TestCase):
    def test_normal_execution_has_closed_stdin_and_explicit_environment(self) -> None:
        result = run_workload(
            python(
                "import os,sys; "
                "print(os.environ.get('VISIBLE')); "
                "print(os.environ.get('HOME', 'absent')); "
                "print(repr(sys.stdin.read()))"
            ),
            budget=budget(),
            env={"VISIBLE": "yes"},
        )
        self.assertTrue(result.command_succeeded, result)
        self.assertEqual(["yes", "absent", "''"], result.stdout.splitlines())
        self.assertFalse(result.timed_out)
        self.assertIsNone(result.timeout_scope)
        self.assertEqual("INSUFFICIENT", result.verdict)
        self.assertFalse(result.passed)

    def test_subprocess_timeout_kills_forked_descendant(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            child_pid_path = Path(directory) / "child.pid"
            script = (
                "import os,pathlib,sys,time; "
                "pid=os.fork(); "
                "pathlib.Path(sys.argv[1]).write_text(str(pid)) if pid else None; "
                "time.sleep(30)"
            )
            result = run_workload(
                python(script, str(child_pid_path)),
                budget=budget(subprocess_timeout_seconds=0.6),
                env={},
            )
            self.assertTrue(result.timed_out, result)
            self.assertEqual("subprocess", result.timeout_scope)
            self.assertTrue(result.killed_process_group)
            self.assertTrue(child_pid_path.exists(), result)
            child_pid = int(child_pid_path.read_text())
            for _ in range(30):
                status = Path(f"/proc/{child_pid}/stat")
                if not status.exists() or status.read_text().split()[2] == "Z":
                    break
                time.sleep(0.05)
            else:
                self.fail(f"forked descendant {child_pid} survived timeout")

    def test_setsid_escape_cannot_claim_proof_pass(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            child_pid_path = Path(directory) / "detached.pid"
            script = (
                "import os,pathlib,sys,time\n"
                "pid=os.fork()\n"
                "if pid == 0:\n"
                "    os.setsid()\n"
                "    os.close(1)\n"
                "    os.close(2)\n"
                "    pathlib.Path(sys.argv[1]).write_text(str(os.getpid()))\n"
                "    time.sleep(10)\n"
                "else:\n"
                "    marker=pathlib.Path(sys.argv[1])\n"
                "    deadline=time.monotonic()+2\n"
                "    while not marker.exists() and time.monotonic()<deadline:\n"
                "        time.sleep(0.01)\n"
            )
            child_pid = None
            try:
                result = run_workload(
                    python(script, str(child_pid_path)),
                    budget=budget(subprocess_timeout_seconds=2.0),
                    env={},
                )
                self.assertTrue(child_pid_path.exists(), result)
                child_pid = int(child_pid_path.read_text())
                os.kill(child_pid, 0)
                self.assertTrue(result.command_succeeded, result)
                self.assertEqual("INSUFFICIENT", result.verdict)
                self.assertEqual("INSUFFICIENT", asdict(result)["verdict"])
                self.assertFalse(result.passed)
            finally:
                if child_pid is not None:
                    try:
                        os.kill(child_pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    def test_global_deadline_is_shared_across_calls(self) -> None:
        runner = BudgetedRunner(
            budget(global_timeout_seconds=0.8, subprocess_timeout_seconds=3.0)
        )
        first = runner.run(python("import time;time.sleep(0.2)"), env={})
        second = runner.run(python("import time;time.sleep(3)"), env={})
        self.assertTrue(first.command_succeeded, first)
        self.assertTrue(second.timed_out, second)
        self.assertEqual("global", second.timeout_scope)

    def test_concurrency_ceiling_serializes_workloads(self) -> None:
        runner = BudgetedRunner(
            budget(
                global_timeout_seconds=3.0,
                subprocess_timeout_seconds=2.0,
                max_concurrency=1,
            )
        )
        started = time.monotonic()
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(
                pool.map(
                    lambda _: runner.run(python("import time;time.sleep(0.3)"), env={}),
                    range(2),
                )
            )
        elapsed = time.monotonic() - started
        self.assertTrue(all(result.command_succeeded for result in results), results)
        self.assertGreaterEqual(elapsed, 0.55)

    def test_missing_and_invalid_budgets_fail_closed(self) -> None:
        values = {
            "global_timeout_seconds": 3.0,
            "subprocess_timeout_seconds": 1.0,
            "cpu_seconds": 2,
            "memory_bytes": 256 * 1024 * 1024,
            "max_concurrency": 2,
        }
        for field in values:
            with self.subTest(missing=field):
                incomplete = dict(values)
                del incomplete[field]
                with self.assertRaisesRegex(ValueError, "missing"):
                    RunnerBudget.from_mapping(incomplete)
        with self.assertRaisesRegex(ValueError, "unknown"):
            RunnerBudget.from_mapping({**values, "extra": 1})
        for field, invalid in (
            ("global_timeout_seconds", 0),
            ("subprocess_timeout_seconds", float("nan")),
            ("cpu_seconds", True),
            ("memory_bytes", -1),
            ("max_concurrency", 0),
            ("max_concurrency", 17),
        ):
            with (
                self.subTest(field=field, invalid=invalid),
                self.assertRaisesRegex(ValueError, field),
            ):
                RunnerBudget.from_mapping({**values, field: invalid})
        with self.assertRaises(ValueError):
            run_workload(python("pass"), budget=budget(), env={"BAD=NAME": "x"})
        with self.assertRaises(TypeError):
            run_workload(python("pass"), budget=budget())

    def test_output_capture_cannot_exhaust_runner_memory(self) -> None:
        result = run_workload(
            python("import os;os.write(1,b'x'*(2*1024*1024))"),
            budget=budget(),
            env={},
        )
        self.assertFalse(result.passed)
        self.assertFalse(result.timed_out)
        self.assertIn("output exceeded", result.error or "")
        self.assertLessEqual(len(result.stdout.encode()), 1_048_576)

    def test_workload_cannot_raise_kernel_hard_limits(self) -> None:
        script = (
            "import resource; "
            "cpu=resource.getrlimit(resource.RLIMIT_CPU); "
            "mem=resource.getrlimit(resource.RLIMIT_AS); "
            "print(cpu[1], mem[1]); "
            "blocked=0; "
            "\nfor limit in (resource.RLIMIT_CPU, resource.RLIMIT_AS):"
            "\n try:"
            "\n  resource.setrlimit(limit, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))"
            "\n except (OSError, ValueError):"
            "\n  blocked+=1"
            "\nprint(blocked)"
        )
        result = run_workload(python(script), budget=budget(), env={})
        self.assertTrue(result.command_succeeded, result)
        self.assertEqual(
            [str(2), str(256 * 1024 * 1024)],
            result.stdout.splitlines()[0].split(),
        )
        self.assertEqual("2", result.stdout.splitlines()[1])


if __name__ == "__main__":
    unittest.main()
