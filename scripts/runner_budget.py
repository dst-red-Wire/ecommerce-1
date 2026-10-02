"""Bounded Linux workload execution for a CI runner.

A BudgetedRunner owns one wall-clock deadline and one concurrency limit. Each
workload starts in its own process group. A small Python bootstrap installs
kernel hard limits before replacing itself with the requested executable.
Process groups and per-process limits do not prove containment of hostile forks;
a successful exit therefore yields an INSUFFICIENT proof verdict.
"""

from __future__ import annotations

import math
import os
import resource
import selectors
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, fields
from pathlib import Path

MAX_CAPTURE_BYTES = 1_048_576


@dataclass(frozen=True, slots=True)
class RunnerBudget:
    global_timeout_seconds: float
    subprocess_timeout_seconds: float
    cpu_seconds: int
    memory_bytes: int
    max_concurrency: int

    def __post_init__(self) -> None:
        for name in ("global_timeout_seconds", "subprocess_timeout_seconds"):
            value = getattr(self, name)
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or value <= 0
            ):
                raise ValueError(f"{name} must be a finite positive number")
        for name in ("cpu_seconds", "memory_bytes", "max_concurrency"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if self.max_concurrency > 16:
            raise ValueError("max_concurrency must be between 1 and 16")

    @classmethod
    def from_mapping(cls, values: Mapping[str, object]) -> RunnerBudget:
        """Reject absent and unknown budget fields instead of using defaults."""
        if not isinstance(values, Mapping):
            raise TypeError("runner budget must be a mapping")
        expected = {field.name for field in fields(cls)}
        actual = set(values)
        if actual != expected:
            missing = sorted(expected - actual)
            unknown = sorted(actual - expected)
            raise ValueError(
                f"runner budget fields differ: missing={missing}, unknown={unknown}"
            )
        return cls(**dict(values))


@dataclass(frozen=True, slots=True)
class WorkloadResult:
    argv: tuple[str, ...]
    returncode: int | None
    stdout: str
    stderr: str
    elapsed_seconds: float
    timed_out: bool
    timeout_scope: str | None
    killed_process_group: bool
    error: str | None = None
    verdict: str = field(init=False)

    def __post_init__(self) -> None:
        if self.timed_out:
            value = "TIMEOUT"
        elif self.returncode == 0 and self.error is None:
            value = "INSUFFICIENT"
        else:
            value = "FAIL"
        object.__setattr__(self, "verdict", value)

    @property
    def command_succeeded(self) -> bool:
        return self.returncode == 0 and not self.timed_out and self.error is None

    @property
    def passed(self) -> bool:
        """No PASS is issued until aggregate descendant containment is proven."""
        return self.verdict == "PASS"


def _validate_argv(argv: Sequence[str]) -> tuple[str, ...]:
    if isinstance(argv, (str, bytes)) or not isinstance(argv, Sequence) or not argv:
        raise ValueError("argv must be a non-empty sequence of strings")
    if any(not isinstance(item, str) or not item or "\x00" in item for item in argv):
        raise ValueError("argv entries must be non-empty strings without NUL")
    return tuple(argv)


def _validate_env(env: Mapping[str, str]) -> dict[str, str]:
    if not isinstance(env, Mapping):
        raise TypeError("env must be an explicit mapping")
    copied = dict(env)
    for key, value in copied.items():
        if (
            not isinstance(key, str)
            or not key
            or "=" in key
            or "\x00" in key
            or not isinstance(value, str)
            or "\x00" in value
        ):
            raise ValueError("env must contain only valid string names and values")
    return copied


def _kill_process_group(pid: int) -> bool:
    try:
        os.killpg(pid, signal.SIGKILL)
        return True
    except ProcessLookupError:
        return False


def _bootstrap(argv: list[str]) -> int:
    """Run only in the child, before exec. No parent-side preexec_fn is used."""
    if len(argv) < 4 or argv[0] != "--budget-exec":
        return 125
    try:
        cpu_seconds = int(argv[1])
        memory_bytes = int(argv[2])
        command = argv[3:]
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))
        resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))
        os.execvpe(command[0], command, os.environ)
    except (OSError, ValueError) as exc:
        print(f"runner budget bootstrap failed: {exc}", file=sys.stderr)
        return 126
    return 125


class BudgetedRunner:
    """Execute work under a shared global deadline and concurrency ceiling."""

    def __init__(self, budget: RunnerBudget):
        if not isinstance(budget, RunnerBudget):
            raise TypeError("budget must be a RunnerBudget")
        self.budget = budget
        self._deadline = time.monotonic() + budget.global_timeout_seconds
        self._slots = threading.BoundedSemaphore(budget.max_concurrency)

    def run(
        self,
        argv: Sequence[str],
        *,
        env: Mapping[str, str],
        cwd: str | os.PathLike[str] | None = None,
    ) -> WorkloadResult:
        command = _validate_argv(argv)
        child_env = _validate_env(env)
        started = time.monotonic()

        def expired() -> WorkloadResult:
            return WorkloadResult(
                argv=command,
                returncode=None,
                stdout="",
                stderr="",
                elapsed_seconds=time.monotonic() - started,
                timed_out=True,
                timeout_scope="global",
                killed_process_group=False,
            )

        remaining = self._deadline - time.monotonic()
        if remaining <= 0 or not self._slots.acquire(timeout=remaining):
            return expired()
        try:
            if self._deadline <= time.monotonic():
                return expired()
            child_argv = [
                sys.executable,
                str(Path(__file__).resolve()),
                "--budget-exec",
                str(self.budget.cpu_seconds),
                str(self.budget.memory_bytes),
                *command,
            ]
            try:
                process = subprocess.Popen(
                    child_argv,
                    cwd=cwd,
                    env=child_env,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    start_new_session=True,
                    close_fds=True,
                )
            except OSError as exc:
                return WorkloadResult(
                    argv=command,
                    returncode=None,
                    stdout="",
                    stderr="",
                    elapsed_seconds=time.monotonic() - started,
                    timed_out=False,
                    timeout_scope=None,
                    killed_process_group=False,
                    error=f"workload launch failed: {exc}",
                )

            launched = time.monotonic()
            child_deadline = launched + self.budget.subprocess_timeout_seconds
            deadline = min(self._deadline, child_deadline)
            scope = "global" if self._deadline <= child_deadline else "subprocess"
            timed_out = False
            output_exceeded = False
            killed = False
            captured = {"stdout": bytearray(), "stderr": bytearray()}
            captured_bytes = 0
            try:
                with selectors.DefaultSelector() as selector:
                    assert process.stdout is not None and process.stderr is not None
                    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
                    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
                    while selector.get_map():
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            timed_out = True
                            break
                        ready = selector.select(remaining)
                        if not ready:
                            timed_out = True
                            break
                        for key, _ in ready:
                            chunk = os.read(key.fileobj.fileno(), 65_536)
                            if not chunk:
                                selector.unregister(key.fileobj)
                                continue
                            allowance = MAX_CAPTURE_BYTES - captured_bytes
                            if len(chunk) > allowance:
                                captured[key.data].extend(chunk[:allowance])
                                output_exceeded = True
                                break
                            captured[key.data].extend(chunk)
                            captured_bytes += len(chunk)
                        if output_exceeded:
                            break
                    if not timed_out and not output_exceeded:
                        try:
                            process.wait(timeout=max(0, deadline - time.monotonic()))
                        except subprocess.TimeoutExpired:
                            timed_out = True
            finally:
                if timed_out or output_exceeded:
                    killed = _kill_process_group(process.pid)
                if process.stdout is not None:
                    process.stdout.close()
                if process.stderr is not None:
                    process.stderr.close()
                if process.poll() is None:
                    try:
                        process.wait(timeout=1)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
                # A command can exit after leaving children in its process group.
                killed = _kill_process_group(process.pid) or killed
            return WorkloadResult(
                argv=command,
                returncode=process.returncode,
                stdout=captured["stdout"].decode("utf-8", errors="replace"),
                stderr=captured["stderr"].decode("utf-8", errors="replace"),
                elapsed_seconds=time.monotonic() - started,
                timed_out=timed_out,
                timeout_scope=scope if timed_out else None,
                killed_process_group=killed,
                error=(
                    f"workload output exceeded {MAX_CAPTURE_BYTES} bytes"
                    if output_exceeded
                    else None
                ),
            )
        finally:
            self._slots.release()


def run_workload(
    argv: Sequence[str],
    *,
    budget: RunnerBudget,
    env: Mapping[str, str],
    cwd: str | os.PathLike[str] | None = None,
) -> WorkloadResult:
    """Convenience wrapper for one workload under an explicit budget."""
    return BudgetedRunner(budget).run(argv, env=env, cwd=cwd)


if __name__ == "__main__":
    raise SystemExit(_bootstrap(sys.argv[1:]))
