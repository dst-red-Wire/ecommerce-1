"""Transactional runtime preparation for repository qualification gates.

The policy lives in ``config/contracts/qualification-execution-policy.yaml``.
This module only implements its detector/planner/executor mechanics.  It never
installs tools, provisions external resources, or changes production state.
"""

from __future__ import annotations

import fcntl
import json
import os
import re
import shutil
import signal
import subprocess
import tempfile
import time
import uuid
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import ClassVar, Protocol, Self


class RuntimePolicyError(RuntimeError):
    """The central runtime contract is invalid or cannot be resolved."""


class RuntimeBlocked(RuntimeError):
    """The runner cannot satisfy a capability without an unsafe mutation."""


class RuntimeVerificationError(RuntimeError):
    """Preparation or restoration did not reach the required state."""


class RuntimeInterrupted(KeyboardInterrupt):
    """A termination signal interrupted the runtime transaction."""


@dataclass(frozen=True)
class CapabilityRequest:
    name: str
    parameters: Mapping[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class CapabilitySpec:
    name: str
    handler: str
    requires: tuple[str, ...]
    mutation_class: str
    timeout_seconds: int
    privilege: str
    global_lock: bool
    operations: Mapping[str, str]
    evidence_fields: tuple[str, ...]
    default_parameters: Mapping[str, object]


@dataclass(frozen=True)
class PlannedCapability:
    spec: CapabilitySpec
    parameters: Mapping[str, object]


@dataclass(frozen=True)
class RuntimeRunResult:
    status: str
    exit_code: int
    evidence_path: Path | None
    environment: Mapping[str, str]


class CapabilityDriver(Protocol):
    def capture(self, capability: PlannedCapability) -> dict: ...

    def preflight(
        self, capability: PlannedCapability, initial_state: Mapping[str, object]
    ) -> dict: ...

    def prepare(
        self, capability: PlannedCapability, initial_state: Mapping[str, object]
    ) -> tuple[dict, dict[str, str]]: ...

    def verify(
        self, capability: PlannedCapability, prepared_state: Mapping[str, object]
    ) -> dict: ...

    def restore(
        self, capability: PlannedCapability, initial_state: Mapping[str, object]
    ) -> dict: ...

    def verify_restore(
        self, capability: PlannedCapability, initial_state: Mapping[str, object]
    ) -> dict: ...


_SENSITIVE_KEY = re.compile(
    r"(?:token|password|passwd|secret|credential|private[_-]?key|kubeconfig|dockerconfig|database[_-]?url)",
    re.IGNORECASE,
)


def redact(value: object) -> object:
    """Recursively remove secret-shaped values before they reach evidence."""
    if isinstance(value, Mapping):
        return {
            str(key): "[REDACTED]" if _SENSITIVE_KEY.search(str(key)) else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact(item) for item in value]
    return value


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _atomic_json(path: Path, payload: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(redact(payload), handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


class RuntimePlanner:
    """Validate and resolve the central capability DAG deterministically."""

    ALLOWED_MUTATION_CLASSES: ClassVar[set[str]] = {
        "none",
        "local-ephemeral",
        "local-virtualization",
        "external-governed",
        "production-governed",
    }
    ALLOWED_HANDLERS: ClassVar[set[str]] = {
        "dependency",
        "docker-rootless",
        "ip-forward",
        "command",
        "wsl-interop",
        "memory",
        "cpu",
        "disk",
        "kubernetes-context",
    }

    def __init__(self, runtime_policy: Mapping[str, object]) -> None:
        self.policy = runtime_policy
        raw_registry = runtime_policy.get("capabilities")
        if not isinstance(raw_registry, Mapping) or not raw_registry:
            raise RuntimePolicyError(
                "runtime orchestration must declare a capability registry"
            )
        self.specs: dict[str, CapabilitySpec] = {}
        for name, raw in raw_registry.items():
            if not isinstance(name, str) or not name or not isinstance(raw, Mapping):
                raise RuntimePolicyError(
                    "runtime capability registry contains an invalid entry"
                )
            requires = raw.get("requires", [])
            operations = raw.get("operations", {})
            evidence_fields = raw.get("evidence_fields", [])
            timeout = raw.get("timeout_seconds")
            mutation_class = raw.get("mutation_class")
            handler = raw.get("handler")
            if (
                not isinstance(requires, list)
                or any(not isinstance(item, str) or not item for item in requires)
                or len(requires) != len(set(requires))
                or not isinstance(operations, Mapping)
                or not isinstance(evidence_fields, list)
                or any(
                    not isinstance(item, str) or not item for item in evidence_fields
                )
                or type(timeout) is not int
                or not 1 <= timeout <= 600
                or mutation_class not in self.ALLOWED_MUTATION_CLASSES
                or handler not in self.ALLOWED_HANDLERS
            ):
                raise RuntimePolicyError(
                    f"runtime capability {name} has an invalid contract"
                )
            if (
                mutation_class in {"external-governed", "production-governed"}
                and operations.get("prepare") != "readonly"
            ):
                raise RuntimePolicyError(
                    f"runtime capability {name} must be prepare-readonly"
                )
            if (
                mutation_class != "none"
                and mutation_class not in {"external-governed", "production-governed"}
                and (
                    operations.get("restore") in {None, "none"}
                    or operations.get("verify_restore") in {None, "none"}
                )
            ):
                raise RuntimePolicyError(
                    f"mutable runtime capability {name} must restore and verify restore"
                )
            self.specs[name] = CapabilitySpec(
                name=name,
                handler=str(handler),
                requires=tuple(requires),
                mutation_class=str(mutation_class),
                timeout_seconds=timeout,
                privilege=str(raw.get("privilege", "none")),
                global_lock=raw.get("global_lock") is True,
                operations={str(key): str(value) for key, value in operations.items()},
                evidence_fields=tuple(evidence_fields),
                default_parameters=dict(raw.get("parameters", {}))
                if isinstance(raw.get("parameters", {}), Mapping)
                else {},
            )
        for spec in self.specs.values():
            unknown = sorted(set(spec.requires) - set(self.specs))
            if unknown:
                raise RuntimePolicyError(
                    f"runtime capability {spec.name} requires unknown capabilities: {unknown}"
                )
        self._validate_acyclic()

    def _validate_acyclic(self) -> None:
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(name: str, trail: tuple[str, ...]) -> None:
            if name in visiting:
                raise RuntimePolicyError(
                    "runtime capability cycle: " + " -> ".join((*trail, name))
                )
            if name in visited:
                return
            visiting.add(name)
            for dependency in self.specs[name].requires:
                visit(dependency, (*trail, name))
            visiting.remove(name)
            visited.add(name)

        for name in sorted(self.specs):
            visit(name, ())

    @staticmethod
    def _merge_parameters(
        current: dict[str, object], incoming: Mapping[str, object], name: str
    ) -> None:
        for key, value in incoming.items():
            if key not in current:
                current[key] = value
            elif (
                key.startswith("minimum_")
                and isinstance(current[key], (int, float))
                and isinstance(value, (int, float))
            ):
                current[key] = max(current[key], value)
            elif current[key] != value:
                raise RuntimePolicyError(
                    f"conflicting runtime parameters for {name}.{key}"
                )

    def resolve(self, requests: Iterable[CapabilityRequest]) -> list[PlannedCapability]:
        parameters: dict[str, dict[str, object]] = {}
        requested: set[str] = set()
        for request in requests:
            if request.name not in self.specs:
                raise RuntimePolicyError(f"unknown runtime capability: {request.name}")
            requested.add(request.name)
            self._merge_parameters(
                parameters.setdefault(request.name, {}),
                request.parameters,
                request.name,
            )

        ordered: list[str] = []
        visited: set[str] = set()

        def add(name: str) -> None:
            if name in visited:
                return
            for dependency in self.specs[name].requires:
                add(dependency)
            visited.add(name)
            ordered.append(name)

        for name in sorted(requested):
            add(name)
        planned: list[PlannedCapability] = []
        for name in ordered:
            merged = dict(self.specs[name].default_parameters)
            self._merge_parameters(merged, parameters.get(name, {}), name)
            planned.append(PlannedCapability(self.specs[name], merged))
        return planned


class BuiltinCapabilityDriver:
    """Bounded local detectors and reversible prepare/restore operations."""

    def __init__(self, environment: Mapping[str, str] | None = None) -> None:
        self.environment = dict(environment or os.environ)

    @staticmethod
    def _run(
        command: list[str], *, env: Mapping[str, str] | None = None, timeout: int = 30
    ) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(
                command,
                check=False,
                text=True,
                capture_output=True,
                env=dict(env) if env is not None else None,
                timeout=timeout,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            return subprocess.CompletedProcess(command, 127, "", type(exc).__name__)

    @staticmethod
    def _int_parameter(capability: PlannedCapability, key: str) -> int:
        value = capability.parameters.get(key)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise RuntimeBlocked(
                f"{capability.spec.name} requires integer parameter {key}"
            )
        return value

    def _docker_env(self) -> dict[str, str]:
        env = dict(self.environment)
        if not env.get("DOCKER_HOST"):
            runtime_dir = env.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}"
            env["DOCKER_HOST"] = f"unix://{runtime_dir}/docker.sock"
        return env

    def _docker_info(
        self, env: Mapping[str, str] | None = None, timeout: int = 30
    ) -> bool:
        docker = shutil.which("docker", path=(env or self.environment).get("PATH"))
        return (
            bool(docker)
            and self._run([docker, "info"], env=env, timeout=timeout).returncode == 0
        )

    def _docker_service_state(self) -> dict[str, object]:
        result = self._run(
            [
                "systemctl",
                "--user",
                "show",
                "docker.service",
                "-p",
                "LoadState",
                "-p",
                "ActiveState",
                "-p",
                "SubState",
            ]
        )
        values: dict[str, str] = {}
        for line in result.stdout.splitlines():
            key, separator, value = line.partition("=")
            if separator:
                values[key] = value
        return {
            "manager_reachable": result.returncode == 0,
            "load_state": values.get("LoadState", "unknown"),
            "active_state": values.get("ActiveState", "unknown"),
            "sub_state": values.get("SubState", "unknown"),
        }

    def _command_probe(
        self, capability: PlannedCapability
    ) -> tuple[list[str], subprocess.CompletedProcess[str]]:
        raw_commands = capability.parameters.get("commands")
        if raw_commands is None:
            raw_commands = [capability.parameters.get("command")]
        if (
            not isinstance(raw_commands, list)
            or not raw_commands
            or any(
                not isinstance(command, list)
                or not command
                or any(not isinstance(item, str) for item in command)
                for command in raw_commands
            )
        ):
            raise RuntimeBlocked(
                f"{capability.spec.name} has no resolved command probe"
            )
        last_result: subprocess.CompletedProcess[str] | None = None
        for command in raw_commands:
            result = self._run(list(command), timeout=capability.spec.timeout_seconds)
            last_result = result
            if result.returncode == 0:
                return list(command), result
        assert last_result is not None
        return list(raw_commands[-1]), last_result

    def capture(self, capability: PlannedCapability) -> dict:
        handler = capability.spec.handler
        if handler == "dependency":
            return {"satisfied": True}
        if handler == "docker-rootless":
            service = self._docker_service_state()
            current_ready = self._docker_info(
                self.environment, capability.spec.timeout_seconds
            )
            candidate_env = self._docker_env()
            candidate_ready = current_ready or self._docker_info(
                candidate_env, capability.spec.timeout_seconds
            )
            return {
                "satisfied": candidate_ready,
                "runtime": "existing" if current_ready else "rootless-user-service",
                "requires_docker_host": candidate_ready and not current_ready,
                "service_active": service["active_state"] == "active",
                "service_state": service["active_state"],
                "service_loaded": service["load_state"] == "loaded",
                "manager_reachable": service["manager_reachable"],
                "socket_present": Path(
                    candidate_env["DOCKER_HOST"].removeprefix("unix://")
                ).exists(),
            }
        if handler == "ip-forward":
            result = self._run(
                ["sysctl", "-n", "net.ipv4.ip_forward"],
                timeout=capability.spec.timeout_seconds,
            )
            value = result.stdout.strip()
            return {
                "satisfied": result.returncode == 0 and value == "1",
                "value": value,
                "readable": result.returncode == 0,
            }
        if handler == "memory":
            values: dict[str, int] = {}
            try:
                for line in (
                    Path("/proc/meminfo").read_text(encoding="utf-8").splitlines()
                ):
                    key, raw = line.split(":", 1)
                    if key in {"MemTotal", "MemAvailable"}:
                        values[key] = int(raw.split()[0]) // 1024
            except (OSError, ValueError, IndexError):
                pass
            return {
                "total_mib": values.get("MemTotal", 0),
                "available_mib": values.get("MemAvailable", 0),
            }
        if handler == "cpu":
            return {"available_count": os.cpu_count() or 0}
        if handler == "disk":
            path = str(capability.parameters.get("path", "."))
            try:
                usage = shutil.disk_usage(path)
                return {"path": path, "available_mib": usage.free // (1024 * 1024)}
            except OSError:
                return {"path": path, "available_mib": 0}
        if handler == "wsl-interop":
            command = capability.parameters.get(
                "command", "/mnt/c/Windows/System32/cmd.exe"
            )
            result = self._run(
                [str(command), "/c", "exit", "0"],
                timeout=capability.spec.timeout_seconds,
            )
            return {
                "satisfied": result.returncode == 0,
                "wsl": bool(os.environ.get("WSL_INTEROP")),
            }
        if handler in {"command", "kubernetes-context"}:
            command, result = self._command_probe(capability)
            expected = capability.parameters.get("expected_stdout")
            output_matches = expected is None or result.stdout.strip() == expected
            return {
                "satisfied": result.returncode == 0 and output_matches,
                "command": command[0],
                "exit_code": result.returncode,
                "output_matches": output_matches,
            }
        raise RuntimePolicyError(f"unsupported runtime handler: {handler}")

    def preflight(
        self, capability: PlannedCapability, initial_state: Mapping[str, object]
    ) -> dict:
        handler = capability.spec.handler
        if handler == "docker-rootless" and initial_state.get("satisfied") is not True:
            if shutil.which("docker") is None:
                raise RuntimeBlocked("docker-runtime: Docker client is unavailable")
            if self.environment.get("DOCKER_HOST"):
                raise RuntimeBlocked(
                    "docker-runtime: configured Docker endpoint is unreachable and is not owned by this run"
                )
            if (
                initial_state.get("manager_reachable") is not True
                or initial_state.get("service_loaded") is not True
            ):
                raise RuntimeBlocked(
                    "docker-runtime: rootless docker user service is not installed/reachable"
                )
            if initial_state.get("service_active") is True:
                raise RuntimeBlocked(
                    "docker-runtime: active rootless service is unreachable and is not safe to restart"
                )
        elif handler == "ip-forward":
            if initial_state.get("readable") is not True or initial_state.get(
                "value"
            ) not in {"0", "1"}:
                raise RuntimeBlocked(
                    "ip-forward: net.ipv4.ip_forward is unreadable or invalid"
                )
            if (
                initial_state.get("value") == "0"
                and os.geteuid() != 0
                and self._run(
                    ["sudo", "-n", "true"], timeout=capability.spec.timeout_seconds
                ).returncode
                != 0
            ):
                raise RuntimeBlocked(
                    "ip-forward: non-interactive privilege is unavailable"
                )
        elif handler == "memory":
            required = self._int_parameter(capability, "minimum_mib")
            if int(initial_state.get("available_mib", 0)) < required:
                raise RuntimeBlocked(
                    f"memory-capacity: required={required}MiB available={initial_state.get('available_mib', 0)}MiB"
                )
        elif handler == "cpu":
            required = self._int_parameter(capability, "minimum_count")
            if int(initial_state.get("available_count", 0)) < required:
                raise RuntimeBlocked(
                    f"cpu-capacity: required={required} available={initial_state.get('available_count', 0)}"
                )
        elif handler == "disk":
            required = self._int_parameter(capability, "minimum_mib")
            if int(initial_state.get("available_mib", 0)) < required:
                raise RuntimeBlocked(
                    f"disk-capacity: required={required}MiB available={initial_state.get('available_mib', 0)}MiB"
                )
        elif (
            handler in {"command", "wsl-interop", "kubernetes-context"}
            and initial_state.get("satisfied") is not True
        ):
            raise RuntimeBlocked(
                f"{capability.spec.name}: required runtime is unavailable"
            )
        return {
            "status": "PASS",
            "mutation_required": self._mutation_required(capability, initial_state),
        }

    @staticmethod
    def _mutation_required(
        capability: PlannedCapability, initial_state: Mapping[str, object]
    ) -> bool:
        if capability.spec.handler == "docker-rootless":
            return (
                initial_state.get("satisfied") is not True
                and initial_state.get("service_active") is not True
            )
        return (
            capability.spec.handler == "ip-forward"
            and initial_state.get("satisfied") is not True
        )

    def prepare(
        self, capability: PlannedCapability, initial_state: Mapping[str, object]
    ) -> tuple[dict, dict[str, str]]:
        if not self._mutation_required(capability, initial_state):
            updates = {}
            if (
                capability.spec.handler == "docker-rootless"
                and initial_state.get("requires_docker_host") is True
            ):
                updates["DOCKER_HOST"] = self._docker_env()["DOCKER_HOST"]
            return dict(initial_state), updates
        if capability.spec.handler == "docker-rootless":
            result = self._run(
                ["systemctl", "--user", "start", "docker.service"],
                timeout=capability.spec.timeout_seconds,
            )
            if result.returncode != 0:
                raise RuntimeVerificationError(
                    "docker-runtime: failed to start rootless user service"
                )
            env = self._docker_env()
            deadline = time.monotonic() + capability.spec.timeout_seconds
            while time.monotonic() < deadline:
                if self._docker_info(env, capability.spec.timeout_seconds):
                    state = self.capture(capability)
                    state.update(
                        {
                            "satisfied": True,
                            "service_active": True,
                            "service_state": "active",
                        }
                    )
                    return state, {"DOCKER_HOST": env["DOCKER_HOST"]}
                time.sleep(0.2)
            raise RuntimeVerificationError(
                "docker-runtime: rootless daemon did not become ready before timeout"
            )
        if capability.spec.handler == "ip-forward":
            prefix = [] if os.geteuid() == 0 else ["sudo", "-n"]
            result = self._run(
                [*prefix, "sysctl", "-w", "net.ipv4.ip_forward=1"],
                timeout=capability.spec.timeout_seconds,
            )
            if result.returncode != 0:
                raise RuntimeVerificationError(
                    "ip-forward: failed to enable forwarding"
                )
            return {"satisfied": True, "value": "1", "readable": True}, {}
        raise RuntimePolicyError(
            f"{capability.spec.name}: prepare requested for a non-mutable handler"
        )

    def verify(
        self, capability: PlannedCapability, prepared_state: Mapping[str, object]
    ) -> dict:
        if capability.spec.handler == "docker-rootless":
            env = self._docker_env()
            if not self._docker_info(env, capability.spec.timeout_seconds):
                raise RuntimeVerificationError(
                    "docker-runtime: docker info failed after prepare"
                )
        elif capability.spec.handler == "ip-forward":
            current = self.capture(capability)
            if current.get("value") != "1":
                raise RuntimeVerificationError(
                    "ip-forward: forwarding is not enabled after prepare"
                )
        elif capability.spec.handler in {
            "command",
            "wsl-interop",
            "kubernetes-context",
            "memory",
            "cpu",
            "disk",
        }:
            current = self.capture(capability)
            self.preflight(capability, current)
        return {"status": "PASS"}

    def restore(
        self, capability: PlannedCapability, initial_state: Mapping[str, object]
    ) -> dict:
        if (
            capability.spec.handler == "docker-rootless"
            and initial_state.get("satisfied") is not True
        ):
            result = self._run(
                ["systemctl", "--user", "stop", "docker.service"],
                timeout=capability.spec.timeout_seconds,
            )
            if result.returncode != 0:
                raise RuntimeVerificationError(
                    "docker-runtime: failed to restore stopped rootless service"
                )
            return {"action": "stop-user-service"}
        if (
            capability.spec.handler == "ip-forward"
            and initial_state.get("value") == "0"
        ):
            prefix = [] if os.geteuid() == 0 else ["sudo", "-n"]
            result = self._run(
                [*prefix, "sysctl", "-w", "net.ipv4.ip_forward=0"],
                timeout=capability.spec.timeout_seconds,
            )
            if result.returncode != 0:
                raise RuntimeVerificationError(
                    "ip-forward: failed to restore initial value"
                )
            return {"action": "restore", "value": "0"}
        return {"action": "none"}

    def verify_restore(
        self, capability: PlannedCapability, initial_state: Mapping[str, object]
    ) -> dict:
        if capability.spec.handler == "docker-rootless":
            state = self._docker_service_state()
            expected_active = initial_state.get("service_active") is True
            actual_active = state.get("active_state") == "active"
            if actual_active != expected_active:
                raise RuntimeVerificationError(
                    "docker-runtime: service state differs from captured state"
                )
            return {
                "status": "PASS",
                "service_active": actual_active,
                "service_state": state.get("active_state"),
                "service_loaded": state.get("load_state") == "loaded",
                "manager_reachable": state.get("manager_reachable"),
                "socket_present": Path(
                    self._docker_env()["DOCKER_HOST"].removeprefix("unix://")
                ).exists(),
            }
        elif capability.spec.handler == "ip-forward":
            state = self.capture(capability)
            if state.get("value") != initial_state.get("value"):
                raise RuntimeVerificationError(
                    "ip-forward: final value differs from captured state"
                )
            return {"status": "PASS", **state}
        return {"status": "PASS"}


class RuntimeLock:
    def __init__(self, path: Path, timeout_seconds: int) -> None:
        self.path = path
        self.timeout_seconds = timeout_seconds
        self._handle = None

    def __enter__(self) -> Self:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._handle = self.path.open("a+", encoding="utf-8")
        deadline = time.monotonic() + self.timeout_seconds
        while True:
            try:
                fcntl.flock(self._handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                return self
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    self._handle.close()
                    self._handle = None
                    raise RuntimeBlocked("runtime orchestration lock timeout")
                time.sleep(0.1)

    def __exit__(self, *_args: object) -> None:
        if self._handle is not None:
            fcntl.flock(self._handle.fileno(), fcntl.LOCK_UN)
            self._handle.close()
            self._handle = None


class RuntimeExecutor:
    """Execute one compensating runtime transaction around existing gates."""

    def __init__(
        self,
        root: Path,
        runtime_policy: Mapping[str, object],
        *,
        driver: CapabilityDriver | None = None,
        lock_factory: Callable[[Path, int], RuntimeLock] = RuntimeLock,
    ) -> None:
        self.root = root
        self.policy = runtime_policy
        self.planner = RuntimePlanner(runtime_policy)
        self.driver = driver or BuiltinCapabilityDriver()
        self.lock_factory = lock_factory

    def _filter_state(
        self, capability: PlannedCapability, state: Mapping[str, object]
    ) -> dict:
        allowed = {*capability.spec.evidence_fields, "status"}
        return {key: value for key, value in state.items() if key in allowed}

    def _stale_runs(self, evidence_root: Path, current_path: Path) -> list[str]:
        stale: list[str] = []
        if not evidence_root.is_dir():
            return stale
        for path in evidence_root.glob("*.json"):
            if path == current_path:
                continue
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if payload.get("status") == "RUNNING" and isinstance(
                payload.get("run_id"), str
            ):
                stale.append(payload["run_id"])
        return sorted(stale)

    def execute(
        self,
        requests: Iterable[CapabilityRequest],
        execute_gates: Callable[[dict[str, str]], int],
        *,
        workflow: str,
        source_kind: str,
        source_sha: str,
        selected_gates: Iterable[str],
        base_environment: Mapping[str, str] | None = None,
        authoritative: bool = False,
        gate_results: Callable[[], object] | None = None,
    ) -> RuntimeRunResult:
        plan = self.planner.resolve(requests)
        environment = dict(base_environment or os.environ)
        if not plan:
            environment["ECOMMERCE_RUNTIME_ORCHESTRATED"] = "1"
            code = execute_gates(environment)
            return RuntimeRunResult(
                "PASS" if code == 0 else "FAIL",
                code,
                None,
                environment,
            )

        run_id = f"{int(time.time())}-{os.getpid()}-{uuid.uuid4().hex[:8]}"
        evidence_root = (
            self.root
            / str(self.policy["rules"]["evidence_root"])
            / "runtime"
            / "orchestration"
        )
        evidence_path = evidence_root / f"{run_id}.json"
        payload: dict[str, object] = {
            "schema_version": 1,
            "run_id": run_id,
            "workflow": workflow,
            "source_kind": source_kind,
            "source_sha": source_sha,
            "authoritative": authoritative and source_kind == "exact-sha",
            "selected_gates": sorted(set(selected_gates)),
            "required_capabilities": [item.spec.name for item in plan],
            "dependency_plan": [
                {"capability": item.spec.name, "requires": list(item.spec.requires)}
                for item in plan
            ],
            "initial_state": {},
            "preflight": {},
            "changes_applied": [],
            "prepared_state": {},
            "gate_results": [],
            "restore_attempted": False,
            "restore_actions": [],
            "final_state": {},
            "restore_verified": False,
            "stale_runs_detected": [],
            "status": "RUNNING",
            "started_at": _utc_now(),
            "completed_at": None,
        }
        evidence_path.parent.mkdir(parents=True, exist_ok=True)
        payload["stale_runs_detected"] = self._stale_runs(evidence_root, evidence_path)
        _atomic_json(evidence_path, payload)

        lock_cfg = self.policy.get("lock", {})
        lock_required = any(item.spec.global_lock for item in plan)
        lock_path = self.root / str(
            lock_cfg.get("path", ".context/runtime/orchestration.lock")
        )
        lock_timeout = int(lock_cfg.get("timeout_seconds", 30))
        lock = (
            self.lock_factory(lock_path, lock_timeout) if lock_required else _NullLock()
        )
        initial: dict[str, dict] = {}
        prepared: list[PlannedCapability] = []
        preflight_results: dict[str, dict] = {}
        exit_code = 1
        restore_failures: list[str] = []
        previous_sigterm = None

        def terminate(_signum: int, _frame: object) -> None:
            raise RuntimeInterrupted("SIGTERM")

        try:
            with lock:
                if signal.getsignal(signal.SIGTERM) is not None:
                    previous_sigterm = signal.getsignal(signal.SIGTERM)
                    signal.signal(signal.SIGTERM, terminate)
                try:
                    for capability in plan:
                        state = self.driver.capture(capability)
                        initial[capability.spec.name] = state
                        payload["initial_state"][capability.spec.name] = (
                            self._filter_state(capability, state)
                        )
                    _atomic_json(evidence_path, payload)

                    # This complete loop is deliberately separate from prepare.
                    for capability in plan:
                        result = self.driver.preflight(
                            capability, initial[capability.spec.name]
                        )
                        preflight_results[capability.spec.name] = result
                        payload["preflight"][capability.spec.name] = result
                    _atomic_json(evidence_path, payload)

                    for capability in plan:
                        if (
                            preflight_results[capability.spec.name].get(
                                "mutation_required"
                            )
                            is True
                        ):
                            # Claim compensation ownership before prepare so a partial
                            # prepare failure is still rolled back.
                            prepared.append(capability)
                        state, updates = self.driver.prepare(
                            capability, initial[capability.spec.name]
                        )
                        environment.update(updates)
                        if (
                            preflight_results[capability.spec.name].get(
                                "mutation_required"
                            )
                            is True
                        ):
                            payload["changes_applied"].append(
                                {
                                    "capability": capability.spec.name,
                                    "owner": run_id,
                                    "resource_existed_before": True,
                                    "state_satisfied_before": initial[
                                        capability.spec.name
                                    ].get("satisfied")
                                    is True,
                                }
                            )
                        payload["prepared_state"][capability.spec.name] = (
                            self._filter_state(capability, state)
                        )
                        self.driver.verify(capability, state)
                    _atomic_json(evidence_path, payload)

                    environment["ECOMMERCE_RUNTIME_ORCHESTRATED"] = "1"
                    environment["ECOMMERCE_RUNTIME_RUN_ID"] = run_id
                    exit_code = execute_gates(environment)
                    payload["gate_results"] = gate_results() if gate_results else []
                    payload["status"] = "PASS" if exit_code == 0 else "FAIL"
                except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 -- transaction boundary must compensate arbitrary gate failures
                    if isinstance(exc, RuntimeBlocked):
                        payload["status"] = "BLOCKED_RUNTIME"
                        exit_code = 2
                    elif isinstance(exc, (KeyboardInterrupt, RuntimeInterrupted)):
                        payload["status"] = "INTERRUPTED"
                        exit_code = 130
                    else:
                        payload["status"] = "FAIL"
                        exit_code = 1
                    payload["failure"] = {
                        "type": type(exc).__name__,
                        "message": str(exc),
                    }
                finally:
                    payload["gate_results"] = (
                        gate_results() if gate_results else payload["gate_results"]
                    )
                    payload["restore_attempted"] = True
                    for capability in reversed(prepared):
                        try:
                            action = self.driver.restore(
                                capability, initial[capability.spec.name]
                            )
                            payload["restore_actions"].append(
                                {"capability": capability.spec.name, **action}
                            )
                        except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 -- attempt every compensation
                            restore_failures.append(
                                f"{capability.spec.name}: restore: {exc}"
                            )
                    for capability in reversed(plan):
                        if capability.spec.name not in initial:
                            continue
                        try:
                            result = self.driver.verify_restore(
                                capability, initial[capability.spec.name]
                            )
                            payload["final_state"][capability.spec.name] = (
                                self._filter_state(capability, result)
                            )
                        except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 -- collect every restore verification failure
                            restore_failures.append(
                                f"{capability.spec.name}: verify_restore: {exc}"
                            )
                    payload["restore_verified"] = not restore_failures
                    if restore_failures:
                        payload["status"] = "FAIL_RESTORE"
                        payload["restore_failures"] = restore_failures
                        exit_code = 1
                    payload["completed_at"] = _utc_now()
                    _atomic_json(evidence_path, payload)
                if previous_sigterm is not None:
                    signal.signal(signal.SIGTERM, previous_sigterm)
        except RuntimeBlocked as exc:
            payload["status"] = "BLOCKED_RUNTIME"
            payload["failure"] = {"type": type(exc).__name__, "message": str(exc)}
            payload["completed_at"] = _utc_now()
            _atomic_json(evidence_path, payload)
            exit_code = 2
        finally:
            if previous_sigterm is not None:
                signal.signal(signal.SIGTERM, previous_sigterm)

        # Preserve ordinary gate exceptions as status/evidence; callers consume the code.
        return RuntimeRunResult(
            str(payload["status"]), exit_code, evidence_path, environment
        )


class _NullLock:
    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_args: object) -> None:
        return None


def validate_runtime_policy(runtime_policy: Mapping[str, object]) -> None:
    """Validate single-authority invariants without touching runner state."""
    if (
        runtime_policy.get("enabled") is not True
        or runtime_policy.get("single_authority") is not True
    ):
        raise RuntimePolicyError(
            "runtime orchestration must be enabled under one authority"
        )
    expected_lifecycle = [
        "resolve",
        "capture",
        "preflight",
        "prepare",
        "verify",
        "execute",
        "restore",
        "verify_restore",
        "evidence",
    ]
    if runtime_policy.get("lifecycle") != expected_lifecycle:
        raise RuntimePolicyError("runtime orchestration lifecycle is invalid")
    if runtime_policy.get("mutation_classes") != [
        "none",
        "local-ephemeral",
        "local-virtualization",
        "external-governed",
        "production-governed",
    ]:
        raise RuntimePolicyError("runtime orchestration mutation classes are invalid")
    rules = runtime_policy.get("rules")
    if not isinstance(rules, Mapping):
        raise RuntimePolicyError("runtime orchestration rules are missing")
    required_rules = {
        "preflight_before_mutation": "required",
        "capture_initial_state": "required",
        "bounded_mutations": "required",
        "restore_on_success": "required",
        "restore_on_failure": "required",
        "restore_on_interrupt": "required",
        "restore_verification": "required",
        "fail_on_restore_failure": "required",
        "tracked_source_mutation_for_evidence": "forbidden",
        "evidence_root": ".context",
        "secrets_in_evidence": "forbidden",
        "dynamic_state_cache": "forbidden",
    }
    if any(rules.get(key) != value for key, value in required_rules.items()):
        raise RuntimePolicyError("runtime orchestration safety rules are invalid")
    if (
        runtime_policy.get("external_paid_resources", {}).get("implicit_creation")
        != "forbidden"
    ):
        raise RuntimePolicyError("external paid resource creation must be forbidden")
    if runtime_policy.get("production", {}).get("implicit_mutation") != "forbidden":
        raise RuntimePolicyError("implicit production mutation must be forbidden")
    if runtime_policy.get("production", {}).get("prepare_default") not in {
        None,
        "readonly",
    }:
        raise RuntimePolicyError(
            "production runtime preparation must default to readonly"
        )
    lock = runtime_policy.get("lock")
    if (
        not isinstance(lock, Mapping)
        or lock.get("path") != ".context/runtime/orchestration.lock"
        or type(lock.get("timeout_seconds")) is not int
        or not 1 <= lock["timeout_seconds"] <= 300
    ):
        raise RuntimePolicyError("runtime orchestration lock policy is invalid")
    RuntimePlanner(runtime_policy)
