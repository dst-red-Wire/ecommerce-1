"""Bounded, offline VirtualBox lifecycle reconciliation. Runtime state stays in .context."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import yaml

METRIC_NAMES = (
    "image_build_seconds",
    "clone_seconds",
    "power_on_to_running_seconds",
    "running_to_tcp22_seconds",
    "tcp22_to_ssh_seconds",
    "ssh_to_os_ready_seconds",
    "provision_seconds",
    "reboot_to_ssh_seconds",
    "destroy_seconds",
    "rebuild_count",
    "reboot_count",
    "reload_count",
    "reprovision_count",
    "timeout_count",
    "destructive_retry_count",
)
CHECKPOINTS = (
    "created",
    "booted",
    "ssh-ready",
    "os-ready",
    "provisioned",
    "reboot-required",
    "rebooted",
    "service-ready",
    "qualified",
)


class LifecycleError(RuntimeError):
    def __init__(self, code: str, detail: str):
        self.code = code
        super().__init__(detail)


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as source:
        for part in iter(lambda: source.read(1024 * 1024), b""):
            h.update(part)
    return h.hexdigest()


def image_fingerprint(root: Path, config: dict, iso_digest: str) -> str:
    """Hash only immutable image inputs; ephemeral SSH credentials are excluded."""
    inputs = [
        "platform/packer/rocky-10.2/rocky-10.2.pkr.hcl",
        "platform/packer/rocky-10.2/http/rocky-10.2.ks",
        "scripts/install_packer_tools.py",
        "config/contracts/machine-image-lock.yaml",
        "config/contracts/toolchain-lock.json",
        "config/artifacts/rocky-10.2-base-packages.lock.json",
    ]
    inputs += config.get("image_inputs", [])
    if len(inputs) != len(set(inputs)):
        raise LifecycleError("PACKER_INPUT_INVALID", "duplicate image input")
    records = {"iso_sha256": iso_digest, "profile": config["image_profile"]}
    hashed = {}

    def file_digest(path: Path) -> str:
        if path not in hashed:
            hashed[path] = digest(path)
        return hashed[path]

    for name in sorted(inputs):
        path = (root / name).resolve()
        if not path.is_relative_to(root.resolve()) or not path.is_file():
            raise LifecycleError(
                "PACKER_INPUT_INVALID", f"missing or external image input: {name}"
            )
        records[name] = file_digest(path)
    bundle = Path(config["offline_bundle"]).resolve()
    if not bundle.is_dir():
        raise LifecycleError("PACKER_INPUT_INVALID", "offline bundle absent")
    for path in sorted(bundle.rglob("*")):
        if path.is_symlink():
            raise LifecycleError(
                "PACKER_INPUT_INVALID", "offline bundle symlink forbidden"
            )
        if path.is_file():
            if (
                path.resolve() == Path(config["iso"]).resolve()
                or path.name == "evidence.json"
            ):
                continue
            records["bundle/" + path.relative_to(bundle).as_posix()] = file_digest(path)
            if path.name == "SHA256SUMS":
                for line in path.read_text(encoding="utf-8").splitlines():
                    match = re.fullmatch(r"([0-9a-f]{64})  \*?([^/\\]+)", line)
                    if not match or not (path.parent / match[2]).is_file():
                        raise LifecycleError(
                            "PACKER_INPUT_INVALID", "offline artifact checksum mismatch"
                        )
                    actual = (
                        iso_digest
                        if (path.parent / match[2]).resolve()
                        == Path(config["iso"]).resolve()
                        else file_digest(path.parent / match[2])
                    )
                    if actual != match[1]:
                        raise LifecycleError(
                            "PACKER_INPUT_INVALID", "offline artifact checksum mismatch"
                        )
    if len(records) < len(inputs) + 3:
        raise LifecycleError("PACKER_INPUT_INVALID", "offline bundle empty")
    return hashlib.sha256(json.dumps(records, sort_keys=True).encode()).hexdigest()


def runtime_fingerprint(root: Path, config: dict) -> str:
    names = config["playbooks"] + config.get("runtime_inputs", [])
    records = {}
    for name in sorted(set(names)):
        path = (root / name).resolve()
        if not path.is_relative_to(root.resolve()) or not path.is_file():
            raise LifecycleError(
                "PACKER_INPUT_INVALID", f"runtime input absent: {name}"
            )
        records[name] = digest(path)
    # Track role task, handler and template changes even when they are included
    # dynamically by a playbook. This may reapply an unrelated role but cannot
    # silently skip a changed runtime input or rebuild the immutable image.
    for path in sorted((root / "platform/ansible/roles").rglob("*")):
        if path.is_symlink():
            raise LifecycleError(
                "PACKER_INPUT_INVALID", "runtime role symlink forbidden"
            )
        if path.is_file():
            records[path.relative_to(root).as_posix()] = digest(path)
    return hashlib.sha256(json.dumps(records, sort_keys=True).encode()).hexdigest()


def available_memory_mib() -> int:
    if os.name == "nt":
        import ctypes

        class MemoryStatus(ctypes.Structure):
            _fields_ = [
                ("length", ctypes.c_ulong),
                ("load", ctypes.c_ulong),
                ("total_physical", ctypes.c_ulonglong),
                ("available_physical", ctypes.c_ulonglong),
                ("total_page", ctypes.c_ulonglong),
                ("available_page", ctypes.c_ulonglong),
                ("total_virtual", ctypes.c_ulonglong),
                ("available_virtual", ctypes.c_ulonglong),
                ("available_extended", ctypes.c_ulonglong),
            ]

        status = MemoryStatus()
        status.length = ctypes.sizeof(status)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)) == 0:
            return 0
        return status.available_physical // 1024**2
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemAvailable:"):
                return int(line.split()[1]) // 1024
    except OSError:
        pass
    return 0


class Runner:
    def run(
        self, argv: list[str], cwd: Path, timeout: int = 30
    ) -> subprocess.CompletedProcess:
        return subprocess.run(
            argv, cwd=cwd, text=True, capture_output=True, timeout=timeout, check=False
        )

    def tcp(self, host: str, port: int) -> bool:
        try:
            with socket.create_connection((host, port), timeout=2):
                return True
        except OSError:
            return False

    def address_in_use(self, host: str) -> bool:
        argv = (
            ["ping", "-n", "1", "-w", "1000", host]
            if os.name == "nt"
            else ["ping", "-c", "1", "-W", "1", host]
        )
        try:
            return self.run(argv, Path.cwd(), 3).returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            raise LifecycleError(
                "VBOX_NETWORK_ERROR", "cannot check guest IP availability"
            )


class Reconciler:
    def __init__(
        self,
        root: Path,
        config: dict,
        runner: Runner | None = None,
        clock=time.monotonic,
        sleep=time.sleep,
    ):
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}", config["vm"]):
            raise LifecycleError("PACKER_INPUT_INVALID", "invalid VM name")
        self.root, self.config = root.resolve(), config
        self.runner, self.clock, self.sleep = runner or Runner(), clock, sleep
        self.policy = yaml.safe_load(
            (root / "config/contracts/vm-lifecycle-policy.yaml").read_text()
        )
        boot = self.policy["boot"]
        if (
            self.policy.get("version") != 1
            or self.policy.get("kind") != "VmLifecyclePolicy"
            or self.policy.get("status") != "enforced"
            or boot["poll_interval_seconds"] != 5
            or boot["global_timeout_seconds"] != 120
            or sum(boot["phases"].values()) > 120
            or self.policy["recovery"].get("destructive_retry") != "forbidden"
        ):
            raise LifecycleError(
                "PACKER_INPUT_INVALID", "VM lifecycle policy is invalid"
            )
        self.state_dir = root / ".context" / "vm-lifecycle" / config["vm"]
        self.metrics = {name: 0 for name in METRIC_NAMES}
        self.checkpoint = None
        self.decision = {
            "vm": config["vm"],
            "current_state": "absent",
            "desired_state": "qualified",
            "image_fingerprint_changed": False,
            "decision": "none",
            "destructive": False,
            "reason": "",
            "retry_budget": 0,
        }

    def command(self, args: list[str], cwd: Path, code: str, timeout: int = 30):
        try:
            result = self.runner.run(args, cwd, timeout)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise LifecycleError(code, str(exc)) from exc
        if result.returncode:
            raise LifecycleError(code, (result.stderr or result.stdout).strip()[:500])
        return result.stdout.strip()

    def _path(self, key: str) -> Path:
        path = Path(self.config[key]).resolve()
        if not path.exists():
            raise LifecycleError("PACKER_INPUT_INVALID", f"{key} absent")
        return path

    def preflight(self):
        c = self.config
        context = (self.root / ".context").resolve()
        for key in (
            "vagrant_dir",
            "packer_vars",
            "offline_bundle",
            "output_box",
            "ssh_config",
            "inventory",
        ):
            if not Path(c[key]).resolve().is_relative_to(context):
                raise LifecycleError(
                    "PACKER_INPUT_INVALID", f"{key} must be under .context"
                )
        if c["image_profile"] not in ("rke2", "admin-qualification"):
            raise LifecycleError("PACKER_INPUT_INVALID", "invalid image profile")
        image = yaml.safe_load(
            (self.root / "config/contracts/machine-image-lock.yaml").read_text()
        )["packer_image"]
        toolchain = json.loads(
            (self.root / "config/contracts/toolchain-lock.json").read_text()
        )
        iso = self._path("iso")
        bundle = Path(c["offline_bundle"]).resolve()
        if not iso.is_relative_to(bundle):
            raise LifecycleError(
                "PACKER_INPUT_INVALID", "ISO must be in offline bundle"
            )
        required_bundle_files = [
            "evidence.json",
            "iso/SHA256SUMS",
            "rpm-keys/SHA256SUMS",
            "rpms/base/SHA256SUMS",
            "tools/base/SHA256SUMS",
            f"rpms/{c['image_profile']}/SHA256SUMS",
            f"tools/{c['image_profile']}/SHA256SUMS",
        ]
        if any(not (bundle / name).is_file() for name in required_bundle_files):
            raise LifecycleError("PACKER_INPUT_INVALID", "offline bundle incomplete")
        if (
            iso.name != image["source"]["iso"]
            or digest(iso) != image["source"]["sha256"]
        ):
            raise LifecycleError("PACKER_INPUT_INVALID", "ISO name or SHA256 mismatch")
        if (
            self.command(
                [c["vboxmanage"], "--version"], self.root, "VBOX_PROVIDER_ERROR"
            ).split("r")[0]
            != image["build"]["virtualbox"]["version"]
        ):
            raise LifecycleError("VBOX_PROVIDER_ERROR", "VirtualBox version mismatch")
        for key, expected, flag in (
            ("vagrant", c["vagrant_version"], "--version"),
            ("packer", toolchain["versions"]["PACKER_VERSION"], "version"),
        ):
            found = self.command([c[key], flag], self.root, "PACKER_INPUT_INVALID")
            if (
                re.search(r"(?<![0-9])" + re.escape(expected) + r"(?![0-9])", found)
                is None
            ):
                raise LifecycleError("PACKER_INPUT_INVALID", f"{key} version mismatch")
        if c["vagrant_version"] != str(self.policy["vagrant"]["version"]):
            raise LifecycleError(
                "PACKER_INPUT_INVALID",
                "Vagrant version is not pinned to fixture contract",
            )
        vagrant_dir = self._path("vagrant_dir")
        if not (vagrant_dir / "Vagrantfile").is_file():
            raise LifecycleError("PACKER_INPUT_INVALID", "Vagrantfile absent")
        vagrant_text = (vagrant_dir / "Vagrantfile").read_text(encoding="utf-8")
        if (
            '"virtualbox"' not in vagrant_text
            or "config.vm.box_check_update = false" not in vagrant_text
            or "config.vm.box_url" not in vagrant_text
            or re.search(r"https?://", vagrant_text)
            or not re.search(
                r'config\.vm\.communicator\s*=\s*["\']none["\']', vagrant_text
            )
        ):
            raise LifecycleError(
                "PACKER_INPUT_INVALID",
                "VirtualBox, immutable box, or short boot policy absent",
            )
        vars_text = self._path("packer_vars").read_text(encoding="utf-8")
        if (
            image["source"]["sha256"] not in vars_text
            or iso.resolve().as_uri() not in vars_text
        ):
            raise LifecycleError(
                "PACKER_INPUT_INVALID", "Packer variables do not pin selected ISO"
            )
        self.command([c["vagrant"], "validate"], vagrant_dir, "PACKER_INPUT_INVALID")
        self.command(
            [
                c["packer"],
                "validate",
                "-var-file=" + str(self._path("packer_vars")),
                "-var=image_profile=" + c["image_profile"],
                str(self.root / "platform/packer/rocky-10.2/rocky-10.2.pkr.hcl"),
            ],
            self.root,
            "PACKER_INPUT_INVALID",
        )
        for playbook in c["playbooks"]:
            path = (self.root / playbook).resolve()
            if not path.is_relative_to(self.root) or not path.is_file():
                raise LifecycleError(
                    "PACKER_INPUT_INVALID", "Ansible playbook absent or external"
                )
            self.command(
                [c["ansible_playbook"], "--syntax-check", str(path)],
                self.root,
                "PACKER_INPUT_INVALID",
            )
        inventory = self._path("inventory")
        if not inventory.is_file():
            raise LifecycleError("PACKER_INPUT_INVALID", "Ansible inventory absent")
        adapters = self.command(
            [c["vboxmanage"], "list", "hostonlyifs"], self.root, "VBOX_NETWORK_ERROR"
        )
        blocks = [
            dict(line.split(":", 1) for line in block.splitlines() if ":" in line)
            for block in re.split(r"\n\s*\n", adapters)
        ]
        selected = [
            {key.strip(): value.strip() for key, value in block.items()}
            for block in blocks
            if block.get("Name", "").strip() == c["hostonly_adapter"]
        ]
        if len(selected) != 1 or selected[0].get("NetworkMask") != "255.255.255.0":
            raise LifecycleError("VBOX_NETWORK_ERROR", "host-only adapter missing")
        import ipaddress

        guest = ipaddress.ip_address(c["guest_ip"])
        host = ipaddress.ip_address(selected[0].get("IPAddress", "0.0.0.0"))
        if (
            not guest.is_private
            or guest.is_loopback
            or guest == host
            or guest not in ipaddress.ip_network(str(host) + "/24", strict=False)
        ):
            raise LifecycleError("VBOX_NETWORK_ERROR", "invalid private guest address")
        if not self.vm_uuid() and (
            self.runner.tcp(c["guest_ip"], 22)
            or self.runner.address_in_use(c["guest_ip"])
        ):
            raise LifecycleError("VBOX_NETWORK_ERROR", "guest address already occupied")
        registered = self.command(
            [c["vboxmanage"], "list", "vms"], self.root, "VBOX_PROVIDER_ERROR"
        )
        if not self.vm_uuid() and f'"{c["vm"]}"' in registered:
            raise LifecycleError(
                "VBOX_PROVIDER_ERROR", "named VM exists without owned Vagrant state"
            )
        if int(c["cpus"]) < 2 or int(c["memory_mib"]) < 4096:
            raise LifecycleError("PACKER_INPUT_INVALID", "insufficient VM resources")
        if (os.cpu_count() or 0) < int(c["cpus"]):
            raise LifecycleError("PACKER_INPUT_INVALID", "host CPU unavailable")
        if available_memory_mib() < int(c["memory_mib"]):
            raise LifecycleError("PACKER_INPUT_INVALID", "host memory unavailable")
        if shutil.disk_usage(vagrant_dir).free < 32 * 1024**3:
            raise LifecycleError("PACKER_INPUT_INVALID", "insufficient disk for VM")
        return image["source"]["sha256"]

    def vm_uuid(self):
        path = (
            Path(self.config["vagrant_dir"]) / ".vagrant/machines/default/virtualbox/id"
        )
        return path.read_text().strip() if path.is_file() else None

    def vm_state(self):
        uuid = self.vm_uuid()
        if not uuid:
            return "absent"
        if not re.fullmatch(r"[0-9a-fA-F-]{36}", uuid):
            raise LifecycleError("VBOX_PROVIDER_ERROR", "invalid Vagrant VM UUID")
        info = self.command(
            [self.config["vboxmanage"], "showvminfo", uuid, "--machinereadable"],
            self.root,
            "VBOX_PROVIDER_ERROR",
        )
        if not re.search(
            r'^name="' + re.escape(self.config["vm"]) + r'"$', info, re.MULTILINE
        ):
            raise LifecycleError(
                "VBOX_PROVIDER_ERROR", "Vagrant identity does not own named VM"
            )
        match = re.search(r'^VMState="([^"]+)"$', info, re.MULTILINE)
        if not match:
            raise LifecycleError("VBOX_PROVIDER_ERROR", "VM state unavailable")
        return match.group(1)

    def ssh(self, remote: str):
        c = self.config
        return (
            self.runner.run(
                [
                    c["ssh"],
                    "-F",
                    str(self._path("ssh_config")),
                    "-o",
                    "ConnectTimeout=3",
                    "-o",
                    "BatchMode=yes",
                    c["vm"],
                    remote,
                ],
                self.root,
                5,
            ).returncode
            == 0
        )

    def remaining_boot(self, deadline):
        remaining = deadline - self.clock()
        if remaining <= 0:
            self.metrics["timeout_count"] += 1
            raise LifecycleError("VM_BOOT_TIMEOUT", "global boot budget exhausted")
        return max(1, int(remaining))

    def probe(self, reboot=False, global_deadline=None):
        phases = self.policy["boot"]["phases"]
        begin = self.clock()
        if global_deadline is None:
            global_deadline = begin + self.policy["boot"]["global_timeout_seconds"]
        previous = begin
        for phase, budget, metric, code in (
            (
                "running",
                phases["running"],
                "power_on_to_running_seconds",
                "VM_BOOT_TIMEOUT",
            ),
            ("tcp22", phases["tcp22"], "running_to_tcp22_seconds", "TCP22_TIMEOUT"),
            ("ssh", phases["ssh"], "tcp22_to_ssh_seconds", "SSH_TIMEOUT"),
            (
                "os_ready",
                phases["os_ready"],
                "ssh_to_os_ready_seconds",
                "OS_READY_TIMEOUT",
            ),
        ):
            deadline = min(global_deadline, self.clock() + budget)
            while True:
                ready = (
                    self.vm_state() == "running"
                    if phase == "running"
                    else self.runner.tcp(self.config["guest_ip"], 22)
                    if phase == "tcp22"
                    else self.ssh("true")
                    if phase == "ssh"
                    else self.ssh(
                        "systemctl is-system-running --wait >/dev/null 2>&1 || systemctl is-system-running | grep -qx degraded"
                    )
                )
                if ready:
                    self.metrics[metric] = round(self.clock() - previous, 3)
                    previous = self.clock()
                    self.checkpoint = {
                        "running": "booted",
                        "tcp22": "booted",
                        "ssh": "ssh-ready",
                        "os_ready": "os-ready",
                    }[phase]
                    if reboot and phase == "ssh":
                        self.metrics["reboot_to_ssh_seconds"] = round(
                            self.clock() - begin, 3
                        )
                    break
                now = self.clock()
                if now >= deadline:
                    self.metrics["timeout_count"] += 1
                    raise LifecycleError(
                        code, f"{phase} did not become ready within its budget"
                    )
                self.sleep(
                    min(self.policy["boot"]["poll_interval_seconds"], deadline - now)
                )

    def _save(self, fingerprint, runtime):
        self.state_dir.mkdir(parents=True, exist_ok=True)
        payload = {
            "vm_uuid": self.vm_uuid(),
            "image_fingerprint": fingerprint,
            "runtime_fingerprint": runtime,
            "checkpoint": self.checkpoint,
            "decision": self.decision,
            "metrics": self.metrics,
        }
        target = self.state_dir / "latest.json"
        temp = target.with_suffix(".tmp")
        temp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
        os.replace(temp, target)
        evidence = self.root / ".context" / "evidence" / "vm-lifecycle"
        evidence.mkdir(parents=True, exist_ok=True)
        evidence_target = evidence / (self.config["vm"] + ".json")
        evidence_temp = evidence_target.with_suffix(".tmp")
        evidence_temp.write_text(
            json.dumps(
                payload
                | {
                    "runtime_qualification": "PASS"
                    if self.checkpoint == "qualified"
                    else "INCOMPLETE"
                },
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )
        os.replace(evidence_temp, evidence_target)

    def reconcile(self):
        self.metrics = {name: 0 for name in METRIC_NAMES}
        self.decision.update(
            decision="none",
            reason="",
            retry_budget=0,
            image_fingerprint_changed=False,
            destructive=False,
        )
        c = self.config
        iso_digest = self.preflight()  # all deterministic checks before boot
        fingerprint = image_fingerprint(self.root, c, iso_digest)
        runtime = runtime_fingerprint(self.root, c)
        box = (
            self._path("output_box")
            if Path(c["output_box"]).is_file()
            else Path(c["output_box"])
        )
        manifest = box.with_suffix(box.suffix + ".fingerprint.json")
        previous_image = json.loads(manifest.read_text()) if manifest.is_file() else {}
        valid_box = (
            box.is_file()
            and previous_image.get("fingerprint") == fingerprint
            and previous_image.get("sha256") == digest(box)
        )
        state = self.vm_state()
        self.decision["current_state"] = state
        self.decision["image_fingerprint_changed"] = bool(
            previous_image and previous_image.get("fingerprint") != fingerprint
        )
        if not valid_box:
            if state != "absent":
                self.decision.update(
                    decision="reclone_required", reason="image_changed_or_corrupt"
                )
                raise LifecycleError(
                    "IMAGE_CORRUPT",
                    "image changed or invalid while VM exists; preserve VM for explicit reclone",
                )
            self.decision.update(
                decision="rebuild", reason="image_missing_changed_or_invalid"
            )
            start = self.clock()
            self.command(
                [
                    c["packer"],
                    "build",
                    "-force",
                    "-only=rocky-10.2-base.virtualbox-iso.base",
                    "-var-file=" + str(self._path("packer_vars")),
                    "-var=image_profile=" + c["image_profile"],
                    str(self.root / "platform/packer/rocky-10.2/rocky-10.2.pkr.hcl"),
                ],
                self.root,
                "PACKER_BUILD_FAILED",
                timeout=int(c.get("build_timeout_seconds", 7200)),
            )
            if not box.is_file():
                raise LifecycleError(
                    "PACKER_BUILD_FAILED", "Packer box missing after build"
                )
            self.metrics["image_build_seconds"] = round(self.clock() - start, 3)
            self.metrics["rebuild_count"] = 1
            manifest.write_text(
                json.dumps(
                    {"fingerprint": fingerprint, "sha256": digest(box)}, sort_keys=True
                )
            )
        boot_deadline = self.clock() + self.policy["boot"]["global_timeout_seconds"]
        if state == "absent":
            self.decision.update(decision="clone", reason="no_existing_vm")
            start = self.clock()
            self.command(
                [c["vagrant"], "up", "--provider=virtualbox", "--no-provision"],
                Path(c["vagrant_dir"]),
                "VM_BOOT_TIMEOUT",
                timeout=self.remaining_boot(boot_deadline),
            )
            self.metrics["clone_seconds"] = round(self.clock() - start, 3)
            self.checkpoint = "created"
        elif state in ("stuck", "gurumeditation"):
            self.decision.update(
                decision="power_cycle", reason="recoverable_hardware_state"
            )
            uuid = self.vm_uuid()
            self.command(
                [c["vboxmanage"], "controlvm", uuid, "poweroff"],
                self.root,
                "VBOX_PROVIDER_ERROR",
                timeout=self.remaining_boot(boot_deadline),
            )
            self.command(
                [c["vboxmanage"], "startvm", uuid, "--type", "headless"],
                self.root,
                "VM_BOOT_TIMEOUT",
                timeout=self.remaining_boot(boot_deadline),
            )
            self.metrics["reboot_count"] += 1
        elif state != "running":
            self.decision.update(decision="resume", reason="existing_vm_powered_off")
            self.command(
                [c["vagrant"], "up", "--no-provision"],
                Path(c["vagrant_dir"]),
                "VM_BOOT_TIMEOUT",
                timeout=self.remaining_boot(boot_deadline),
            )
        else:
            self.decision.update(decision="probe", reason="existing_vm_running")
        probe_deadline = boot_deadline
        try:
            self.probe(global_deadline=probe_deadline)
        except LifecycleError as exc:
            if exc.code not in (
                "VM_BOOT_TIMEOUT",
                "TCP22_TIMEOUT",
                "SSH_TIMEOUT",
                "OS_READY_TIMEOUT",
            ):
                raise
            self.decision.update(
                decision="retry_probe", reason=exc.code, retry_budget=1
            )
            self.probe(
                global_deadline=probe_deadline
            )  # same global budget; never destroy or reboot
        previous = {}
        latest = self.state_dir / "latest.json"
        if latest.is_file():
            previous = json.loads(latest.read_text())
        same_vm = (
            previous.get("vm_uuid") == self.vm_uuid()
            and previous.get("image_fingerprint") == fingerprint
            and previous.get("runtime_fingerprint") == runtime
        )
        if (
            same_vm
            and previous.get("checkpoint") == "qualified"
            and self.ssh(c["service_probe"])
        ):
            self.decision.update(
                decision="reuse", reason="qualified_and_service_ready", retry_budget=0
            )
            self.checkpoint = "qualified"
        else:
            self.decision.update(
                decision="reprovision", reason="new_or_unqualified_vm", retry_budget=1
            )
            for attempt in range(2):
                start = self.clock()
                result = None
                for playbook in c["playbooks"]:
                    result = self.runner.run(
                        [
                            c["ansible_playbook"],
                            "-i",
                            str(self._path("inventory")),
                            str(self.root / playbook),
                        ],
                        self.root,
                        int(c.get("provision_timeout_seconds", 1800)),
                    )
                    if result.returncode:
                        break
                if result is None:
                    raise LifecycleError(
                        "PACKER_INPUT_INVALID", "no provisioning playbook"
                    )
                self.metrics["provision_seconds"] += round(self.clock() - start, 3)
                self.metrics["reprovision_count"] += 1
                if result.returncode == 0:
                    break
                self.checkpoint = "os-ready"
                self._save(fingerprint, runtime)
                if attempt:
                    raise LifecycleError(
                        "PROVISION_FAILED", (result.stderr or result.stdout)[:500]
                    )
            self.checkpoint = "provisioned"
            if self.ssh("test -e /run/reboot-required"):
                self.checkpoint = "reboot-required"
                self.decision.update(decision="reload", reason="guest_requested_reboot")
                self.command(
                    [c["vagrant"], "reload", "--no-provision"],
                    Path(c["vagrant_dir"]),
                    "REBOOT_TIMEOUT",
                    timeout=300,
                )
                self.metrics["reload_count"] += 1
                self.metrics["reboot_count"] += 1
                self.probe(reboot=True)
                self.checkpoint = "rebooted"
            if not self.ssh(c["service_probe"]):
                raise LifecycleError(
                    "SERVICE_READY_TIMEOUT", "service probe failed; VM preserved"
                )
            self.checkpoint = "service-ready"
            self.checkpoint = "qualified"
        self._save(fingerprint, runtime)
        (self.state_dir / "failure.json").unlink(missing_ok=True)
        return self.decision | {
            "checkpoint": self.checkpoint,
            "metrics": self.metrics,
            "image_fingerprint": fingerprint,
        }


def reconcile_cli(root: Path, config_path: Path) -> int:
    controller = None
    try:
        path = config_path.resolve()
        if not path.is_relative_to((root / ".context").resolve()):
            raise LifecycleError(
                "PACKER_INPUT_INVALID", "VM config must be under .context"
            )
        config = json.loads(path.read_text(encoding="utf-8"))
        controller = Reconciler(root, config)
        controller.state_dir.mkdir(parents=True, exist_ok=True)
        lock = controller.state_dir.parent / "reconcile.lock"
        try:
            fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError as exc:
            raise LifecycleError(
                "VBOX_PROVIDER_ERROR", "VM lifecycle already locked"
            ) from exc
        try:
            os.write(fd, str(os.getpid()).encode())
            print(json.dumps(controller.reconcile(), sort_keys=True))
            return 0
        finally:
            os.close(fd)
            lock.unlink()
    except (
        LifecycleError,
        KeyError,
        ValueError,
        OSError,
        subprocess.TimeoutExpired,
    ) as exc:
        code = exc.code if isinstance(exc, LifecycleError) else "PACKER_INPUT_INVALID"
        if controller is not None:
            failure = {
                "runtime_qualification": "FAIL",
                "failure_class": code,
                "checkpoint": controller.checkpoint,
                "decision": controller.decision,
                "metrics": controller.metrics,
            }
            controller.state_dir.mkdir(parents=True, exist_ok=True)
            (controller.state_dir / "failure.json").write_text(
                json.dumps(failure, indent=2, sort_keys=True) + "\n"
            )
        print(
            json.dumps({"status": "FAIL", "failure_class": code, "detail": str(exc)}),
            file=sys.stderr,
        )
        return 2
