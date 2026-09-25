#!/usr/bin/env python3
"""Build, boot-qualify and release the native-Linux Rocky image candidate."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT_ROOT = ROOT / ".artifacts/packer/rocky-10.2/linux"
EVIDENCE_ROOT = ROOT / ".context/evidence/rocky-image/rocky-10.2/linux"
PIPELINE_ROOT = ROOT / ".context/packer-linux/rocky-10.2"
SOURCE_ROOT = ROOT / "platform/packer/rocky-10.2"
ARTIFACT_NAME = "rocky-10.2-rke2-kvm.qcow2"
BUILD_EVIDENCE = EVIDENCE_ROOT / "build.json"
QUALIFICATION_EVIDENCE = EVIDENCE_ROOT / "qualification.json"
RELEASE_EVIDENCE = EVIDENCE_ROOT / "release.json"
STATIC_EVIDENCE = EVIDENCE_ROOT / "static-validation.json"


class PipelineError(RuntimeError):
    """Raised when a fail-closed pipeline invariant is not satisfied."""


def now() -> str:
    return datetime.now(UTC).isoformat()


def read_json(path: Path) -> dict:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PipelineError(f"cannot read JSON evidence {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise PipelineError(f"JSON evidence is not an object: {path}")
    return payload


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    body = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=path.parent,
        prefix=f"{path.name}.",
        delete=False,
    ) as stream:
        stream.write(body)
        temporary = Path(stream.name)
    os.replace(temporary, path)


def sha256(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise PipelineError(f"artifact must be a regular non-symlink file: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run(
    arguments: list[str],
    *,
    cwd: Path = ROOT,
    timeout: int,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    process = subprocess.Popen(
        arguments,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            stdout, stderr = process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            stdout, stderr = process.communicate()
        raise PipelineError(
            f"bounded command timed out after {timeout}s: {arguments[0]}"
        ) from exc
    result = subprocess.CompletedProcess(arguments, process.returncode, stdout, stderr)
    if check and result.returncode:
        detail = (stderr or stdout or "no diagnostic output").strip()[-2000:]
        raise PipelineError(
            f"command failed with exit code {result.returncode}: {arguments[0]}: {detail}"
        )
    return result


def safe_remove_tree(path: Path) -> None:
    base = PIPELINE_ROOT.resolve()
    candidate = path.resolve()
    if candidate == base or not candidate.is_relative_to(base):
        raise PipelineError(f"refusing unsafe pipeline cleanup target: {candidate}")
    if path.is_symlink():
        raise PipelineError(f"refusing symlink pipeline cleanup target: {path}")
    if path.exists():
        shutil.rmtree(path)


def toolchain() -> dict:
    return read_json(ROOT / "config/contracts/toolchain-lock.json")


def require_native_linux() -> None:
    if sys.platform != "linux":
        raise PipelineError("Linux image profile requires a native Linux host")
    release = Path("/proc/sys/kernel/osrelease").read_text(encoding="utf-8").lower()
    if "microsoft" in release or "wsl" in release:
        raise PipelineError(
            "Linux image profile is forbidden in WSL; use the Windows profile there"
        )
    if os.uname().machine != "x86_64":
        raise PipelineError("Linux image profile requires x86_64")
    os_release = {}
    for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            os_release[key] = value.strip().strip('"')
    if os_release.get("ID") != "ubuntu" or os_release.get("VERSION_ID") != "24.04":
        raise PipelineError("Linux image profile requires Ubuntu 24.04")
    kvm = Path("/dev/kvm")
    if not kvm.exists() or not os.access(kvm, os.R_OK | os.W_OK):
        raise PipelineError(
            "Linux image profile requires readable and writable /dev/kvm"
        )


def executable(name: str) -> str:
    value = shutil.which(name)
    if not value:
        raise PipelineError(f"required native Linux executable is absent: {name}")
    return value


def inspect_tools() -> dict:
    require_native_linux()
    lock = toolchain()
    expected_packer = str(lock["versions"]["PACKER_VERSION"])
    expected_qemu = str(lock["versions"]["QEMU_VERSION"])
    paths = {
        name: executable(name)
        for name in (
            "packer",
            "qemu-img",
            "qemu-system-x86_64",
            "ssh",
            "ssh-keygen",
        )
    }
    packer_output = run([paths["packer"], "version"], timeout=15).stdout
    packer_match = re.search(r"Packer v([0-9]+\.[0-9]+\.[0-9]+)", packer_output)
    actual_packer = packer_match.group(1) if packer_match else "unparseable"
    if actual_packer != expected_packer:
        raise PipelineError(
            f"Packer version mismatch: expected {expected_packer}, actual {actual_packer}"
        )
    qemu_output = run([paths["qemu-system-x86_64"], "--version"], timeout=15).stdout
    qemu_match = re.search(r"version ([0-9]+\.[0-9]+\.[0-9]+)", qemu_output)
    actual_qemu = qemu_match.group(1) if qemu_match else "unparseable"
    if actual_qemu != expected_qemu:
        raise PipelineError(
            f"QEMU version mismatch: expected {expected_qemu}, actual {actual_qemu}"
        )
    return {
        "packer": {
            "executable": paths["packer"],
            "expected_version": expected_packer,
            "actual_version": actual_packer,
        },
        "qemu": {
            "executable": paths["qemu-system-x86_64"],
            "qemu_img": paths["qemu-img"],
            "expected_version": expected_qemu,
            "actual_version": actual_qemu,
        },
        "ssh": paths["ssh"],
        "ssh_keygen": paths["ssh-keygen"],
    }


def _windows_path(path: Path) -> str:
    value = run(["wslpath", "-w", str(path)], timeout=15).stdout.strip()
    if not value.startswith("\\\\") and re.fullmatch(r"[A-Za-z]:\\[^\r\n]+", value) is None:
        raise PipelineError(f"path cannot be bridged to Windows: {path}")
    return value


def static_validate() -> int:
    evidence = {
        "schema": 1,
        "profile": "linux",
        "status": "FAIL",
        "packer_init": "NOT_EXECUTED",
        "packer_validate": "NOT_EXECUTED",
        "variable_derivation": "NOT_EXECUTED",
        "iso_checksum": "NOT_EXECUTED",
        "qemu_plugin_version": "NOT_EXECUTED",
        "host_capability": "NOT_AVAILABLE",
        "runtime_build": "NOT_EXECUTED",
        "completed_at": None,
        "error": None,
    }
    try:
        release = Path("/proc/sys/kernel/osrelease").read_text(encoding="utf-8").lower()
        if "microsoft" not in release and "wsl" not in release:
            raise PipelineError("this static entrypoint is reserved for the governed WSL/Windows bridge")
        lock = toolchain()
        expected_packer = lock["versions"]["PACKER_VERSION"]
        powershell = "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"
        lookup = run(
            [
                powershell,
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "(Get-Command packer.exe -ErrorAction Stop).Source",
            ],
            cwd=Path("/mnt/c/Windows"),
            timeout=30,
        ).stdout.strip()
        packer = run(["wslpath", "-u", lookup], timeout=15).stdout.strip()
        actual = run([packer, "version"], cwd=Path("/mnt/c/Windows"), timeout=30).stdout
        if f"Packer v{expected_packer}" not in actual:
            raise PipelineError("Windows Packer version differs from the exact toolchain lock")
        local_app_data = run(
            [
                powershell,
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                '[Environment]::GetFolderPath("LocalApplicationData")',
            ],
            cwd=Path("/mnt/c/Windows"),
            timeout=30,
        ).stdout.strip()
        parent = Path(run(["wslpath", "-u", local_app_data], timeout=15).stdout.strip()) / "Temp/ecommerce/qemu-static"
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        contract = yaml.safe_load((ROOT / "config/contracts/machine-image-lock.yaml").read_text(encoding="utf-8"))
        image = contract["packer_image"]
        expected_plugin = image["build"]["qemu_kvm"]["plugin"]["version"]
        source = image["source"]
        if not re.fullmatch(r"[0-9a-f]{64}", source["sha256"]):
            raise PipelineError("QEMU ISO checksum is invalid")
        evidence["iso_checksum"] = "PASS"
        with tempfile.TemporaryDirectory(prefix="run-", dir=parent) as directory:
            stage = Path(directory)
            packer_source = stage / "source"
            shutil.copytree(SOURCE_ROOT, packer_source)
            artifact_dir = stage / "artifacts"
            artifact_dir.mkdir()
            offline = stage / "offline"
            offline.mkdir()
            for name in ("rpm-keys", "rpms", "tools"):
                (offline / name).mkdir()
            (offline / "install_tools.py").write_text(
                "raise SystemExit('static validation placeholder must never execute')\n",
                encoding="utf-8",
            )
            key = stage / "qualification-key"
            run(
                [
                    "ssh-keygen",
                    "-q",
                    "-t",
                    "ed25519",
                    "-N",
                    "",
                    "-C",
                    "qemu-static-validation",
                    "-f",
                    str(key),
                ],
                cwd=stage,
                timeout=30,
            )
            public_key = key.with_suffix(".pub").read_text(encoding="utf-8").strip()
            variables = stage / "qemu.auto.pkrvars.hcl"
            resources = image["build"]["resources"]
            storage = image["build"]["storage"]
            variables.write_text(
                f"iso_url = {json.dumps(source['url'])}\n"
                f"iso_checksum = {json.dumps(source['sha256'])}\n"
                f"offline_bundle_dir = {json.dumps(_windows_path(offline))}\n"
                f"artifact_dir = {json.dumps(_windows_path(artifact_dir))}\n"
                f"vm_cpus = {resources['vcpus']}\n"
                f"vm_memory_mib = {resources['memory_mib']}\n"
                f"vm_disk_mib = {resources['disk_mib']}\n"
                f"vm_headless = {str(resources['headless']).lower()}\n"
                f"vm_firmware = {json.dumps(storage['firmware'])}\n"
                f"vm_partition_table = {json.dumps(storage['partition_table'])}\n"
                f"vm_bios_boot_mib = {storage['bios_boot_mib']}\n"
                f"vm_boot_mib = {storage['boot_mib']}\n"
                f"vm_root_min_mib = {storage['root_min_mib']}\n"
                f"vm_root_filesystem = {json.dumps(storage['root_filesystem'])}\n"
                f"vm_ssh_timeout_seconds = {image['build']['timeouts']['ssh_seconds']}\n"
                f"vm_virtualbox_nic_type = {json.dumps(image['hypervisors']['virtualbox']['network_adapter'])}\n"
                f"virtualbox_serial_log_file = {json.dumps(_windows_path(stage / 'serial.log'))}\n"
                f"build_ssh_public_key = {json.dumps(public_key)}\n"
                f"build_ssh_private_key_file = {json.dumps(_windows_path(key))}\n",
                encoding="utf-8",
            )
            source_windows = _windows_path(packer_source)
            variables_windows = _windows_path(variables)
            run([packer, "init", source_windows], cwd=stage, timeout=300)
            evidence["packer_init"] = "PASS"
            plugins = run([packer, "plugins", "installed"], cwd=stage, timeout=60).stdout
            plugin_pattern = rf"github\.com[\\/]hashicorp[\\/]qemu[\\/].*_v{re.escape(expected_plugin)}_"
            if re.search(plugin_pattern, plugins) is None:
                raise PipelineError(f"Packer QEMU plugin {expected_plugin} is not installed exactly")
            evidence["qemu_plugin_version"] = "PASS"
            run([packer, "fmt", "-check", source_windows], cwd=stage, timeout=120)
            evidence["variable_derivation"] = "PASS"
            run(
                [
                    packer,
                    "validate",
                    "-only=rocky-10.2-base.qemu.base",
                    f"-var-file={variables_windows}",
                    source_windows,
                ],
                cwd=stage,
                timeout=120,
            )
            evidence["packer_validate"] = "PASS"
        evidence["status"] = "PASS"
    except (KeyError, OSError, PipelineError, subprocess.SubprocessError, yaml.YAMLError) as exc:
        evidence["error"] = str(exc)
    evidence["completed_at"] = now()
    write_json(STATIC_EVIDENCE, evidence)
    if evidence["status"] != "PASS":
        print(f"FAIL rocky-image-qemu-static: {evidence['error']}", file=sys.stderr)
        return 1
    print("PASS rocky-image-qemu-static host_capability=NOT_AVAILABLE runtime_build=NOT_EXECUTED")
    return 0


def preflight() -> int:
    evidence = {
        "schema": 1,
        "profile": "linux",
        "host": "native-linux",
        "status": "FAIL",
        "tools": {},
        "completed_at": None,
        "error": None,
    }
    try:
        evidence["tools"] = inspect_tools()
        evidence["status"] = "PASS"
    except (OSError, PipelineError) as exc:
        evidence["error"] = str(exc)
    evidence["completed_at"] = now()
    write_json(EVIDENCE_ROOT / "preflight.json", evidence)
    if evidence["status"] == "PASS":
        print("PASS rocky-image-linux-preflight")
        return 0
    print(f"FAIL rocky-image-linux-preflight: {evidence['error']}", file=sys.stderr)
    return 1


def git_state() -> tuple[str, bool]:
    head = run(["git", "rev-parse", "HEAD"], timeout=15).stdout.strip()
    if re.fullmatch(r"[0-9a-f]{40}", head) is None:
        raise PipelineError("Git HEAD is not a full SHA")
    status = run(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"], timeout=30
    )
    return head, not bool(status.stdout.strip())


def find_qcow2(directory: Path, qemu_img: str) -> Path:
    matches: list[Path] = []
    for candidate in directory.rglob("*"):
        if candidate.is_symlink() or not candidate.is_file():
            continue
        probe = run(
            [qemu_img, "info", "--output=json", str(candidate)],
            timeout=30,
            check=False,
        )
        if probe.returncode == 0:
            try:
                if json.loads(probe.stdout).get("format") == "qcow2":
                    matches.append(candidate)
            except json.JSONDecodeError:
                pass
    if len(matches) != 1:
        raise PipelineError(
            f"expected exactly one qcow2 Packer output, found {len(matches)}"
        )
    return matches[0]


def build(*, offline: bool) -> int:
    evidence = {
        "schema": 1,
        "image": "rocky-10.2",
        "profile": "rke2",
        "platform": "linux",
        "builder": "packer",
        "hypervisor": "qemu-kvm",
        "status": "FAIL",
        "source_sha": None,
        "source_clean": False,
        "artifact": ARTIFACT_NAME,
        "sha256": None,
        "packer_version": None,
        "qemu_version": None,
        "preflight": "NOT_EXECUTED",
        "packer_init": "NOT_EXECUTED",
        "packer_fmt": "NOT_EXECUTED",
        "packer_validate": "NOT_EXECUTED",
        "packer_build": "NOT_EXECUTED",
        "checksum": "NOT_EXECUTED",
        "cleanup": "NOT_EXECUTED",
        "qualification_key": "NOT_CREATED",
        "started_at": now(),
        "completed_at": None,
        "error": None,
    }
    stage: Path | None = None
    key_target: Path | None = None
    try:
        tools = inspect_tools()
        evidence["preflight"] = "PASS"
        evidence["packer_version"] = tools["packer"]["actual_version"]
        evidence["qemu_version"] = tools["qemu"]["actual_version"]
        head, clean = git_state()
        evidence["source_sha"] = head
        evidence["source_clean"] = clean
        PIPELINE_ROOT.mkdir(parents=True, exist_ok=True)
        stage = PIPELINE_ROOT / f"build-{head[:12]}-{uuid.uuid4().hex}"
        stage.mkdir(mode=0o700)
        offline_bundle = stage / "offline"
        build_artifacts = stage / "artifacts"
        build_artifacts.mkdir()

        run([tools["packer"]["executable"], "init", str(SOURCE_ROOT)], timeout=300)
        evidence["packer_init"] = "PASS"
        run(
            [tools["packer"]["executable"], "fmt", "-check", str(SOURCE_ROOT)],
            timeout=120,
        )
        evidence["packer_fmt"] = "PASS"
        materialize = [
            sys.executable,
            str(ROOT / "scripts/materialize_packer_rpm_repo.py"),
            "--contract",
            str(ROOT / "config/contracts/machine-image-lock.yaml"),
            "--package-lock",
            str(ROOT / "config/artifacts/rocky-10.2-base-packages.lock.json"),
            "--toolchain-lock",
            str(ROOT / "config/contracts/toolchain-lock.json"),
            "--cache",
            str(ROOT / ".context/cache/packer"),
            "--output",
            str(offline_bundle),
        ]
        if offline:
            materialize.append("--offline")
        run(materialize, timeout=7200)

        private_key = stage / "qualification-key"
        run(
            [
                tools["ssh_keygen"],
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                "ecommerce-rocky-image-qualification",
                "-f",
                str(private_key),
            ],
            timeout=30,
        )
        private_key.chmod(0o600)
        evidence["qualification_key"] = "CREATED_LINUX_LOCAL_ONLY"
        var_file = stage / "rocky-10.2.auto.pkrvars.hcl"
        run(
            [
                sys.executable,
                str(ROOT / "scripts/render_packer_vars.py"),
                "--contract",
                str(ROOT / "config/contracts/machine-image-lock.yaml"),
                "--bundle",
                str(offline_bundle),
                "--build-public-key-file",
                str(private_key.with_suffix(".pub")),
                "--build-private-key-file",
                str(private_key),
                "--artifact-dir",
                str(build_artifacts),
                "--target-platform",
                "linux",
                "--output",
                str(var_file),
            ],
            timeout=120,
        )
        run(
            [
                tools["packer"]["executable"],
                "validate",
                f"-var-file={var_file}",
                str(SOURCE_ROOT),
            ],
            timeout=120,
        )
        evidence["packer_validate"] = "PASS"
        run(
            [
                tools["packer"]["executable"],
                "build",
                "-only=rocky-10.2-base.qemu.base",
                f"-var-file={var_file}",
                "-var=image_profile=rke2",
                str(SOURCE_ROOT),
            ],
            timeout=7200,
        )
        evidence["packer_build"] = "PASS"
        source_artifact = find_qcow2(build_artifacts, tools["qemu"]["qemu_img"])
        digest = sha256(source_artifact)
        evidence["sha256"] = digest
        evidence["checksum"] = "PASS"

        ARTIFACT_ROOT.mkdir(parents=True, exist_ok=True)
        target = ARTIFACT_ROOT / ARTIFACT_NAME
        temporary = ARTIFACT_ROOT / f"{ARTIFACT_NAME}.{uuid.uuid4().hex}.tmp"
        shutil.copy2(source_artifact, temporary)
        if sha256(temporary) != digest:
            raise PipelineError("artifact digest changed during promotion")
        os.replace(temporary, target)
        (ARTIFACT_ROOT / "SHA256SUMS").write_text(
            f"{digest}  {ARTIFACT_NAME}\n", encoding="utf-8"
        )
        for stale in (QUALIFICATION_EVIDENCE, RELEASE_EVIDENCE):
            stale.unlink(missing_ok=True)
        key_root = PIPELINE_ROOT / "keys"
        key_root.mkdir(mode=0o700, exist_ok=True)
        key_target = key_root / f"{digest}.key"
        public_target = key_root / f"{digest}.key.pub"
        os.replace(private_key, key_target)
        os.replace(private_key.with_suffix(".pub"), public_target)
        key_target.chmod(0o600)
        public_target.chmod(0o600)
        evidence["qualification_key"] = "STORED_LINUX_LOCAL_ONLY"
        evidence["status"] = "PASS"
    except (OSError, PipelineError) as exc:
        evidence["error"] = str(exc)
    finally:
        if stage is not None:
            try:
                safe_remove_tree(stage)
                evidence["cleanup"] = "PASS"
            except (OSError, PipelineError) as exc:
                evidence["cleanup"] = "FAIL"
                evidence["status"] = "FAIL"
                evidence["error"] = evidence["error"] or str(exc)
        if evidence["status"] != "PASS" and key_target is not None:
            key_target.unlink(missing_ok=True)
            key_target.with_suffix(".key.pub").unlink(missing_ok=True)
    evidence["completed_at"] = now()
    write_json(BUILD_EVIDENCE, evidence)
    if evidence["status"] == "PASS":
        print(f"PASS rocky-image-linux-build sha256={evidence['sha256']}")
        return 0
    print(f"FAIL rocky-image-linux-build: {evidence['error']}", file=sys.stderr)
    return 1


def ssh_command(ssh: str, private_key: Path, port: int, command: str) -> list[str]:
    return [
        ssh,
        "-o",
        "BatchMode=yes",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "ConnectTimeout=10",
        "-i",
        str(private_key),
        "-p",
        str(port),
        "packer@127.0.0.1",
        command,
    ]


def available_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def qualify() -> int:
    fields = (
        "preflight",
        "checksum",
        "boot",
        "ssh",
        "rocky_release",
        "kernel",
        "architecture_cpu",
        "systemd",
        "disk",
        "network",
        "fundamental_tools",
        "rke2_prerequisites",
        "security",
        "cleanup",
        "key_cleanup",
    )
    evidence = {
        "schema": 1,
        "image": "rocky-10.2",
        "platform": "linux",
        "artifact": ARTIFACT_NAME,
        "artifact_sha256": None,
        "source_sha": None,
        "status": "FAIL",
        "qualification": {field: "NOT_EXECUTED" for field in fields},
        "observations": {},
        "started_at": now(),
        "completed_at": None,
        "error": None,
    }
    stage: Path | None = None
    qemu_process: subprocess.Popen[str] | None = None
    qemu_log = None
    private_key: Path | None = None
    public_key: Path | None = None
    passed = False
    try:
        tools = inspect_tools()
        evidence["qualification"]["preflight"] = "PASS"
        build_evidence = read_json(BUILD_EVIDENCE)
        if build_evidence.get("status") != "PASS":
            raise PipelineError("Linux build evidence is absent or not PASS")
        artifact = ARTIFACT_ROOT / ARTIFACT_NAME
        digest = sha256(artifact)
        if digest != build_evidence.get("sha256"):
            raise PipelineError("artifact SHA-256 does not match build evidence")
        evidence["artifact_sha256"] = digest
        evidence["source_sha"] = build_evidence.get("source_sha")
        evidence["qualification"]["checksum"] = "PASS"
        private_key = PIPELINE_ROOT / "keys" / f"{digest}.key"
        public_key = PIPELINE_ROOT / "keys" / f"{digest}.key.pub"
        if not private_key.is_file() or not public_key.is_file():
            raise PipelineError(
                "ephemeral qualification key is missing; rebuild candidate"
            )
        PIPELINE_ROOT.mkdir(parents=True, exist_ok=True)
        stage = PIPELINE_ROOT / f"qualify-{digest[:12]}-{uuid.uuid4().hex}"
        stage.mkdir(mode=0o700)
        overlay = stage / "smoke-overlay.qcow2"
        run(
            [
                tools["qemu"]["qemu_img"],
                "create",
                "-f",
                "qcow2",
                "-F",
                "qcow2",
                "-b",
                str(artifact),
                str(overlay),
            ],
            timeout=60,
        )
        port = available_port()
        qemu_log = (stage / "qemu.log").open("w", encoding="utf-8")
        qemu_process = subprocess.Popen(
            [
                tools["qemu"]["executable"],
                "-name",
                f"ecommerce-rocky-10-2-smoke-{digest[:12]}",
                "-enable-kvm",
                "-machine",
                "q35",
                "-cpu",
                "host",
                "-smp",
                "2",
                "-m",
                "4096",
                "-drive",
                f"file={overlay},format=qcow2,if=virtio",
                "-netdev",
                f"user,id=net0,hostfwd=tcp:127.0.0.1:{port}-:22",
                "-device",
                "virtio-net-pci,netdev=net0",
                "-display",
                "none",
                "-serial",
                "none",
                "-monitor",
                "none",
                "-no-reboot",
            ],
            cwd=stage,
            text=True,
            stdin=subprocess.DEVNULL,
            stdout=qemu_log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        evidence["qualification"]["boot"] = "PASS"
        probe = ssh_command(tools["ssh"], private_key, port, "true")
        for attempt in range(1, 13):
            if qemu_process.poll() is not None:
                raise PipelineError("QEMU smoke VM exited before SSH became ready")
            result = run(probe, cwd=stage, timeout=30, check=False)
            if result.returncode == 0:
                break
            if attempt == 12:
                raise PipelineError(
                    "SSH did not become ready within 12 bounded attempts"
                )
            time.sleep(5)
        evidence["qualification"]["ssh"] = "PASS"
        checks = {
            "rocky_release": "grep -Fx 'Rocky Linux release 10.2 (Red Quartz)' /etc/rocky-release",
            "kernel": "uname -r",
            "architecture_cpu": 'test "$(uname -m)" = x86_64 && test "$(getconf _NPROCESSORS_ONLN)" -ge 2 && uname -m && getconf _NPROCESSORS_ONLN',
            "systemd": 'state=$(systemctl is-system-running --wait || true); test "$state" = running; test -z "$(systemctl --failed --no-legend --plain)"; printf \'%s\' "$state"',
            "disk": "available=$(df --output=avail -BM / | tail -1 | tr -dc '0-9'); test \"$available\" -ge 1024; printf '%s MiB' \"$available\"",
            "network": "ip -4 -o addr show scope global | grep -q .; ip -4 route show default | grep -q '^default '; ip -4 -o addr show scope global; ip -4 route show default",
            "fundamental_tools": 'for tool in python3 curl tar gzip xz zstd rsync unzip openssl nft ip ss systemctl; do command -v "$tool" >/dev/null; done; printf required-tools-present',
            "rke2_prerequisites": 'test -z "$(swapon --noheadings --show)"; test "$(stat -fc %T /sys/fs/cgroup)" = cgroup2fs; for module in overlay br_netfilter nf_conntrack vxlan; do sudo -n modprobe "$module"; done; test "$(sysctl -n net.ipv4.ip_forward)" = 1; test "$(sysctl -n net.bridge.bridge-nf-call-iptables)" = 1; test -d /sys/fs/bpf; printf rke2-prerequisites-present',
            "security": "test \"$(getenforce)\" = Enforcing; sudo -n sshd -T | grep -qx 'permitrootlogin no'; sudo -n sshd -T | grep -qx 'passwordauthentication no'; command -v oscap >/dev/null; test -r /usr/share/xml/scap/ssg/content/ssg-rl10-ds.xml; test ! -e /root/.config/gh/hosts.yml; test ! -e /etc/rancher/rke2/config.yaml; printf security-baseline-present",
        }
        for name, command in checks.items():
            result = run(
                ssh_command(tools["ssh"], private_key, port, command),
                cwd=stage,
                timeout=120,
            )
            evidence["qualification"][name] = "PASS"
            evidence["observations"][name] = result.stdout.strip()
        passed = True
    except (OSError, PipelineError) as exc:
        evidence["error"] = str(exc)
    finally:
        cleanup_failed = False
        if qemu_process is not None and qemu_process.poll() is None:
            try:
                os.killpg(qemu_process.pid, signal.SIGTERM)
                qemu_process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                os.killpg(qemu_process.pid, signal.SIGKILL)
                qemu_process.wait(timeout=10)
            except OSError as exc:
                cleanup_failed = True
                evidence["error"] = evidence["error"] or str(exc)
        if qemu_log is not None:
            qemu_log.close()
        evidence["qualification"]["cleanup"] = "FAIL" if cleanup_failed else "PASS"
        try:
            if private_key is not None:
                private_key.unlink(missing_ok=True)
            if public_key is not None:
                public_key.unlink(missing_ok=True)
            evidence["qualification"]["key_cleanup"] = "PASS"
        except OSError as exc:
            cleanup_failed = True
            evidence["qualification"]["key_cleanup"] = "FAIL"
            evidence["error"] = evidence["error"] or str(exc)
        if stage is not None:
            try:
                safe_remove_tree(stage)
            except (OSError, PipelineError) as exc:
                cleanup_failed = True
                evidence["qualification"]["cleanup"] = "FAIL"
                evidence["error"] = evidence["error"] or str(exc)
        if passed and not cleanup_failed:
            evidence["status"] = "PASS"
    evidence["completed_at"] = now()
    write_json(QUALIFICATION_EVIDENCE, evidence)
    if evidence["status"] == "PASS":
        print(
            f"PASS rocky-image-linux-qualification sha256={evidence['artifact_sha256']}"
        )
        return 0
    print(f"FAIL rocky-image-linux-qualification: {evidence['error']}", file=sys.stderr)
    return 1


def release() -> int:
    checks = {
        name: "NOT_EXECUTED"
        for name in (
            "preflight",
            "exact_source_sha",
            "clean_source",
            "build_evidence",
            "checksum",
            "qualification_evidence",
            "cleanup",
            "ephemeral_key_absent",
        )
    }
    evidence = {
        "schema": 1,
        "image": "rocky-10.2",
        "platform": "linux",
        "artifact": ARTIFACT_NAME,
        "artifact_sha256": None,
        "source_sha": None,
        "status": "FAIL",
        "remote_publication": "NOT_PERFORMED",
        "checks": checks,
        "completed_at": None,
        "error": None,
    }
    try:
        inspect_tools()
        checks["preflight"] = "PASS"
        build_evidence = read_json(BUILD_EVIDENCE)
        required = (
            "preflight",
            "packer_init",
            "packer_fmt",
            "packer_validate",
            "packer_build",
            "checksum",
            "cleanup",
        )
        if build_evidence.get("status") != "PASS" or any(
            build_evidence.get(field) != "PASS" for field in required
        ):
            raise PipelineError("build evidence is not fully PASS")
        checks["build_evidence"] = "PASS"
        head, clean = git_state()
        if not clean or build_evidence.get("source_clean") is not True:
            raise PipelineError("release requires build evidence from a clean worktree")
        checks["clean_source"] = "PASS"
        if head != build_evidence.get("source_sha"):
            raise PipelineError("release candidate source SHA differs from current SHA")
        checks["exact_source_sha"] = "PASS"
        evidence["source_sha"] = head
        artifact = ARTIFACT_ROOT / ARTIFACT_NAME
        digest = sha256(artifact)
        expected_line = f"{digest}  {ARTIFACT_NAME}"
        if (
            digest != build_evidence.get("sha256")
            or (ARTIFACT_ROOT / "SHA256SUMS").read_text(encoding="utf-8").strip()
            != expected_line
        ):
            raise PipelineError("artifact checksum differs from build evidence")
        evidence["artifact_sha256"] = digest
        checks["checksum"] = "PASS"
        qualification = read_json(QUALIFICATION_EVIDENCE)
        if (
            qualification.get("status") != "PASS"
            or qualification.get("artifact_sha256") != digest
            or any(value != "PASS" for value in qualification["qualification"].values())
        ):
            raise PipelineError("qualification evidence is not PASS for exact artifact")
        checks["qualification_evidence"] = "PASS"
        checks["cleanup"] = "PASS"
        key_root = PIPELINE_ROOT / "keys"
        if (key_root / f"{digest}.key").exists() or (
            key_root / f"{digest}.key.pub"
        ).exists():
            raise PipelineError("ephemeral qualification key remains present")
        checks["ephemeral_key_absent"] = "PASS"
        evidence["status"] = "PASS"
    except (KeyError, OSError, PipelineError) as exc:
        evidence["error"] = str(exc)
    evidence["completed_at"] = now()
    write_json(RELEASE_EVIDENCE, evidence)
    if evidence["status"] == "PASS":
        print(
            f"PASS rocky-image-linux-release sha256={evidence['artifact_sha256']} "
            "publication=NOT_PERFORMED"
        )
        return 0
    print(f"FAIL rocky-image-linux-release: {evidence['error']}", file=sys.stderr)
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("static-validate", "preflight", "build", "qualify", "release"))
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()
    if args.offline and args.action != "build":
        parser.error("--offline is valid only for build")
    if args.action == "static-validate":
        return static_validate()
    if args.action == "preflight":
        return preflight()
    if args.action == "build":
        return build(offline=args.offline)
    if args.action == "qualify":
        return qualify()
    if args.action == "release":
        return release()
    raise AssertionError("argparse accepted an unsupported image pipeline action")


if __name__ == "__main__":
    raise SystemExit(main())
