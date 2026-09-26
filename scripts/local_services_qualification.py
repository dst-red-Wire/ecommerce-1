#!/usr/bin/env python3
"""Qualify Gitea, Harbor and an ORAS digest round-trip on the Rocky box."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.request
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "config/contracts/local-services-qualification.yaml"
FIXTURE = ROOT / "platform/ansible/tests/local_services_vm"
TRANSPORT = FIXTURE / "transport.py"
SEED_SERVER = ROOT / "scripts/windows/local-services-seed-server.ps1"
POWERSHELL = Path("/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe")
CACHE = ROOT / ".context/cache/local-services-vm"
RUNTIME = ROOT / ".context/runtime/local-services-vm"
EVIDENCE = ROOT / ".context/evidence/local-services-vm/qualification.json"


class QualificationError(RuntimeError):
    """Raised when runtime qualification cannot prove a required invariant."""


class RuntimeBlocked(QualificationError):
    """The current host cannot run the required VirtualBox backend."""


def now() -> str:
    return datetime.now(UTC).isoformat()


def run(
    command: list[str],
    *,
    cwd: Path = ROOT,
    env: dict[str, str] | None = None,
    timeout: int = 300,
    stdin: str | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            env=env,
            input=stdin,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise QualificationError(f"bounded command timed out after {timeout}s: {command[0]}") from exc
    if check and result.returncode:
        detail = " ".join((result.stderr or result.stdout or "no diagnostic output").split())[-2000:]
        raise QualificationError(f"command failed ({result.returncode}): {command[0]}: {detail}")
    return result


def sha256(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise QualificationError(f"regular non-symlink file required: {path}")
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write_json(path: Path, payload: dict, *, mode: int = 0o600) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}.", delete=False
    ) as stream:
        json.dump(payload, stream, indent=2, sort_keys=True)
        stream.write("\n")
        temporary = Path(stream.name)
    temporary.chmod(mode)
    os.replace(temporary, path)


def contract() -> dict:
    value = yaml.safe_load(CONTRACT_PATH.read_text(encoding="utf-8"))
    if value.get("status") != "exact-local-runtime-qualification":
        raise QualificationError("local service contract is not exact")
    return value


def runtime_capabilities() -> dict:
    """Observe controller and Windows virtualization state without starting a VM."""
    capabilities = {
        "controller": "wsl2" if platform.system() == "Linux" and "wsl2" in platform.release().lower() else "unavailable",
        "ansible": (ROOT / ".venv/qualification/bin/ansible-playbook").is_file(),
        "ssh": shutil.which("ssh") is not None,
        "windows_interop": POWERSHELL.is_file(),
        "hypervisor_present": None,
        "firmware_virtualization_enabled": None,
        "virtualbox_backend": "NOT_PROBED",
        "status": "BLOCKED_RUNTIME",
        "reason": None,
    }
    if capabilities["windows_interop"]:
        probe = (
        "$c=Get-CimInstance Win32_ComputerSystem;"
        "$p=@(Get-CimInstance Win32_Processor);"
        "[pscustomobject]@{hypervisor_present=[bool]$c.HypervisorPresent;"
        "firmware_virtualization_enabled=($p.Count -gt 0 -and "
        "@($p | Where-Object {$_.VirtualizationFirmwareEnabled -ne $true}).Count -eq 0)}"
        "|ConvertTo-Json -Compress"
        )
        try:
            result = run([str(POWERSHELL), "-NoProfile", "-NonInteractive", "-Command", probe],
                         cwd=Path("/mnt/c/Windows"), timeout=30)
            windows = json.loads(result.stdout)
            capabilities["hypervisor_present"] = windows["hypervisor_present"]
            capabilities["firmware_virtualization_enabled"] = windows["firmware_virtualization_enabled"]
        except (OSError, QualificationError, ValueError, KeyError, json.JSONDecodeError):
            capabilities["windows_interop"] = False
    if capabilities["controller"] != "wsl2":
        capabilities["reason"] = "WSL2 Ansible/SSH controller is unavailable"
    elif capabilities["hypervisor_present"]:
        capabilities["virtualbox_backend"] = "NATIVE_VTX_UNAVAILABLE"
        capabilities["reason"] = "Microsoft hypervisor is active; native VT-x is unavailable and NEM is forbidden"
    elif not capabilities["ansible"] or not capabilities["ssh"] or not capabilities["windows_interop"]:
        capabilities["reason"] = "WSL2 Ansible, SSH or Windows interop capability is unavailable"
    elif not capabilities["firmware_virtualization_enabled"]:
        capabilities["reason"] = "firmware virtualization is unavailable"
    else:
        capabilities["status"] = "READY_FOR_BACKEND_PROBE"
    return capabilities


def git(*arguments: str) -> str:
    return run(["git", *arguments], timeout=60).stdout.strip()


def windows_path(path: Path) -> str:
    value = run(["wslpath", "-w", str(path.resolve())], timeout=15).stdout.strip()
    if not value.startswith("\\\\") and re.fullmatch(r"[A-Za-z]:\\[^\r\n]+", value) is None:
        raise QualificationError(f"path cannot be bridged to Windows: {path}")
    return value


def local_app_data() -> Path:
    result = run(
        [
            str(POWERSHELL),
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            '[Environment]::GetFolderPath("LocalApplicationData")',
        ],
        cwd=Path("/mnt/c/Windows"),
        timeout=30,
    ).stdout.strip()
    path = run(["wslpath", "-u", result], timeout=15).stdout.strip()
    candidate = Path(path).resolve()
    if not candidate.is_relative_to(Path("/mnt/c/Users").resolve()):
        raise QualificationError("Windows LocalApplicationData resolved outside the user profile")
    return candidate


def windows_free_port() -> int:
    script = (
        "$l=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,0);"
        "$l.Start();$p=$l.LocalEndpoint.Port;$l.Stop();[Console]::Write($p)"
    )
    value = run(
        [str(POWERSHELL), "-NoProfile", "-NonInteractive", "-Command", script],
        cwd=Path("/mnt/c/Windows"),
        timeout=30,
    ).stdout.strip()
    if not value.isdigit() or not 1024 <= int(value) <= 65535:
        raise QualificationError("Windows failed to allocate an ephemeral port")
    return int(value)


def local_free_port(address: str = "127.0.0.1") -> int:
    with socket.socket() as listener:
        listener.bind((address, 0))
        return int(listener.getsockname()[1])


def validate_released_artifact(configuration: dict, head: str) -> tuple[Path, str]:
    image = configuration["machine_image"]
    artifact = ROOT / image["artifact"]
    checksums = ROOT / image["checksum_file"]
    release_path = ROOT / image["release_evidence"]
    digest = sha256(artifact)
    expected_line = f"{digest}  {artifact.name}"
    if checksums.read_text(encoding="utf-8").strip() != expected_line:
        raise QualificationError("Rocky box SHA256SUMS does not match its exact bytes")
    release = json.loads(release_path.read_text(encoding="utf-8"))
    if (
        release.get("status") != "PASS"
        or release.get("source_sha") != head
        or release.get("artifact_sha256") != digest
        or release.get("remote_publication") != "NOT_PERFORMED"
    ):
        raise QualificationError("exact-SHA Windows release evidence is absent or stale")
    return artifact, digest


def materialize_assets(*, offline: bool) -> None:
    command = [
        sys.executable,
        str(ROOT / "scripts/materialize_local_service_assets.py"),
        "--contract",
        str(CONTRACT_PATH),
        "--output",
        str(CACHE),
    ]
    if offline:
        command.append("--offline")
    result = run(command, timeout=3600)
    print(result.stdout.strip())


def prepare_native_controller_payload(destination: Path, *, offline: bool) -> dict:
    """Freeze the published source and locked Linux tools before WSL2 stops."""
    head = git("rev-parse", "HEAD")
    branch = git("symbolic-ref", "--short", "HEAD")
    if not re.fullmatch(r"[0-9a-f]{40}", head) or branch != "feat/packer-dual-host-rocky-image-pipeline":
        raise QualificationError("native controller payload requires the published PR branch")
    if git("status", "--porcelain", "--untracked-files=all"):
        raise QualificationError("native controller payload requires a clean exact-SHA worktree")
    if git("rev-parse", "@{upstream}") != head:
        raise QualificationError("native controller payload requires the published exact SHA")
    if destination.is_symlink() or destination.exists():
        manifest = destination / "payload.json"
        if not manifest.is_file():
            raise QualificationError(f"stale or incomplete native controller payload: {destination}")
        payload = json.loads(manifest.read_text(encoding="utf-8"))
        if payload.get("source_sha") != head:
            raise QualificationError("native controller payload is stale for the current SHA")
        if not isinstance(payload.get("files"), dict) or len(payload["files"]) < 5:
            raise QualificationError("native controller payload manifest is incomplete")
        for relative, digest in payload.get("files", {}).items():
            if not isinstance(relative, str) or not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
                raise QualificationError("native controller payload manifest is invalid")
            if Path(relative).is_absolute() or any(part in {"", ".", ".."} for part in Path(relative).parts):
                raise QualificationError("native controller payload path is unsafe")
            path = destination / relative
            if not path.resolve().is_relative_to(destination.resolve()) or sha256(path) != digest:
                raise QualificationError(f"native controller payload checksum differs: {relative}")
        return payload

    materialize_assets(offline=offline)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f"{destination.name}.{os.getpid()}.tmp")
    if temporary.exists() or temporary.is_symlink():
        raise QualificationError(f"stale interrupted native controller preparation: {temporary}")
    try:
        temporary.mkdir(mode=0o700)
        run(["git", "bundle", "create", str(temporary / "source.bundle"), branch], timeout=1800)
        run(["git", "bundle", "verify", str(temporary / "source.bundle")], timeout=300)
        shutil.copy2(ROOT / "scripts/native_controller_bootstrap.py", temporary / "bootstrap.py")
        shutil.copytree(CACHE, temporary / "assets")
        oras = shutil.which("oras")
        if not oras or not re.search(r"Version:\s+1\.3\.3\b", run([oras, "version"], timeout=30).stdout):
            raise QualificationError("locked ORAS 1.3.3 is unavailable for native controller")
        expected_oras = contract()["runtime"]["native_controller"]["oras_binary_sha256"]
        if sha256(Path(oras)) != expected_oras:
            raise QualificationError("local ORAS binary digest differs from the native controller contract")
        shutil.copy2(oras, temporary / "oras")
        wheels = temporary / "wheels"
        wheels.mkdir()
        requirements = ROOT / "config/python/requirements.lock"
        index = contract()["runtime"]["native_controller"]["python_package_index"]
        command = [
            sys.executable, "-m", "pip", "download", "--require-hashes",
            "--only-binary=:all:", "--dest", str(wheels), "-r", str(requirements),
        ]
        if offline:
            command.extend(["--no-index", "--find-links", str(ROOT / ".context/cache/native-controller-wheels")])
        else:
            if index != "https://pypi.org/simple":
                raise QualificationError("native controller Python index is not the declared pinned source")
            command.extend(["--index-url", index])
        run(command, timeout=3600)
        if not any(wheels.glob("*.whl")):
            raise QualificationError("native controller wheelhouse is empty")
        files = {
            path.relative_to(temporary).as_posix(): sha256(path)
            for path in temporary.rglob("*") if path.is_file()
        }
        payload = {
            "schema": 1,
            "source_sha": head,
            "source_branch": branch,
            "source_tree": git("rev-parse", "HEAD^{tree}"),
            "files": files,
            "created_at": now(),
        }
        write_json(temporary / "payload.json", payload)
        os.replace(temporary, destination)
        return payload
    except BaseException:
        if temporary.is_dir() and not temporary.is_symlink():
            shutil.rmtree(temporary)
        raise


def ensure_key(path: Path, comment: str) -> None:
    if path.is_file() and path.with_suffix(".pub").is_file():
        return
    if path.exists() or path.is_symlink() or path.with_suffix(".pub").exists():
        raise QualificationError(f"incomplete runtime SSH key pair: {path}")
    run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", comment, "-f", str(path)], timeout=30)
    path.chmod(0o600)
    path.with_suffix(".pub").chmod(0o600)


def ensure_tls(runtime: Path) -> tuple[Path, Path, Path]:
    root = runtime / "tls"
    root.mkdir(mode=0o700, exist_ok=True)
    ca_key, ca_cert = root / "ca.key", root / "ca.crt"
    key, csr, cert, extensions = root / "harbor.key", root / "harbor.csr", root / "harbor.crt", root / "harbor.ext"
    if ca_key.is_file() and ca_cert.is_file() and key.is_file() and cert.is_file():
        return ca_cert, cert, key
    for path in (ca_key, ca_cert, key, csr, cert, extensions):
        if path.exists() or path.is_symlink():
            raise QualificationError("incomplete Harbor runtime TLS material")
    run(["openssl", "req", "-x509", "-newkey", "rsa:3072", "-nodes", "-days", "30", "-subj", "/CN=ecommerce-local-harbor-ca", "-keyout", str(ca_key), "-out", str(ca_cert)], timeout=60)
    run(["openssl", "req", "-newkey", "rsa:3072", "-nodes", "-subj", "/CN=127.0.0.2", "-keyout", str(key), "-out", str(csr)], timeout=60)
    extensions.write_text("subjectAltName=IP:127.0.0.2\nextendedKeyUsage=serverAuth\n", encoding="utf-8")
    run(["openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca_cert), "-CAkey", str(ca_key), "-CAcreateserial", "-days", "30", "-sha256", "-extfile", str(extensions), "-out", str(cert)], timeout=60)
    ca_key.chmod(0o600)
    key.chmod(0o600)
    csr.unlink(missing_ok=True)
    extensions.unlink(missing_ok=True)
    return ca_cert, cert, key


def ensure_secrets(runtime: Path) -> dict[str, str]:
    path = runtime / "secrets.json"
    if path.is_file() and not path.is_symlink():
        if path.stat().st_mode & 0o077:
            raise QualificationError("runtime secret file is group/world accessible")
        return json.loads(path.read_text(encoding="utf-8"))
    values = {
        name: secrets.token_urlsafe(36)
        for name in (
            "gitea_admin_password",
            "gitea_secret_key",
            "gitea_internal_token",
            "gitea_lfs_jwt_secret",
            "harbor_admin_password",
            "harbor_database_password",
        )
    }
    write_json(path, values)
    return values


def powershell_seed(action: str, seed_root: Path, port: int) -> None:
    result = run(
        [
            str(POWERSHELL),
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            windows_path(SEED_SERVER),
            "-Action",
            action,
            "-SeedRoot",
            windows_path(seed_root),
            "-Port",
            str(port),
        ],
        cwd=Path("/mnt/c/Windows"),
        timeout=30,
    )
    if result.stdout.strip():
        print(result.stdout.strip())


def vagrant(state: Path, *arguments: str, timeout: int = 900) -> subprocess.CompletedProcess[str]:
    return run(
        [sys.executable, str(TRANSPORT), "vagrant", "--state", str(state), "--", *arguments],
        timeout=timeout,
    )


def proxy_command(state: Path) -> str:
    return f"{sys.executable} {TRANSPORT} proxy --state {state}"


def ssh_command(state: Path, identity: Path, known_hosts: Path, *remote: str, accept_new: bool = False) -> list[str]:
    return [
        "ssh",
        "-o", f"ProxyCommand={proxy_command(state)}",
        "-o", f"UserKnownHostsFile={known_hosts}",
        "-o", f"StrictHostKeyChecking={'accept-new' if accept_new else 'yes'}",
        "-o", "IdentitiesOnly=yes",
        "-o", "ConnectTimeout=10",
        "-i", str(identity),
        "qualifier@127.0.0.1",
        *remote,
    ]


def wait_for_ssh(state: Path, identity: Path, known_hosts: Path) -> None:
    for _ in range(90):
        probe = run(
            ssh_command(
                state,
                identity,
                known_hosts,
                "cloud-init status --wait >/dev/null && test -f /var/lib/ecommerce-first-boot-ready && getenforce",
                accept_new=True,
            ),
            timeout=30,
            check=False,
        )
        if probe.returncode == 0 and probe.stdout.strip() == "Enforcing":
            return
        time.sleep(3)
    raise QualificationError("Rocky NoCloud SSH bootstrap did not become ready")


def render_seed(seed: Path, public_key: str, service: str, head: str) -> None:
    seed.mkdir(mode=0o700, parents=True, exist_ok=True)
    (seed / "meta-data").write_text(
        f"instance-id: ecommerce-{service}-{head[:12]}\nlocal-hostname: {service}-local\n",
        encoding="utf-8",
    )
    (seed / "user-data").write_text(
        "#cloud-config\n"
        "disable_root: true\n"
        "ssh_pwauth: false\n"
        "ssh_deletekeys: true\n"
        "ssh_genkeytypes: [ed25519]\n"
        "users:\n"
        "  - name: qualifier\n"
        "    gecos: Ecommerce local qualification\n"
        "    groups: [wheel]\n"
        "    lock_passwd: true\n"
        "    shell: /bin/bash\n"
        "    sudo: ['ALL=(ALL) NOPASSWD:ALL']\n"
        "    ssh_authorized_keys:\n"
        f"      - {public_key}\n"
        "package_update: false\n"
        "package_upgrade: false\n"
        "runcmd:\n"
        "  - [restorecon, -RF, /home/qualifier/.ssh]\n"
        "  - [touch, /var/lib/ecommerce-first-boot-ready]\n",
        encoding="utf-8",
    )


def prepare_windows_state(
    configuration: dict,
    runtime: Path,
    windows_root: Path,
    service: str,
    head: str,
    box_name: str,
    ssh_port: int,
    seed_port: int,
    public_key: str,
) -> Path:
    state = windows_root / service
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    shutil.copy2(FIXTURE / "Vagrantfile", state / "Vagrantfile")
    sizing = configuration["machine_image"]["sizing"][service]
    runtime_document = {
        "name": f"ecommerce-local-{service}-{head[:12]}",
        "memory_mib": sizing["memory_mib"],
        "cpus": sizing["vcpus"],
        "ssh_host_port": ssh_port,
        "seed_port": seed_port,
        "box_name": box_name,
        "vagrant_version": "2.4.9",
        "vagrant_windows": r"C:\Program Files\Vagrant\bin\vagrant.exe",
        "vagrant_home": str(windows_root / "vagrant-home"),
    }
    write_json(state / "runtime.json", runtime_document)
    render_seed(state / "seed", public_key, service, head)
    return state


def ansible_inventory(runtime: Path, state: Path, identity: Path, known_hosts: Path) -> Path:
    path = runtime / f"inventory-{state.name}.json"
    write_json(
        path,
        {
            "all": {
                "hosts": {
                    "local_service": {
                        "ansible_host": "127.0.0.1",
                        "ansible_user": "qualifier",
                        "ansible_python_interpreter": "/usr/bin/python3",
                        "ansible_ssh_private_key_file": str(identity),
                        "ansible_ssh_common_args": (
                            f"-o UserKnownHostsFile={known_hosts} -o StrictHostKeyChecking=yes "
                            f"-o IdentitiesOnly=yes -o ProxyCommand=\"{proxy_command(state)}\""
                        ),
                    }
                }
            }
        },
    )
    return path


def run_ansible(playbook: Path, inventory: Path, variables: dict, runtime: Path) -> int:
    variables_path = runtime / f"extra-vars-{playbook.stem}.json"
    write_json(variables_path, variables)
    executable = ROOT / ".venv/qualification/bin/ansible-playbook"
    if not executable.is_file():
        raise QualificationError("qualification Ansible environment is absent; run make seed")
    environment = dict(os.environ)
    environment["ANSIBLE_CONFIG"] = str(ROOT / "platform/ansible/ansible.cfg")
    environment["ANSIBLE_NOCOLOR"] = "1"
    result = run(
        [str(executable), "-i", str(inventory), str(playbook), "--extra-vars", f"@{variables_path}"],
        env=environment,
        timeout=1800,
    )
    print(result.stdout.strip())
    recaps = re.findall(
        r"(?m)^local_service\s+:\s+ok=\d+\s+changed=(\d+)\s+unreachable=(\d+)\s+failed=(\d+)\b",
        result.stdout,
    )
    if len(recaps) != 1 or int(recaps[0][1]) != 0 or int(recaps[0][2]) != 0:
        raise QualificationError("Ansible recap is absent, ambiguous or reports an unreachable/failed host")
    return int(recaps[0][0])


def prove_second_apply(playbook: Path, inventory: Path, variables: dict, runtime: Path) -> int:
    changed = run_ansible(playbook, inventory, variables, runtime)
    if changed != 0:
        raise QualificationError(f"second Ansible apply changed {changed} resources: {playbook.name}")
    return changed


@contextmanager
def ssh_tunnel(
    state: Path,
    identity: Path,
    known_hosts: Path,
    forwards: list[tuple[str, int, int]],
):
    command = ssh_command(state, identity, known_hosts)
    command[1:1] = ["-N"]
    for address, local_port, guest_port in forwards:
        command[1:1] = ["-L", f"{address}:{local_port}:127.0.0.1:{guest_port}"]
    process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    try:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if process.poll() is not None:
                detail = (process.stderr.read() if process.stderr else "").strip()[-1000:]
                raise QualificationError(f"SSH tunnel exited before readiness: {detail}")
            ready = True
            for address, port, _ in forwards:
                try:
                    with socket.create_connection((address, port), timeout=1):
                        pass
                except OSError:
                    ready = False
                    break
            if ready:
                yield
                return
            time.sleep(0.25)
        raise QualificationError("SSH tunnel readiness timed out")
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def git_qualification(runtime: Path, git_port: int, key: Path, repository: str) -> dict:
    known_hosts = runtime / "gitea-known-hosts"
    remote = f"ssh://git@127.0.0.1:{git_port}/qualification-admin/{repository}.git"
    ssh = f"ssh -i {key} -o IdentitiesOnly=yes -o UserKnownHostsFile={known_hosts} -o StrictHostKeyChecking=accept-new"
    environment = dict(os.environ)
    environment["GIT_SSH_COMMAND"] = ssh
    environment["GIT_CONFIG_NOSYSTEM"] = "1"
    with tempfile.TemporaryDirectory(prefix="gitea-git-", dir=runtime) as directory:
        root = Path(directory)
        source, clone = root / "source", root / "clone"
        source.mkdir()
        run(["git", "init", "-b", "main"], cwd=source)
        run(["git", "config", "user.name", "Qualification"], cwd=source)
        run(["git", "config", "user.email", "qualification@localhost.invalid"], cwd=source)
        (source / "integrity.txt").write_text("first\n", encoding="utf-8")
        run(["git", "add", "integrity.txt"], cwd=source)
        run(["git", "-c", "commit.gpgsign=false", "commit", "-m", "test: first integrity commit"], cwd=source)
        run(["git", "remote", "add", "origin", remote], cwd=source)
        run(["git", "push", "-u", "origin", "main"], cwd=source, env=environment)
        first = run(["git", "rev-parse", "HEAD"], cwd=source).stdout.strip()
        run(["git", "clone", remote, str(clone)], cwd=root, env=environment)
        cloned = run(["git", "rev-parse", "HEAD"], cwd=clone).stdout.strip()
        if cloned != first:
            raise QualificationError("Gitea clone SHA differs from pushed SHA")
        (source / "integrity.txt").write_text("first\nsecond\n", encoding="utf-8")
        run(["git", "add", "integrity.txt"], cwd=source)
        run(["git", "-c", "commit.gpgsign=false", "commit", "-m", "test: fetched integrity commit"], cwd=source)
        run(["git", "push", "origin", "main"], cwd=source, env=environment)
        second = run(["git", "rev-parse", "HEAD"], cwd=source).stdout.strip()
        run(["git", "fetch", "origin"], cwd=clone, env=environment)
        fetched = run(["git", "rev-parse", "origin/main"], cwd=clone).stdout.strip()
        if fetched != second:
            raise QualificationError("Gitea fetched SHA differs from pushed SHA")
    return {"push_sha": first, "clone_sha": cloned, "fetch_sha": fetched, "expected_fetch_sha": second}


def tls_health(url: str, ca_file: Path, *, attempts: int = 60) -> dict:
    context = ssl.create_default_context(cafile=str(ca_file))
    for _ in range(attempts):
        try:
            with urllib.request.urlopen(url, context=context, timeout=5) as response:
                payload = json.load(response)
                if response.status == 200:
                    return payload
        except (OSError, ValueError):
            time.sleep(2)
    raise QualificationError(f"TLS health endpoint did not become ready: {url}")


def oras_qualification(
    configuration: dict,
    runtime: Path,
    ca_cert: Path,
    harbor_port: int,
    password: str,
) -> dict:
    oras = shutil.which("oras")
    if not oras:
        raise QualificationError("ORAS is absent; run make bootstrap")
    version = run([oras, "version"], timeout=30).stdout
    if not re.search(r"Version:\s+1\.3\.3\b", version):
        raise QualificationError("ORAS runtime version is not exactly 1.3.3")
    registry = f"127.0.0.2:{harbor_port}"
    registry_config = runtime / "oras-registry-config.json"
    if not registry_config.exists():
        registry_config.write_text("{}\n", encoding="utf-8")
        registry_config.chmod(0o600)
    login = run(
        [
            oras,
            "login",
            registry,
            "--username",
            "admin",
            "--password-stdin",
            "--ca-file",
            str(ca_cert),
            "--registry-config",
            str(registry_config),
        ],
        stdin=password + "\n",
        timeout=60,
    )
    if "Login Succeeded" not in login.stdout + login.stderr:
        raise QualificationError("ORAS authenticated login did not report success")
    repository = f"{registry}/{configuration['harbor']['project']}/{configuration['oras']['repository'].split('/', 1)[1]}"
    environment = dict(os.environ)
    environment.update(
        ORAS_CA_FILE=str(ca_cert),
        ORAS_REGISTRY_CONFIG=str(registry_config),
        ORAS_CACHE=str(runtime / "oras-cache"),
    )
    push = run(
        [sys.executable, str(ROOT / "scripts/repoctl.py"), "image-rocky-oras-push", "--profile", "windows", "--repository", repository],
        env=environment,
        timeout=7200,
    )
    print(push.stdout.strip())
    machine = yaml.safe_load((ROOT / "config/contracts/machine-image-lock.yaml").read_text(encoding="utf-8"))
    push_evidence = json.loads((ROOT / machine["packer_image"]["distribution"]["evidence_by_profile"]["windows"]["push"]).read_text(encoding="utf-8"))
    reference = push_evidence.get("immutable_reference")
    if not isinstance(reference, str) or re.fullmatch(r"[^@]+@sha256:[0-9a-f]{64}", reference) is None:
        raise QualificationError("ORAS push evidence has no immutable digest reference")
    pull = run(
        [sys.executable, str(ROOT / "scripts/repoctl.py"), "image-rocky-oras-pull", "--profile", "windows", "--reference", reference],
        env=environment,
        timeout=7200,
    )
    print(pull.stdout.strip())
    pull_evidence = json.loads((ROOT / machine["packer_image"]["distribution"]["evidence_by_profile"]["windows"]["pull"]).read_text(encoding="utf-8"))
    wrong = repository + "@sha256:" + ("f" * 64)
    with tempfile.TemporaryDirectory(prefix="wrong-digest-", dir=runtime) as destination:
        rejected = run(
            [oras, "pull", "--ca-file", str(ca_cert), "--registry-config", str(registry_config), wrong, "--output", destination, "--no-tty"],
            timeout=60,
            check=False,
        )
        if rejected.returncode == 0 or any(Path(destination).iterdir()):
            raise QualificationError("wrong ORAS digest was not rejected before materialization")
    if push_evidence.get("artifact_sha256") != pull_evidence.get("artifact_sha256"):
        raise QualificationError("ORAS pulled artifact SHA-256 differs from source")
    return {
        "version": "1.3.3",
        "login": "PASS",
        "push": "PASS",
        "oci_digest": reference.rsplit("@", 1)[1],
        "pull_by_digest": "PASS",
        "source_sha256": push_evidence["artifact_sha256"],
        "pulled_sha256": pull_evidence["artifact_sha256"],
        "sha_match": "PASS",
        "tamper_rejection": "PASS",
    }


def is_virtualbox_guest() -> bool:
    try:
        return "virtualbox" in Path("/sys/class/dmi/id/product_name").read_text(encoding="utf-8").lower()
    except OSError:
        return False


def validate_native_controller_input(document: dict, head: str) -> dict:
    runtime = document.get("runtime")
    if (
        document.get("source_sha") != head
        or not isinstance(document.get("campaign_id"), str)
        or re.fullmatch(r"[0-9a-f]{32}", document["campaign_id"]) is None
        or not isinstance(runtime, dict)
        or runtime.get("hypervisor_present") is not False
        or runtime.get("hardware_virtualization") is not True
        or runtime.get("virtualbox_backend") != "NATIVE_VTX"
        or runtime.get("nem_detected") is not False
        or re.fullmatch(r"[0-9a-f]{64}", str(runtime.get("virtualbox_log_sha256"))) is None
        or re.fullmatch(r"[0-9a-f]{64}", str(document.get("service_virtualbox_log_sha256"))) is None
        or document.get("controller") != "virtualbox-linux"
        or document.get("target_ip") != contract()["runtime"]["native_controller"]["host_only_service_ipv4"]
    ):
        raise RuntimeBlocked("native controller input lacks exact-SHA observed VT-x/no-NEM binding")
    if platform.system() != "Linux" or "microsoft" in platform.release().lower():
        raise RuntimeBlocked("native controller must run in a Linux VirtualBox guest, never WSL2")
    if not is_virtualbox_guest():
        raise RuntimeBlocked("native controller does not have a VirtualBox guest identity")
    return runtime


def direct_ssh_command(address: str, identity: Path, known_hosts: Path, *remote: str, accept_new: bool = False) -> list[str]:
    return [
        "ssh", "-o", f"UserKnownHostsFile={known_hosts}",
        "-o", f"StrictHostKeyChecking={'accept-new' if accept_new else 'yes'}",
        "-o", "IdentitiesOnly=yes", "-o", "ConnectTimeout=5",
        "-o", "BatchMode=yes",
        "-i", str(identity), f"qualifier@{address}", *remote,
    ]


def wait_for_direct_ssh(address: str, identity: Path, known_hosts: Path) -> None:
    for attempt in range(30):
        probe = run(
            direct_ssh_command(
                address, identity, known_hosts,
                "test -f /var/lib/ecommerce-first-boot-ready && test \"$(getenforce)\" = Enforcing",
                accept_new=True,
            ),
            timeout=15,
            check=False,
        )
        if probe.returncode == 0:
            return
        if attempt < 29:
            time.sleep(3)
    raise QualificationError("native local-service VM SSH or cloud-init readiness timed out")


def direct_ansible_inventory(runtime: Path, address: str, identity: Path, known_hosts: Path) -> Path:
    path = runtime / "inventory-native.json"
    write_json(path, {
        "all": {"hosts": {"local_service": {
            "ansible_host": address,
            "ansible_user": "qualifier",
            "ansible_python_interpreter": "/usr/bin/python3",
            "ansible_ssh_private_key_file": str(identity),
            "ansible_ssh_common_args": (
                f"-o UserKnownHostsFile={known_hosts} -o StrictHostKeyChecking=yes "
                "-o IdentitiesOnly=yes -o ConnectTimeout=5"
            ),
        }}},
    })
    return path


@contextmanager
def direct_ssh_tunnel(address: str, identity: Path, known_hosts: Path, forwards: list[tuple[str, int, int]]):
    command = direct_ssh_command(address, identity, known_hosts)
    command[1:1] = ["-N"]
    for local_address, local_port, remote_port in forwards:
        command[1:1] = ["-L", f"{local_address}:{local_port}:127.0.0.1:{remote_port}"]
    process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    try:
        for attempt in range(60):
            if process.poll() is not None:
                detail = (process.stderr.read() if process.stderr else "").strip()[-1000:]
                raise QualificationError(f"native SSH tunnel exited before readiness: {detail}")
            try:
                for local_address, local_port, _ in forwards:
                    with socket.create_connection((local_address, local_port), timeout=1):
                        pass
                yield
                return
            except OSError:
                if attempt < 59:
                    time.sleep(0.5)
        raise QualificationError("native SSH tunnel readiness timed out")
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def qualify_native_controller_phase(phase: str, input_path: Path) -> int:
    head = git("rev-parse", "HEAD")
    document = json.loads(input_path.read_text(encoding="utf-8"))
    campaign = document.get("campaign_id")
    evidence_path = EVIDENCE
    evidence = {
        "schema": 1, "status": "FAIL", "source_sha": head, "campaign_id": campaign,
        "controller": {"type": "virtualbox-linux", "wsl2_required": False},
        "runtime": document.get("runtime"), "gitea": {}, "harbor": {}, "oras": {},
        "started_at": now(), "completed_at": None, "error": None,
    }
    try:
        validate_native_controller_input(document, head)
        os.environ["PATH"] = str(ROOT / ".venv/qualification/bin") + os.pathsep + os.environ.get("PATH", "")
        if git("status", "--porcelain", "--untracked-files=all"):
            raise QualificationError("native controller requires a clean exact-SHA checkout")
        if git("rev-parse", "@{upstream}") != head:
            raise QualificationError("native controller source SHA is not its bundled upstream")
        configuration = contract()
        artifact, digest = validate_released_artifact(configuration, head)
        evidence["artifact_sha256"] = digest
        runtime = RUNTIME / str(campaign)
        runtime.mkdir(mode=0o700, parents=True, exist_ok=True)
        identity = Path(document["service_identity"])
        if identity.is_symlink() or not identity.is_file() or identity.stat().st_mode & 0o077:
            raise QualificationError("native controller service SSH identity is absent or not private")
        address = document["target_ip"]
        known_hosts = runtime / "service-known-hosts"
        wait_for_direct_ssh(address, identity, known_hosts)
        inventory = direct_ansible_inventory(runtime, address, identity, known_hosts)
        secrets_value = ensure_secrets(runtime)
        if phase == "gitea":
            git_identity = runtime / "git-identity"
            ensure_key(git_identity, "ecommerce-local-gitea-client")
            repository = f"qualification-{head[:12]}-{campaign[:8]}"
            variables = {
                "local_gitea_version": configuration["gitea"]["version"],
                "local_gitea_binary": str(CACHE / configuration["gitea"]["filename"]),
                "local_gitea_binary_sha256": configuration["gitea"]["sha256"],
                "local_gitea_rpm_root": str(CACHE / "gitea-rpms"),
                "local_gitea_rpm_keys": str(CACHE / "rpm-keys"),
                "local_gitea_admin_password": secrets_value["gitea_admin_password"],
                "local_gitea_secret_key": secrets_value["gitea_secret_key"],
                "local_gitea_internal_token": secrets_value["gitea_internal_token"],
                "local_gitea_lfs_jwt_secret": secrets_value["gitea_lfs_jwt_secret"],
                "local_gitea_repository_name": repository,
                "local_gitea_git_public_key": git_identity.with_suffix(".pub").read_text(encoding="utf-8").strip(),
            }
            playbook = FIXTURE / "gitea.yml"
            run_ansible(playbook, inventory, variables, runtime)
            changed = prove_second_apply(playbook, inventory, variables, runtime)
            http_port, git_port = local_free_port(), local_free_port()
            with direct_ssh_tunnel(address, identity, known_hosts, [
                ("127.0.0.1", http_port, 3000), ("127.0.0.1", git_port, 2222),
            ]):
                with urllib.request.urlopen(f"http://127.0.0.1:{http_port}/api/healthz", timeout=10) as response:
                    health = json.load(response)
                if health.get("status") != "pass":
                    raise QualificationError("Gitea health response is not pass")
                git_proof = git_qualification(runtime, git_port, git_identity, repository)
            evidence["gitea"] = {
                "status": "PASS", "install": "PASS", "health": "PASS",
                "second_apply_changes": changed, **git_proof,
            }
            evidence["status"] = "GITEA_PASS"
        elif phase == "harbor":
            previous = json.loads(evidence_path.read_text(encoding="utf-8"))
            if (
                previous.get("source_sha") != head
                or previous.get("campaign_id") != campaign
                or previous.get("status") != "GITEA_PASS"
                or previous.get("runtime") != document.get("runtime")
                or previous.get("gitea", {}).get("status") != "PASS"
                or previous.get("gitea", {}).get("second_apply_changes") != 0
            ):
                raise QualificationError("native Harbor phase lacks the matching Gitea campaign")
            evidence["gitea"] = previous["gitea"]
            ca_cert, harbor_cert, harbor_key = ensure_tls(runtime)
            harbor_port = local_free_port("127.0.0.2")
            docker = configuration["harbor"]["container_runtime"]
            variables = {
                "local_harbor_version": configuration["harbor"]["version"],
                "local_harbor_archive": str(CACHE / configuration["harbor"]["filename"]),
                "local_harbor_archive_sha256": configuration["harbor"]["sha256"],
                "local_harbor_nested_archive_sha256": configuration["harbor"]["nested_image_archive_sha256"],
                "local_harbor_docker_rpm_root": str(CACHE / "docker-rpms"),
                "local_harbor_docker_signing_key": str(CACHE / docker["signing_key"]["filename"]),
                "local_harbor_docker_signing_key_sha256": docker["signing_key"]["sha256"],
                "local_harbor_admin_password": secrets_value["harbor_admin_password"],
                "local_harbor_database_password": secrets_value["harbor_database_password"],
                "local_harbor_tls_certificate": str(harbor_cert),
                "local_harbor_tls_private_key": str(harbor_key),
                "local_harbor_tls_ca": str(ca_cert),
                "local_harbor_external_port": harbor_port,
                "local_harbor_project": configuration["harbor"]["project"],
                "local_harbor_images": configuration["harbor"]["images"],
            }
            playbook = FIXTURE / "harbor.yml"
            run_ansible(playbook, inventory, variables, runtime)
            changed = prove_second_apply(playbook, inventory, variables, runtime)
            with direct_ssh_tunnel(address, identity, known_hosts, [("127.0.0.2", harbor_port, 443)]):
                health = tls_health(f"https://127.0.0.2:{harbor_port}/api/v2.0/health", ca_cert)
                if health.get("status") != "healthy":
                    raise QualificationError("Harbor health response is not healthy")
                evidence["harbor"] = {
                    "status": "PASS", "install": "PASS", "health": "PASS",
                    "second_apply_changes": changed,
                }
                evidence["oras"] = oras_qualification(
                    configuration, runtime, ca_cert, harbor_port, secrets_value["harbor_admin_password"]
                )
            if (
                evidence["oras"].get("push") != "PASS"
                or evidence["oras"].get("pull_by_digest") != "PASS"
                or evidence["oras"].get("source_sha256") != evidence["oras"].get("pulled_sha256")
                or evidence["oras"].get("source_sha256") != digest
            ):
                raise QualificationError("native ORAS digest identity is not proven")
            evidence["status"] = "PASS"
        else:
            raise QualificationError(f"unknown native controller phase: {phase}")
    except RuntimeBlocked as exc:
        evidence["status"] = "BLOCKED_RUNTIME"
        evidence["error"] = str(exc)[:2000]
    except (KeyError, OSError, QualificationError, ValueError, json.JSONDecodeError, yaml.YAMLError) as exc:
        evidence["error"] = str(exc)[:2000]
    evidence["completed_at"] = now()
    write_json(evidence_path, evidence)
    if evidence["status"] not in {"GITEA_PASS", "PASS"}:
        print(f"{evidence['status']} native-controller-{phase}: {evidence['error']}", file=sys.stderr)
        return 1
    print(f"PASS native-controller-{phase} campaign={campaign} sha={head}")
    return 0


def bootstrap_vm(state: Path, identity: Path, known_hosts: Path) -> None:
    seed = state / "seed"
    runtime = json.loads((state / "runtime.json").read_text(encoding="utf-8"))
    powershell_seed("Start", seed, int(runtime["seed_port"]))
    try:
        vagrant(state, "validate", timeout=120)
        vagrant(state, "up", "--provider", "virtualbox", "--no-provision", timeout=900)
        backend = run([sys.executable, str(TRANSPORT), "backend", "--state", str(state)], timeout=60).stdout.strip()
        if backend != "NATIVE_VTX":
            raise RuntimeBlocked(f"VirtualBox backend is {backend}; native VT-x is required and NEM is forbidden")
        wait_for_ssh(state, identity, known_hosts)
    finally:
        powershell_seed("Stop", seed, int(runtime["seed_port"]))


def qualify(*, offline: bool) -> int:
    configuration = contract()
    head = git("rev-parse", "HEAD")
    evidence = {
        "schema": 1,
        "status": "FAIL",
        "source_sha": head,
        "artifact_sha256": None,
        "runtime_capabilities": {},
        "gitea": {},
        "harbor": {},
        "oras": {},
        "cleanup": {},
        "started_at": now(),
        "completed_at": None,
        "error": None,
    }
    states: dict[str, Path] = {}
    try:
        if git("status", "--porcelain", "--untracked-files=all"):
            raise QualificationError("local service qualification requires a clean exact-SHA worktree")
        if git("rev-parse", "@{upstream}") != head:
            raise QualificationError("local service qualification requires the exact SHA published upstream")
        artifact, artifact_digest = validate_released_artifact(configuration, head)
        evidence["artifact_sha256"] = artifact_digest
        evidence["runtime_capabilities"] = runtime_capabilities()
        if evidence["runtime_capabilities"]["status"] == "BLOCKED_RUNTIME":
            raise RuntimeBlocked(evidence["runtime_capabilities"]["reason"])
        materialize_assets(offline=offline)
        runtime = RUNTIME / head
        runtime.mkdir(mode=0o700, parents=True, exist_ok=True)
        identity, git_identity = runtime / "identity", runtime / "git-identity"
        ensure_key(identity, "ecommerce-local-service-controller")
        ensure_key(git_identity, "ecommerce-local-gitea-client")
        secrets_value = ensure_secrets(runtime)
        ca_cert, harbor_cert, harbor_key = ensure_tls(runtime)
        windows_root = local_app_data() / "Temp/ecommerce/.context/local-services-vm" / head
        windows_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        box_copy = windows_root / artifact.name
        if not box_copy.exists():
            shutil.copy2(artifact, box_copy)
        if sha256(box_copy) != artifact_digest:
            raise QualificationError("Rocky box digest changed during Windows staging")
        box_name = f"ecommerce/rocky-10.2-rke2-{head[:12]}"
        ssh_port, seed_port = windows_free_port(), windows_free_port()
        public_key = identity.with_suffix(".pub").read_text(encoding="utf-8").strip()
        for service in ("gitea", "harbor"):
            states[service] = prepare_windows_state(
                configuration, runtime, windows_root, service, head, box_name, ssh_port, seed_port, public_key
            )
        listing = vagrant(states["gitea"], "box", "list", timeout=120).stdout
        if box_name not in listing:
            vagrant(
                states["gitea"],
                "box", "add", "--name", box_name, "--provider", "virtualbox",
                "--checksum-type", "sha256", "--checksum", artifact_digest, windows_path(box_copy),
                timeout=900,
            )

        gitea_known = runtime / "gitea-vm-known-hosts"
        bootstrap_vm(states["gitea"], identity, gitea_known)
        gitea_inventory = ansible_inventory(runtime, states["gitea"], identity, gitea_known)
        repository = f"qualification-{head[:12]}-{secrets.token_hex(4)}"
        gitea_variables = {
            "local_gitea_version": configuration["gitea"]["version"],
            "local_gitea_binary": str(CACHE / configuration["gitea"]["filename"]),
            "local_gitea_binary_sha256": configuration["gitea"]["sha256"],
            "local_gitea_rpm_root": str(CACHE / "gitea-rpms"),
            "local_gitea_rpm_keys": str(CACHE / "rpm-keys"),
            "local_gitea_admin_password": secrets_value["gitea_admin_password"],
            "local_gitea_secret_key": secrets_value["gitea_secret_key"],
            "local_gitea_internal_token": secrets_value["gitea_internal_token"],
            "local_gitea_lfs_jwt_secret": secrets_value["gitea_lfs_jwt_secret"],
            "local_gitea_repository_name": repository,
            "local_gitea_git_public_key": git_identity.with_suffix(".pub").read_text(encoding="utf-8").strip(),
        }
        run_ansible(FIXTURE / "gitea.yml", gitea_inventory, gitea_variables, runtime)
        gitea_second_changes = prove_second_apply(FIXTURE / "gitea.yml", gitea_inventory, gitea_variables, runtime)
        http_port, git_port = local_free_port(), local_free_port()
        with ssh_tunnel(states["gitea"], identity, gitea_known, [("127.0.0.1", http_port, 3000), ("127.0.0.1", git_port, 2222)]):
            with urllib.request.urlopen(f"http://127.0.0.1:{http_port}/api/healthz", timeout=10) as response:
                health = json.load(response)
            if health.get("status") != "pass":
                raise QualificationError("Gitea health response is not pass")
            git_proof = git_qualification(runtime, git_port, git_identity, repository)
        evidence["gitea"] = {
            "version": configuration["gitea"]["version"],
            "second_apply_changes": gitea_second_changes,
            "install": "PASS", "service": "PASS", "health": "PASS",
            "repository_create": "PASS", "push": "PASS", "clone": "PASS", "fetch": "PASS",
            "sha_integrity": "PASS", **git_proof,
        }
        vagrant(states["gitea"], "halt", timeout=300)
        evidence["cleanup"]["gitea_vm"] = "STOPPED_DISK_PRESERVED"

        harbor_known = runtime / "harbor-vm-known-hosts"
        bootstrap_vm(states["harbor"], identity, harbor_known)
        harbor_inventory = ansible_inventory(runtime, states["harbor"], identity, harbor_known)
        harbor_port = local_free_port("127.0.0.2")
        docker = configuration["harbor"]["container_runtime"]
        harbor_variables = {
            "local_harbor_version": configuration["harbor"]["version"],
            "local_harbor_archive": str(CACHE / configuration["harbor"]["filename"]),
            "local_harbor_archive_sha256": configuration["harbor"]["sha256"],
            "local_harbor_nested_archive_sha256": configuration["harbor"]["nested_image_archive_sha256"],
            "local_harbor_docker_rpm_root": str(CACHE / "docker-rpms"),
            "local_harbor_docker_signing_key": str(CACHE / docker["signing_key"]["filename"]),
            "local_harbor_docker_signing_key_sha256": docker["signing_key"]["sha256"],
            "local_harbor_admin_password": secrets_value["harbor_admin_password"],
            "local_harbor_database_password": secrets_value["harbor_database_password"],
            "local_harbor_tls_certificate": str(harbor_cert),
            "local_harbor_tls_private_key": str(harbor_key),
            "local_harbor_tls_ca": str(ca_cert),
            "local_harbor_external_port": harbor_port,
            "local_harbor_project": configuration["harbor"]["project"],
            "local_harbor_images": configuration["harbor"]["images"],
        }
        run_ansible(FIXTURE / "harbor.yml", harbor_inventory, harbor_variables, runtime)
        harbor_second_changes = prove_second_apply(FIXTURE / "harbor.yml", harbor_inventory, harbor_variables, runtime)
        with ssh_tunnel(states["harbor"], identity, harbor_known, [("127.0.0.2", harbor_port, 443)]):
            health = tls_health(f"https://127.0.0.2:{harbor_port}/api/v2.0/health", ca_cert)
            if health.get("status") != "healthy":
                raise QualificationError("Harbor health response is not healthy")
            evidence["harbor"] = {
                "version": configuration["harbor"]["version"],
                "second_apply_changes": harbor_second_changes,
                "install": "PASS", "service": "PASS", "health": "PASS", "project_create": "PASS",
                "image_digests": "PASS",
            }
            evidence["oras"] = oras_qualification(
                configuration, runtime, ca_cert, harbor_port, secrets_value["harbor_admin_password"]
            )
        vagrant(states["harbor"], "halt", timeout=300)
        evidence["cleanup"]["harbor_vm"] = "STOPPED_DISK_PRESERVED"
        evidence["status"] = "PASS"
    except RuntimeBlocked as exc:
        evidence["status"] = "BLOCKED_RUNTIME"
        evidence["error"] = str(exc)[:2000]
    except (KeyError, OSError, QualificationError, ValueError, json.JSONDecodeError, yaml.YAMLError) as exc:
        evidence["error"] = str(exc)[:2000]
    finally:
        for service, state in states.items():
            try:
                status = vagrant(state, "status", "--machine-readable", timeout=120).stdout
                if ",state,running" in status:
                    vagrant(state, "halt", timeout=300)
                    evidence["cleanup"][f"{service}_vm"] = "STOPPED_DISK_PRESERVED"
            except (OSError, QualificationError):
                evidence["cleanup"][f"{service}_vm"] = "STOP_FAILED"
                evidence["status"] = "FAIL"
        evidence["completed_at"] = now()
        write_json(EVIDENCE, evidence)
    if evidence["status"] != "PASS":
        print(f"{evidence['status']} local-services-qualification: {evidence['error']}", file=sys.stderr)
        return 1
    print("PASS local-services-qualification")
    return 0


def recover() -> int:
    head = git("rev-parse", "HEAD")
    root = local_app_data() / "Temp/ecommerce/.context/local-services-vm" / head
    for service in ("gitea", "harbor"):
        state = root / service
        if not (state / "runtime.json").is_file():
            continue
        runtime = json.loads((state / "runtime.json").read_text(encoding="utf-8"))
        try:
            powershell_seed("Stop", state / "seed", int(runtime["seed_port"]))
        except QualificationError:
            pass
        status = vagrant(state, "status", "--machine-readable", timeout=120).stdout
        if ",state,running" in status:
            vagrant(state, "halt", timeout=300)
    print("PASS local-services-recover stopped-owned-vms-disks-preserved")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("assets", "capabilities", "qualify", "recover", "native-payload", "controller-gitea", "controller-harbor"))
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--stage", type=Path)
    parser.add_argument("--input", type=Path)
    args = parser.parse_args()
    if args.action == "capabilities":
        print(json.dumps(runtime_capabilities(), indent=2, sort_keys=True))
        return 0
    if args.action != "recover":
        from validate_guest_smoke_commands import GuestSmokePreflightError, validate_guest_smoke_commands

        try:
            count = validate_guest_smoke_commands()
        except GuestSmokePreflightError as exc:
            print(f"FAIL guest-smoke-preflight: {exc}", file=sys.stderr)
            return 1
        print(f"PASS guest-smoke-preflight commands={count}")
    if args.action == "assets":
        materialize_assets(offline=args.offline)
        return 0
    if args.action == "native-payload":
        if args.stage is None:
            parser.error("native-payload requires --stage")
        payload = prepare_native_controller_payload(args.stage, offline=args.offline)
        print(f"PASS native-controller-payload sha={payload['source_sha']} stage={args.stage}")
        return 0
    if args.action in {"controller-gitea", "controller-harbor"}:
        if args.input is None:
            parser.error(f"{args.action} requires --input")
        return qualify_native_controller_phase(args.action.split("-", 1)[1], args.input)
    if args.action == "recover":
        return recover()
    return qualify(offline=args.offline)


if __name__ == "__main__":
    raise SystemExit(main())
