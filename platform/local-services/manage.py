#!/usr/bin/env python3
"""Reconcile the local Gitea/Harbor management services on native WSL storage."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import socket
import ssl
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
STATE = ROOT / ".context/local-services"
TLS = STATE / "tls"
HARBOR = STATE / "harbor"
INSTALLER = STATE / "harbor-online-installer-v2.15.2.tgz"
INSTALLER_URL = (
    "https://github.com/goharbor/harbor/releases/download/v2.15.2/" + INSTALLER.name
)
INSTALLER_SHA256 = "88f6a7436b31890e8e472972a7433d36b7d6a36de9adeb86337fdc9fe7fb5fa3"
GITEA_URL = "https://gitea.ecommerce.local/"
HARBOR_URL = "https://harbor.ecommerce.local/"


def run(*args: str, cwd: Path = ROOT, env: dict | None = None) -> None:
    subprocess.run(args, cwd=cwd, env=env, check=True)


def write_private(path: Path, value: str) -> None:
    path.write_text(value, encoding="utf-8")
    path.chmod(0o600)


def configure_wsl_host() -> None:
    """Persist WSL-only name resolution and allow rootless TLS on port 443."""
    script = r"""
from pathlib import Path
conf = Path('/etc/wsl.conf')
text = conf.read_text()
if '[network]' not in text:
    text += '\n[network]\ngenerateHosts=false\n'
elif 'generateHosts=' not in text:
    text = text.replace('[network]', '[network]\ngenerateHosts=false', 1)
conf.write_text(text)
hosts = Path('/etc/hosts')
entry = '127.0.0.1 gitea.ecommerce.local harbor.ecommerce.local'
text = hosts.read_text()
if entry not in text:
    hosts.write_text(text.rstrip() + '\n' + entry + '\n')
Path('/etc/sysctl.d/90-ecommerce-local-ports.conf').write_text(
    'net.ipv4.ip_unprivileged_port_start = 0\n')
"""
    subprocess.run(
        ["sudo", "-n", "python3", "-c", script],
        capture_output=True,
        text=True,
        check=True,
    )
    subprocess.run(
        ["sudo", "-n", "sysctl", "-w", "net.ipv4.ip_unprivileged_port_start=0"],
        capture_output=True,
        text=True,
        check=True,
    )
    subprocess.run(
        [
            "sudo",
            "-n",
            "install",
            "-m",
            "0644",
            str(TLS / "ca.crt"),
            "/usr/local/share/ca-certificates/ecommerce-local.crt",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    subprocess.run(
        ["sudo", "-n", "update-ca-certificates"],
        capture_output=True,
        text=True,
        check=True,
    )


def initialize() -> None:
    sys.path.insert(0, str(ROOT))
    from scripts.native_workspace import workspace_error

    error = workspace_error()
    if error:
        raise RuntimeError(error)
    STATE.mkdir(parents=True, exist_ok=True)
    STATE.chmod(0o700)
    TLS.mkdir(exist_ok=True)
    TLS.chmod(0o700)
    ca_key, ca_cert = TLS / "ca.key", TLS / "ca.crt"
    server_key, server_cert = TLS / "server.key", TLS / "server.crt"
    if not ca_cert.exists():
        run(
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:3072",
            "-noenc",
            "-sha256",
            "-days",
            "365",
            "-subj",
            "/CN=ecommerce local development CA",
            "-keyout",
            str(ca_key),
            "-out",
            str(ca_cert),
        )
        ca_key.chmod(0o600)
    if not server_cert.exists():
        csr = TLS / "server.csr"
        ext = TLS / "server.ext"
        write_private(
            ext,
            "subjectAltName=DNS:gitea.ecommerce.local,DNS:harbor.ecommerce.local\n"
            "extendedKeyUsage=serverAuth\n",
        )
        run(
            "openssl",
            "req",
            "-new",
            "-newkey",
            "rsa:3072",
            "-noenc",
            "-sha256",
            "-subj",
            "/CN=gitea.ecommerce.local",
            "-keyout",
            str(server_key),
            "-out",
            str(csr),
        )
        run(
            "openssl",
            "x509",
            "-req",
            "-in",
            str(csr),
            "-CA",
            str(ca_cert),
            "-CAkey",
            str(ca_key),
            "-CAcreateserial",
            "-days",
            "365",
            "-sha256",
            "-extfile",
            str(ext),
            "-out",
            str(server_cert),
        )
        server_key.chmod(0o600)
        csr.unlink()
        ext.unlink()
    secrets_path = STATE / "credentials.json"
    if not secrets_path.exists():
        write_private(
            secrets_path,
            json.dumps(
                {
                    "gitea_human_password": secrets.token_urlsafe(32),
                    "gitea_account_password": secrets.token_urlsafe(32),
                    "harbor_admin_password": secrets.token_urlsafe(32),
                    "harbor_database_password": secrets.token_urlsafe(32),
                },
                indent=2,
            )
            + "\n",
        )
    if not INSTALLER.exists():
        urllib.request.urlretrieve(INSTALLER_URL, INSTALLER)
    digest = hashlib.sha256(INSTALLER.read_bytes()).hexdigest()
    if digest != INSTALLER_SHA256:
        raise RuntimeError("Harbor installer checksum mismatch")
    if not HARBOR.exists():
        with tarfile.open(INSTALLER, "r:gz") as archive:
            for member in archive.getmembers():
                if (
                    not member.name.startswith("harbor/")
                    or member.issym()
                    or member.islnk()
                ):
                    raise RuntimeError("unexpected Harbor installer member")
            archive.extractall(STATE, filter="data")
    creds = json.loads(secrets_path.read_text(encoding="utf-8"))
    config = yaml.safe_load((HARBOR / "harbor.yml.tmpl").read_text(encoding="utf-8"))
    config["hostname"] = "harbor.ecommerce.local"
    config["http"]["port"] = 8080
    config["https"] = {
        "port": 8443,
        "certificate": str(server_cert),
        "private_key": str(server_key),
    }
    config["external_url"] = HARBOR_URL.rstrip("/")
    config["harbor_admin_password"] = creds["harbor_admin_password"]
    config["database"]["password"] = creds["harbor_database_password"]
    config["data_volume"] = str(STATE / "data")
    config["log"]["local"]["location"] = str(STATE / "logs")
    config["jobservice"]["max_job_workers"] = 2
    write_private(HARBOR / "harbor.yml", yaml.safe_dump(config, sort_keys=False))
    configure_wsl_host()
    print("PASS local TLS, native state, installer checksum and WSL name resolution")


def provision_gitea() -> None:
    creds_path = STATE / "credentials.json"
    creds = json.loads(creds_path.read_text(encoding="utf-8"))
    listing = subprocess.run(
        [
            "docker",
            "exec",
            "ecommerce-local-management-gitea-1",
            "gitea",
            "admin",
            "user",
            "list",
        ],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    for username, email, key, user_type, is_admin in [
        (
            "dst-red-Wire",
            "141283735+dst-red-Wire@users.noreply.github.com",
            "gitea_human_password",
            "individual",
            True,
        ),
    ]:
        if any(line.split()[1:2] == [username] for line in listing.splitlines()[1:]):
            continue
        command = [
            "docker",
            "exec",
            "ecommerce-local-management-gitea-1",
            "gitea",
            "admin",
            "user",
            "create",
            "--username",
            username,
            "--email",
            email,
            "--password",
            creds[key],
            "--user-type",
            user_type,
            "--must-change-password=false",
        ]
        if is_admin:
            command.append("--admin")
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        if result.returncode:
            raise RuntimeError(
                "Gitea account creation failed: " + result.stderr.strip()
            )
    if "gitea_account_token" not in creds:
        token = subprocess.run(
            [
                "docker",
                "exec",
                "ecommerce-local-management-gitea-1",
                "gitea",
                "admin",
                "user",
                "generate-access-token",
                "--username",
                "dst-red-Wire",
                "--token-name",
                "local-management",
                "--scopes",
                "write:user,write:repository,read:organization",
                "--raw",
            ],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        if not token:
            raise RuntimeError("Gitea automation token was not generated")
        creds["gitea_account_token"] = token
        write_private(creds_path, json.dumps(creds, indent=2) + "\n")
    print("PASS Gitea canonical dst-red-Wire identity")


def harbor_request(
    path: str, password: str, *, method: str = "GET", body: dict | None = None
) -> tuple[int, object]:
    url = HARBOR_URL.rstrip("/") + "/api/v2.0" + path
    token = base64.b64encode(("admin:" + password).encode()).decode()
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={
            "Authorization": "Basic " + token,
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    context = ssl.create_default_context(cafile=str(TLS / "ca.crt"))
    try:
        with urllib.request.urlopen(req, context=context, timeout=15) as response:
            content = response.read()
            return response.status, json.loads(content) if content else {}
    except urllib.error.HTTPError as error:
        content = error.read().decode("utf-8", errors="replace")
        if error.code == 404:
            return 404, {}
        raise RuntimeError(
            f"Harbor API {method} {path}: HTTP {error.code}: {content[:300]}"
        ) from None


def normalize_harbor_permissions(robot: dict) -> frozenset[tuple[str, str]]:
    permissions = robot.get("permissions")
    if not isinstance(permissions, list) or len(permissions) != 1:
        raise RuntimeError("Harbor robot permissions must contain exactly one project scope")
    scope = permissions[0]
    if not isinstance(scope, dict) or scope.get("kind") != "project" or scope.get("namespace") != "ecommerce":
        raise RuntimeError("Harbor robot scope differs from contract")
    access = scope.get("access")
    if not isinstance(access, list):
        raise RuntimeError("Harbor robot access permissions are malformed")
    actual = []
    for item in access:
        if not isinstance(item, dict) or item.get("resource") != "repository" or not isinstance(item.get("action"), str):
            raise RuntimeError("Harbor robot repository permissions are malformed")
        actual.append((item["resource"], item["action"]))
    expected = frozenset({("repository", "pull"), ("repository", "push")})
    if frozenset(actual) != expected or len(actual) != len(expected):
        raise RuntimeError("Harbor robot permissions differ from exact pull/push contract")
    return expected


def provision_harbor() -> None:
    creds_path = STATE / "credentials.json"
    creds = json.loads(creds_path.read_text(encoding="utf-8"))
    admin_password = creds["harbor_admin_password"]
    status, _ = harbor_request("/projects/ecommerce", admin_password)
    if status == 404:
        harbor_request(
            "/projects",
            admin_password,
            method="POST",
            body={
                "project_name": "ecommerce",
                "metadata": {"public": "false", "auto_scan": "true"},
            },
        )
    robot_id = creds.get("harbor_robot_id")
    if robot_id:
        status, robot = harbor_request(f"/robots/{robot_id}", admin_password)
        if status == 404 or robot.get("name") != creds.get("harbor_robot_username"):
            raise RuntimeError("stored Harbor robot identity does not match runtime")
    else:
        creds["harbor_robot_secret"] = secrets.token_urlsafe(32)
        write_private(creds_path, json.dumps(creds, indent=2) + "\n")
        _, created = harbor_request(
            "/robots",
            admin_password,
            method="POST",
            body={
                "name": "ecommerce-ci",
                "description": "Dedicated ecommerce CI robot",
                "level": "project",
                "duration": 90,
                "secret": creds["harbor_robot_secret"],
                "permissions": [
                    {
                        "kind": "project",
                        "namespace": "ecommerce",
                        "access": [
                            {"resource": "repository", "action": "pull"},
                            {"resource": "repository", "action": "push"},
                        ],
                    }
                ],
            },
        )
        creds["harbor_robot_id"] = created["id"]
        creds["harbor_robot_username"] = created["name"]
        write_private(creds_path, json.dumps(creds, indent=2) + "\n")
        harbor_request(
            f"/robots/{created['id']}",
            admin_password,
            method="PATCH",
            body={"secret": creds["harbor_robot_secret"]},
        )
    print("PASS Harbor ecommerce project and scoped ecommerce-ci robot")


def gitea_request(
    path: str,
    token: str | None = None,
    *,
    method: str = "GET",
    body: dict | None = None,
) -> tuple[int, object]:
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = "token " + token
    if body is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(
        GITEA_URL.rstrip("/") + "/api/v1" + path,
        method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers=headers,
    )
    context = ssl.create_default_context(cafile=str(TLS / "ca.crt"))
    with urllib.request.urlopen(req, context=context, timeout=15) as response:
        content = response.read()
        return response.status, json.loads(content) if content else {}


def register_gpg() -> None:
    expected = yaml.safe_load((ROOT / "architecture.lock.yaml").read_text())["repository_governance"]["automation_signing"]["automation_key"]["fingerprint"]
    proof = json.loads((ROOT / ".context/reboot-proof/result.json").read_text())
    before = datetime.fromisoformat(
        proof["baseline_windows_boot_utc"].replace("Z", "+00:00")
    )
    after = datetime.fromisoformat(
        proof["observed_windows_boot_utc"].replace("Z", "+00:00")
    )
    if (
        proof["status"] != "PASS"
        or proof["observed_fingerprint"] != expected
        or after <= before
        or proof["passphrase_prompt"] != "none"
    ):
        raise RuntimeError("real Windows reboot signing proof is not PASS")
    verified = subprocess.run(
        ["git", "verify-commit", "--raw", proof["signed_commit"]],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    if f"[GNUPG:] VALIDSIG {expected}" not in verified.stderr + verified.stdout:
        raise RuntimeError("reboot proof commit signature differs from automation key")
    creds = json.loads((STATE / "credentials.json").read_text())
    token = creds["gitea_account_token"]
    _, user = gitea_request("/user", token)
    if user["login"] != "dst-red-Wire":
        raise RuntimeError("Gitea token does not belong to the automation identity")
    _, existing = gitea_request("/user/gpg_keys", token)
    if not any(key.get("key_id") == expected[-16:] for key in existing):
        public = subprocess.run(
            ["gpg", "--batch", "--armor", "--export", expected],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        if "BEGIN PGP PUBLIC KEY BLOCK" not in public or "PRIVATE KEY" in public:
            raise RuntimeError("public key export is invalid")
        gitea_request(
            "/user/gpg_keys", token, method="POST", body={"armored_public_key": public}
        )
    _, keys = gitea_request("/user/gpg_keys", token)
    if not any(key.get("key_id") == expected[-16:] for key in keys):
        raise RuntimeError("automation GPG key is absent from its Gitea account")
    print("PASS automation GPG public key registered on dst-red-Wire")


def verify_running_images() -> None:
    compose_json = subprocess.run(
        [
            "docker",
            "compose",
            "-f",
            str(HARBOR / "docker-compose.yml"),
            "config",
            "--format",
            "json",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    config = json.loads(compose_json.stdout)
    expected = {
        service["container_name"]: service["image"]
        for service in config["services"].values()
    }
    expected.update(
        {
            "ecommerce-local-management-gitea-1": "docker.gitea.com/gitea@sha256:"
            "1c17ecaead42eb3b5391553d8708103a4beb0e86edf5b9ebc1eb269c318845f2",
            "ecommerce-local-management-edge-1": "caddy@sha256:c3d7ee5d2b11f9dc54f947f68a734c84e9c9666c92c88a7f30b9cba5da182adb",
        }
    )
    for container, pinned in expected.items():
        actual = subprocess.run(
            ["docker", "inspect", container, "--format", "{{.Config.Image}}"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        if actual != pinned:
            raise RuntimeError(f"running image differs from lock: {container}")


def proof() -> None:
    creds = json.loads((STATE / "credentials.json").read_text())
    expected = yaml.safe_load((ROOT / "architecture.lock.yaml").read_text())["repository_governance"]["automation_signing"]["automation_key"]["fingerprint"]
    for hostname in ("gitea.ecommerce.local", "harbor.ecommerce.local"):
        if "127.0.0.1" not in {
            record[4][0]
            for record in socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
        }:
            raise RuntimeError(f"local DNS does not resolve {hostname}")
    context = ssl.create_default_context(cafile=str(TLS / "ca.crt"))
    with urllib.request.urlopen(
        GITEA_URL.rstrip("/") + "/api/healthz", context=context, timeout=15
    ) as response:
        gitea_health = json.load(response)
    if gitea_health["status"] != "pass":
        raise RuntimeError("Gitea is unhealthy")
    _, user = gitea_request("/user", creds["gitea_account_token"])
    if user["login"] != "dst-red-Wire":
        raise RuntimeError("Gitea automation identity is incorrect")
    _, keys = gitea_request("/user/gpg_keys", creds["gitea_account_token"])
    if not any(key.get("key_id") == expected[-16:] for key in keys):
        raise RuntimeError("automation GPG key is missing from Gitea")
    _, health = harbor_request("/health", creds["harbor_admin_password"])
    if health["status"] != "healthy":
        raise RuntimeError("Harbor is unhealthy")
    _, project = harbor_request("/projects/ecommerce", creds["harbor_admin_password"])
    if project.get("name") != "ecommerce" or project["metadata"]["public"] != "false":
        raise RuntimeError("Harbor project is absent or public")
    _, robot = harbor_request(
        f"/robots/{creds['harbor_robot_id']}", creds["harbor_admin_password"]
    )
    if robot["name"] != creds["harbor_robot_username"] or robot.get("level") != "project":
        raise RuntimeError("Harbor robot identity or level differs from contract")
    normalize_harbor_permissions(robot)
    with tempfile.TemporaryDirectory(dir=STATE) as temporary:
        env = os.environ.copy()
        env["DOCKER_CONFIG"] = temporary
        login = subprocess.run(
            [
                "docker",
                "login",
                "harbor.ecommerce.local",
                "--username",
                creds["harbor_robot_username"],
                "--password-stdin",
            ],
            input=creds["harbor_robot_secret"],
            text=True,
            capture_output=True,
            env=env,
            check=False,
        )
        if login.returncode:
            raise RuntimeError("Harbor robot Docker login failed")
    verify_running_images()
    evidence = {
        "status": "PASS",
        "checked_at_utc": datetime.now(timezone.utc).isoformat(),
        "gitea_url": GITEA_URL,
        "gitea_account": user["login"],
        "gitea_gpg_key_id": expected[-16:],
        "gitea_gpg_fingerprint": expected,
        "harbor_url": HARBOR_URL,
        "harbor_project": project["name"],
        "harbor_robot": robot["name"],
        "harbor_robot_permissions": robot["permissions"],
        "harbor_robot_login": "PASS",
        "local_dns": "PASS",
        "tls_ca_certificate": str(TLS / "ca.crt"),
        "gitea_health": "PASS",
        "harbor_health": "PASS",
        "image_lock": "PASS",
    }
    output = ROOT / ".context/runtime/local-services.json"
    write_private(output, json.dumps(evidence, indent=2) + "\n")
    print(f"PASS local management runtime evidence={output}")


def restrict_harbor_ports() -> None:
    compose = HARBOR / "docker-compose.yml"
    text = compose.read_text(encoding="utf-8")
    for port in (8080, 8443):
        public = f"- {port}:{port}"
        local = f"- 127.0.0.1:{port}:{port}"
        if public in text:
            text = text.replace(public, local, 1)
        elif local not in text:
            raise RuntimeError(f"Harbor generated compose lacks expected port {port}")
    images = json.loads(
        (ROOT / "platform/local-services/harbor-images.lock.json").read_text()
    )["images"]
    if len(images) != 9:
        raise RuntimeError("Harbor image lock is incomplete")
    for tagged, pinned in images.items():
        if not pinned.startswith(tagged.split(":")[0] + "@sha256:"):
            raise RuntimeError("Harbor image lock has a mismatched repository")
        old = f"image: {tagged}"
        new = f"image: {pinned}"
        if old in text:
            text = text.replace(old, new, 1)
        elif new not in text:
            raise RuntimeError(f"Harbor generated compose lacks {tagged}")
    compose.write_text(text, encoding="utf-8")


def wait_for_health(seconds: int = 120) -> None:
    deadline = time.monotonic() + seconds
    password = json.loads((STATE / "credentials.json").read_text())[
        "harbor_admin_password"
    ]
    context = ssl.create_default_context(cafile=str(TLS / "ca.crt"))
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(
                GITEA_URL.rstrip("/") + "/api/healthz", context=context, timeout=3
            ) as response:
                gitea_healthy = json.load(response).get("status") == "pass"
            _, harbor = harbor_request("/health", password)
            if gitea_healthy and harbor.get("status") == "healthy":
                return
        except (OSError, ValueError, RuntimeError):
            pass
        time.sleep(2)
    raise RuntimeError("Gitea/Harbor did not become healthy within 120 seconds")


def up() -> None:
    initialize()
    env = os.environ.copy()
    env["GITEA_HTTPS_URL"] = GITEA_URL
    env["LOCAL_TLS_DIR"] = str(TLS)
    run(
        "docker",
        "compose",
        "-f",
        str(ROOT / "platform/local-services/compose.yaml"),
        "up",
        "-d",
        env=env,
    )
    if not (HARBOR / "docker-compose.yml").exists():
        run(str(HARBOR / "prepare"), cwd=HARBOR)
    restrict_harbor_ports()
    run("docker", "compose", "up", "-d", cwd=HARBOR)
    wait_for_health()
    print("PASS local services healthy")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "action",
        choices=["init", "up", "gitea-users", "harbor-robot", "register-gpg", "proof"],
    )
    args = parser.parse_args()
    {
        "init": initialize,
        "up": up,
        "gitea-users": provision_gitea,
        "harbor-robot": provision_harbor,
        "register-gpg": register_gpg,
        "proof": proof,
    }[args.action]()
