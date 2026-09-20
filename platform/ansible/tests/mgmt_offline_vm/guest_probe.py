"""Read-only local VM proof; run as root through SSH, optionally with a manifest pin."""

import hashlib
import json
import os
import re
import socket
import subprocess
import sys
from pathlib import Path


def output(*argv):
    return subprocess.check_output(argv, text=True).strip()


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main():
    selinux = output("getenforce")
    assert selinux == "Enforcing", "SELinux must remain enforcing"
    routes = json.loads(output("ip", "-j", "route"))
    routes6 = json.loads(output("ip", "-j", "-6", "route"))
    assert not any(row.get("dst") == "default" for row in routes + routes6)
    with socket.socket() as connection:
        connection.settimeout(3)
        errno = connection.connect_ex(("1.1.1.1", 443))
    assert errno == 101, "public connection must fail with ENETUNREACH"
    nft = json.loads(output("nft", "-j", "list", "table", "inet", "ecommerce_test_offline"))
    policies = {row["chain"]["name"]: row["chain"].get("policy") for row in nft["nftables"] if "chain" in row}
    assert policies == {"output": "drop", "forward": "drop"}
    sshd = dict(line.split(" ", 1) for line in output("/usr/sbin/sshd", "-T").splitlines())
    ssh_access = {
        key: sshd[key]
        for key in (
            "passwordauthentication",
            "kbdinteractiveauthentication",
            "permitrootlogin",
            "authenticationmethods",
        )
    }
    assert ssh_access == {
        "passwordauthentication": "no",
        "kbdinteractiveauthentication": "no",
        "permitrootlogin": "no",
        "authenticationmethods": "publickey",
    }, "only the generated non-root SSH identity may authenticate"
    systemd = subprocess.run(["systemctl", "is-system-running"], text=True, capture_output=True, check=False)
    result = {
        "selinux": selinux,
        "ssh_access": ssh_access,
        "kernel": output("uname", "-r"),
        "online_cpus": os.cpu_count(),
        "systemd": systemd.stdout.strip(),
        "public_connect_errno": errno,
        "ipv4_routes": routes,
        "ipv6_routes": routes6,
        "nft_policies": policies,
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
    }
    if len(sys.argv) > 1 and sys.argv[1] == "--before":
        packages = output(
            "rpm", "-qa", "--queryformat", "%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n"
        ).splitlines()
        paths = {
            name: Path(name).exists()
            for name in ("/var/lib/ecommerce/bootstrap", "/var/lib/rancher/rke2", "/usr/local/bin/rke2")
        }
        result.update(
            installed_nevras=sorted(packages),
            rke2_paths_present=paths,
            cold_artifact_target=not any(paths.values()) and not any(name.startswith("rke2-") for name in packages),
        )
    elif len(sys.argv) > 1:
        pin = sys.argv[1]
        assert re.fullmatch(r"[0-9a-f]{64}", pin)
        manifest_path = Path("/var/lib/ecommerce/bootstrap") / pin / "manifest.json"
        assert sha256(manifest_path) == pin
        manifest = json.loads(manifest_path.read_text())
        expected = {item["nevra"] for item in manifest["artifacts"] if item["category"] == "rpm"}
        installed = set(
            output("rpm", "-qa", "--queryformat", "%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n").splitlines()
        )
        assert expected <= installed, "manifest NEVRAs missing after installation"
        images = {}
        for item in manifest["artifacts"]:
            if item["category"] in {"images-core", "images-cilium"}:
                path = Path("/var/lib/rancher/rke2/agent/images") / item["file"]
                actual = sha256(path)
                assert actual == item["sha256"], "staged image bytes differ from approved archive"
                images[path.name] = actual
        assert len(images) == 2
        services = subprocess.run(
            ["systemctl", "is-active", "rke2-server.service", "rke2-agent.service"],
            text=True,
            capture_output=True,
            check=False,
        ).stdout.splitlines()
        assert services and "active" not in services, "RKE2 startup is outside this artifact-only trial"
        result.update(
            manifest_sha256=pin,
            exact_installed_rpms=len(expected),
            staged_images=images,
            manifest_rke2_version=manifest["rke2_version"],
            rke2_selinux_modules=[row for row in output("semodule", "-l").splitlines() if "rke2" in row],
            rke2_service_states=services,
        )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
