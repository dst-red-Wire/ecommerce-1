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


def verify_bundle_rpms(artifacts, installed_rows, compare_versions):
    """Accept exact bundle NEVRAs or newer RPMs already supplied by the image."""
    installed = {}
    for row in installed_rows:
        name, epoch, version, release, arch = row.split("\t")
        nevra = f"{name}-{epoch}:{version}-{release}.{arch}"
        installed.setdefault((name, arch), []).append(((epoch, version, release), nevra))
    all_nevras = {nevra for variants in installed.values() for _, nevra in variants}
    superseded = []
    exact = 0
    for item in artifacts:
        if item["category"] != "rpm":
            continue
        expected = item["nevra"]
        if expected in all_nevras:
            exact += 1
            continue
        name = item["package"]
        suffix = expected.removeprefix(name + "-")
        assert suffix != expected, "manifest package and NEVRA differ"
        epoch, version_release = suffix.split(":", 1)
        version, release_arch = version_release.rsplit("-", 1)
        release, arch = release_arch.rsplit(".", 1)
        newer = [
            nevra for label, nevra in installed.get((name, arch), ())
            if compare_versions(label, (epoch, version, release)) > 0
        ]
        assert newer, f"manifest RPM is absent without a newer installed image package: {expected}"
        superseded.append({"expected_nevra": expected, "installed_nevra": sorted(newer)[-1]})
    return exact, sorted(superseded, key=lambda row: row["expected_nevra"])


def main():
    restage = "--before-restage" in sys.argv or "--restage" in sys.argv
    selinux = output("getenforce")
    assert selinux == "Enforcing", "SELinux must remain enforcing"
    routes = json.loads(output("ip", "-j", "route"))
    routes6 = json.loads(output("ip", "-j", "-6", "route"))
    with socket.socket() as connection:
        connection.settimeout(3)
        errno = connection.connect_ex(("1.1.1.1", 443))
    if restage:
        assert errno != 0, "public connection must remain denied during restaging"
        table = "ecommerce_mgmt_bootstrap"
    else:
        assert not any(row.get("dst") == "default" for row in routes + routes6)
        assert errno == 101, "public connection must fail with ENETUNREACH"
        table = "ecommerce_test_offline"
    nft = json.loads(output("nft", "-j", "list", "table", "inet", table))
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
        "rocky_release": Path("/etc/rocky-release").read_text().strip(),
        "selinux": selinux,
        "ssh_access": ssh_access,
        "kernel": output("uname", "-r"),
        "online_cpus": os.cpu_count(),
        "memory_kib": int(next(line.split()[1] for line in Path("/proc/meminfo").read_text().splitlines()
                               if line.startswith("MemTotal:"))),
        "systemd": systemd.stdout.strip(),
        "public_connect_errno": errno,
        "ipv4_routes": routes,
        "ipv6_routes": routes6,
        "nft_policies": policies,
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
    }
    if len(sys.argv) > 1 and sys.argv[1] in {"--before", "--before-restage"}:
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
        import rpm
        installed_rows = output(
            "rpm", "-qa", "--queryformat", "%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n"
        ).splitlines()
        exact, superseded = verify_bundle_rpms(
            manifest["artifacts"], installed_rows, rpm.labelCompare
        )
        images = {}
        for item in manifest["artifacts"]:
            if item["category"] in {"images-core", "images-cilium"}:
                path = Path("/var/lib/rancher/rke2/agent/images") / item["file"]
                actual = sha256(path)
                assert actual == item["sha256"], "staged image bytes differ from approved archive"
                if "--hardlink-images" in sys.argv:
                    source = manifest_path.parent / item["file"]
                    assert source.stat().st_ino == path.stat().st_ino, "fixture image is not a hardlink"
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
            exact_installed_rpms=exact,
            newer_image_rpms=superseded,
            bundle_rpm_dependencies_satisfied=exact + len(superseded),
            staged_images=images,
            manifest_rke2_version=manifest["rke2_version"],
            rke2_selinux_modules=[row for row in output("semodule", "-l").splitlines() if "rke2" in row],
            rke2_service_states=services,
        )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
