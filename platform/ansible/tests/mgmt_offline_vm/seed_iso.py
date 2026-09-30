#!/usr/bin/env python3
"""Build and verify a local, passwordless NoCloud ISO for one isolated MGMT VM."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys


POWERSHELL = Path("/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe")
VM_NAME = re.compile(r"ecommerce-mgmt-test-[a-z0-9-]+\Z")
NONCE = re.compile(r"[0-9a-f]{32}\Z")
SEED_FILES = {"meta-data", "user-data", "network-config"}
MAX_SCRIPT_BYTES = 8192
MAX_ISO_BYTES = 16 * 1024 * 1024


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def windows_path(path: Path, *, allow_unc: bool = False) -> str:
    value = subprocess.check_output(["wslpath", "-w", str(path)], text=True).strip()
    if re.fullmatch(r"[A-Za-z]:\\.+", value) is None and not (
        allow_unc and value.startswith("\\\\wsl.localhost\\")
    ):
        raise ValueError("NoCloud ISO must live in a native Windows-accessible state directory")
    return value


def public_key(path: Path) -> str:
    raw = path.read_text(encoding="ascii")
    if not raw.endswith("\n") or raw.count("\n") != 1:
        raise ValueError("fixture SSH public key must be exactly one terminated line")
    parts = raw[:-1].split(" ")
    if len(parts) != 3 or parts[0] != "ssh-ed25519" or parts[2] != "ecommerce-local-vm-test":
        raise ValueError("fixture SSH public key type or identity differs")
    try:
        decoded = base64.b64decode(parts[1], validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("fixture SSH public key encoding is invalid") from exc
    if not decoded.startswith(b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20"):
        raise ValueError("fixture SSH public key wire format is invalid")
    if len(decoded) != 51:
        raise ValueError("fixture SSH public key length is invalid")
    return raw[:-1]


def guest_script(path: Path) -> bytes:
    value = path.read_bytes()
    if not value or len(value) > MAX_SCRIPT_BYTES or b"\x00" in value or b"\r" in value:
        raise ValueError("guest access script is absent, oversized or not LF shell text")
    if b"set -eu\n" not in value[:80]:
        raise ValueError("guest access script must fail closed with set -eu")
    value.decode("utf-8")
    return value


def boot_verifier(nonce: str) -> bytes:
    script = f"""#!/usr/bin/env bash
set -euo pipefail
stage=guest_access
report_failure() {{
  local rc=$?
  trap - EXIT
  if [ "$rc" -eq 0 ]; then return 0; fi
  {{
    printf 'MGMT_BOOTSTRAP_FAIL:%s stage=%s rc=%s\\n' '{nonce}' "$stage" "$rc"
    if [ -r /var/log/ecommerce-mgmt-guest-access.log ]; then
      LC_ALL=C tail -n 12 /var/log/ecommerce-mgmt-guest-access.log |
        LC_ALL=C cut -c1-200 |
        LC_ALL=C tr -cd '\\11\\12\\40-\\176' |
        sed 's/^/MGMT_BOOTSTRAP_LOG:/'
    fi
  }} > /dev/ttyS0 2>/dev/null || true
  exit "$rc"
}}
trap report_failure EXIT
bash /root/ecommerce-mgmt-guest-access.sh > /var/log/ecommerce-mgmt-guest-access.log 2>&1
stage=selinux
test "$(getenforce)" = Enforcing
stage=packer_account
passwd --status packer | grep -Eq '^packer[[:space:]]+L'
test "$(stat -c '%U:%G:%a' /home/packer/.ssh/authorized_keys)" = 'packer:packer:600'
stage=sshd
sshd -t
sshd -T | grep -qx 'passwordauthentication no'
sshd -T | grep -qx 'kbdinteractiveauthentication no'
sshd -T | grep -qx 'permitrootlogin no'
sshd -T | grep -qx 'authenticationmethods publickey'
stage=nft
nft -j list table inet ecommerce_test_offline | python3 -c 'import json,sys; rows=json.load(sys.stdin)["nftables"]; policies={{row["chain"]["name"]:row["chain"].get("policy") for row in rows if "chain" in row}}; assert policies=={{"output":"drop","forward":"drop"}}'
stage=host_key
read -r key_type key_blob _ < /etc/ssh/ssh_host_ed25519_key.pub
test "$key_type" = ssh-ed25519
[[ "$key_blob" =~ ^[A-Za-z0-9+/]+={{0,2}}$ ]]
stage=serial
printf 'MGMT_BOOTSTRAP_READY:%s MGMT_HOST_KEY:%s %s\\n' '{nonce}' "$key_type" "$key_blob" > /dev/ttyS0
"""
    return script.encode("utf-8")


def seed_bytes(*, vm_name: str, nonce: str, key: str, script: bytes,
               vm_address: str, vm_mac: str) -> tuple[bytes, bytes, bytes]:
    meta = f"instance-id: {vm_name}-{nonce}\nlocal-hostname: {vm_name}\n".encode()
    user = (
        "#cloud-config\n"
        "disable_root: true\n"
        "disable_network_activation: true\n"
        "ssh_pwauth: false\n"
        "ssh_deletekeys: true\n"
        "ssh_genkeytypes: [ed25519]\n"
        "package_update: false\n"
        "package_upgrade: false\n"
        "users:\n"
        "  - name: packer\n"
        "    lock_passwd: true\n"
        "    ssh_authorized_keys:\n"
        f"      - {key}\n"
        "write_files:\n"
        "  - path: /root/ecommerce-mgmt-guest-access.sh\n"
        "    owner: root:root\n"
        "    permissions: '0700'\n"
        "    encoding: b64\n"
        f"    content: {base64.b64encode(script).decode()}\n"
        "  - path: /root/ecommerce-mgmt-boot-verify.sh\n"
        "    owner: root:root\n"
        "    permissions: '0700'\n"
        "    encoding: b64\n"
        f"    content: {base64.b64encode(boot_verifier(nonce)).decode()}\n"
        "runcmd:\n"
        "  - [bash, /root/ecommerce-mgmt-boot-verify.sh]\n"
    ).encode()
    colon_mac = ":".join(vm_mac[i:i + 2] for i in range(0, 12, 2)).lower()
    network = (
        "version: 2\n"
        "ethernets:\n"
        "  mgmt:\n"
        "    match:\n"
        f"      macaddress: {colon_mac}\n"
        "    dhcp4: false\n"
        "    dhcp6: false\n"
        f"    addresses: [{vm_address}/24]\n"
    ).encode()
    return meta, user, network


def validate_network(vm_address: str, host_address: str, vm_mac: str) -> None:
    if re.fullmatch(r"02[0-9A-Fa-f]{10}", vm_mac) is None:
        raise ValueError("NoCloud seed requires the owned locally administered MAC")
    guest = ipaddress.IPv4Address(vm_address)
    host = ipaddress.IPv4Address(host_address)
    network = ipaddress.IPv4Network(f"{host}/24", strict=False)
    if (not guest.is_private or not host.is_private or guest == host or
            guest not in network or guest in (network.network_address, network.broadcast_address) or
            host in (network.network_address, network.broadcast_address)):
        raise ValueError("NoCloud guest and host must have distinct private addresses in one /24")


def joliet_files(contents: bytes) -> dict[str, bytes]:
    descriptor = next(
        (
            contents[index * 2048:(index + 1) * 2048]
            for index in range(17, 20)
            if contents[index * 2048:index * 2048 + 7] == b"\x02CD001\x01"
        ),
        None,
    )
    if descriptor is None or descriptor[88:91] not in {b"%/@", b"%/C", b"%/E"}:
        raise ValueError("NoCloud ISO lacks a valid Joliet supplementary descriptor")
    root = descriptor[156:190]
    extent = int.from_bytes(root[2:6], "little")
    size = int.from_bytes(root[10:14], "little")
    if not 0 < size <= 16384 or (extent * 2048 + size) > len(contents):
        raise ValueError("NoCloud ISO Joliet root directory is out of bounds")
    directory = contents[extent * 2048:extent * 2048 + size]
    files: dict[str, bytes] = {}
    offset = 0
    while offset < len(directory):
        length = directory[offset]
        if length == 0:
            offset = ((offset // 2048) + 1) * 2048
            continue
        entry = directory[offset:offset + length]
        if length < 34 or len(entry) != length:
            raise ValueError("NoCloud ISO contains a malformed Joliet entry")
        name_length = entry[32]
        if name_length in (1,) and entry[33] in (0, 1):
            offset += length
            continue
        try:
            name = entry[33:33 + name_length].decode("utf-16-be").removesuffix(";1")
        except UnicodeError as exc:
            raise ValueError("NoCloud ISO Joliet file name is malformed") from exc
        if name in files or name not in SEED_FILES or entry[25] & 0x02:
            raise ValueError("NoCloud ISO contains unexpected or duplicate files")
        file_extent = int.from_bytes(entry[2:6], "little")
        file_size = int.from_bytes(entry[10:14], "little")
        if not 0 < file_size <= MAX_SCRIPT_BYTES * 4 or file_extent * 2048 + file_size > len(contents):
            raise ValueError("NoCloud ISO Joliet file extent is invalid")
        files[name] = contents[file_extent * 2048:file_extent * 2048 + file_size]
        offset += length
    if set(files) != SEED_FILES:
        raise ValueError("NoCloud ISO does not contain its three exact seed files")
    return files


def checked_iso(path: Path, expected_files: dict[str, bytes]) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError("NoCloud ISO is missing or redirected")
    size = path.stat().st_size
    if size < 32768 + 2048 or size > MAX_ISO_BYTES or size % 2048:
        raise ValueError("NoCloud ISO has an invalid bounded size")
    contents = path.read_bytes()
    descriptor = contents[16 * 2048:17 * 2048]
    if descriptor[:7] != b"\x01CD001\x01" or descriptor[40:72].rstrip(b" ") != b"CIDATA":
        raise ValueError("NoCloud ISO lacks the expected CIDATA volume descriptor")
    if joliet_files(contents) != expected_files:
        raise ValueError("NoCloud ISO file bytes differ from generated seed inputs")
    return digest(contents)


def write_new(path: Path, data: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(data)


def result_bytes(result: dict[str, object]) -> bytes:
    return (json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n").encode()


def generate(state: Path, vm_name: str, script: bytes, key: str, *,
             vm_address: str, host_address: str, vm_mac: str,
             reuse: bool) -> dict[str, object]:
    if VM_NAME.fullmatch(vm_name) is None:
        raise ValueError("NoCloud seed requires the owned MGMT VM name")
    validate_network(vm_address, host_address, vm_mac)
    if state.is_symlink() or not state.is_dir():
        raise ValueError("owned Windows state directory is absent or redirected")
    state = state.resolve(strict=True)
    seed = state / "seed"
    iso = state / "seed.iso"
    result_path = state / "seed-result.json"
    iso_windows = windows_path(iso)
    if reuse:
        if result_path.is_symlink() or not result_path.is_file():
            raise ValueError("NoCloud reuse requires a recorded seed result")
        saved_bytes = result_path.read_bytes()
        saved = json.loads(saved_bytes)
        if not isinstance(saved, dict) or saved_bytes != result_bytes(saved):
            raise ValueError("NoCloud seed result is malformed")
        nonce = saved.get("nonce")
        if not isinstance(nonce, str) or NONCE.fullmatch(nonce) is None:
            raise ValueError("NoCloud seed nonce is invalid")
    else:
        if seed.exists() or seed.is_symlink() or iso.exists() or iso.is_symlink() or result_path.exists() or result_path.is_symlink():
            raise ValueError("NoCloud seed already exists; explicit verified reuse is required")
        nonce = secrets.token_hex(16)
    meta, user, network = seed_bytes(
        vm_name=vm_name, nonce=nonce, key=key, script=script,
        vm_address=vm_address, vm_mac=vm_mac,
    )
    if reuse:
        if seed.is_symlink() or not seed.is_dir() or {entry.name for entry in seed.iterdir()} != SEED_FILES:
            raise ValueError("NoCloud seed directory differs from the expected two files")
        for name, expected in (("meta-data", meta), ("user-data", user),
                               ("network-config", network)):
            path = seed / name
            if path.is_symlink() or not path.is_file() or path.read_bytes() != expected:
                raise ValueError(f"NoCloud {name} differs from the bound inputs")
    else:
        seed.mkdir(mode=0o700)
        write_new(seed / "meta-data", meta)
        write_new(seed / "user-data", user)
        write_new(seed / "network-config", network)
        if not POWERSHELL.is_file():
            raise ValueError("native Windows PowerShell is unavailable for the offline ISO")
        subprocess.run(
            [str(POWERSHELL), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
             "-File", windows_path(Path(__file__).with_suffix(".ps1").resolve(), allow_unc=True),
             "-SeedDir", windows_path(seed), "-IsoPath", iso_windows],
            check=True, capture_output=True, text=True, timeout=90,
        )
    result = {
        "schema_version": 1,
        "status": "PASS",
        "vm_name": vm_name,
        "nonce": nonce,
        "iso_path": iso_windows,
        "sha256": checked_iso(
            iso, {"meta-data": meta, "user-data": user, "network-config": network}
        ),
        "meta_data_sha256": digest(meta),
        "user_data_sha256": digest(user),
        "network_config_sha256": digest(network),
        "guest_script_sha256": digest(script),
        "public_key_sha256": digest((key + "\n").encode()),
    }
    if reuse:
        if saved != result:
            raise ValueError("NoCloud seed result differs from verified ISO or current inputs")
    else:
        write_new(result_path, result_bytes(result))
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--guest-script", required=True, type=Path)
    parser.add_argument("--public-key", required=True, type=Path)
    parser.add_argument("--vm-name", required=True)
    parser.add_argument("--vm-address", required=True)
    parser.add_argument("--host-address", required=True)
    parser.add_argument("--vm-mac", required=True)
    parser.add_argument("--reuse-existing", action="store_true")
    args = parser.parse_args()
    try:
        result = generate(
            args.state, args.vm_name, guest_script(args.guest_script),
            public_key(args.public_key), vm_address=args.vm_address,
            host_address=args.host_address, vm_mac=args.vm_mac,
            reuse=args.reuse_existing,
        )
    except (OSError, ValueError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        print(f"FAIL: NoCloud ISO seed: {exc}", file=sys.stderr)
        return 1
    sys.stdout.buffer.write(result_bytes(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
