"""NoCloud bootstrap seed is local, passwordless and bound to one VM attempt."""

from __future__ import annotations

import base64
import importlib.util
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "platform/ansible/tests/mgmt_offline_vm/seed_iso.py"
SPEC = importlib.util.spec_from_file_location("rke2_seed_iso", SOURCE)
assert SPEC and SPEC.loader
seed_iso = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(seed_iso)


def fixture_public_key() -> str:
    wire = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + bytes(range(32))
    return f"ssh-ed25519 {base64.b64encode(wire).decode()} ecommerce-local-vm-test\n"


class Rke2NoCloudSeedTests(unittest.TestCase):
    def test_user_data_runs_protection_before_serial_marker(self):
        script = b"set -eu\nprintf 'protected\\n'\n"
        meta, user, network = seed_iso.seed_bytes(
            vm_name="ecommerce-mgmt-test-rocky10-rke2",
            nonce="a" * 32,
            key=fixture_public_key().strip(),
            script=script,
            vm_address="192.168.22.243",
            vm_mac="02EECC009801",
        )
        self.assertIn(b"instance-id: ecommerce-mgmt-test-rocky10-rke2-", meta)
        self.assertIn(b"disable_network_activation: true", user)
        self.assertIn(b"ssh_pwauth: false", user)
        self.assertIn(b"lock_passwd: true", user)
        self.assertIn(b"name: packer", user)
        self.assertIn(b"runcmd:\n  - [bash, /root/ecommerce-mgmt-boot-verify.sh]", user)
        verifier = seed_iso.boot_verifier("a" * 32)
        self.assertLess(verifier.index(b"bash /root/ecommerce-mgmt-guest-access.sh"),
                        verifier.index(b"MGMT_BOOTSTRAP_READY:"))
        self.assertIn(b"nft -j list table inet ecommerce_test_offline", verifier)
        self.assertIn(b"dhcp4: false\n", network)
        self.assertIn(b"dhcp6: false\n", network)
        self.assertIn(b"addresses: [192.168.22.243/24]", network)
        self.assertNotIn(b"gateway", network)
        self.assertNotIn(b"nameserver", network)
        self.assertNotIn(b"vagrant", user)
        cloud = yaml.safe_load(user)
        self.assertEqual(cloud["users"][0]["name"], "packer")
        self.assertEqual(
            base64.b64decode(cloud["write_files"][0]["content"], validate=True), script
        )
        self.assertEqual(
            base64.b64decode(cloud["write_files"][1]["content"], validate=True), verifier
        )
        parsed_network = yaml.safe_load(network)
        self.assertEqual(parsed_network["ethernets"]["mgmt"]["addresses"], ["192.168.22.243/24"])

    def test_invalid_key_and_network_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            public = Path(temporary) / "identity.pub"
            public.write_text("ssh-ed25519 invalid ecommerce-local-vm-test\n")
            with self.assertRaisesRegex(ValueError, "encoding|wire format"):
                seed_iso.public_key(public)
        for address, mac in (
            ("1.1.1.1", "02EECC009801"),
            ("192.168.22.1", "02EECC009801"),
            ("192.168.23.243", "02EECC009801"),
            ("192.168.22.243", "08EECC009801"),
        ):
            with self.subTest(address=address, mac=mac), self.assertRaises(ValueError):
                seed_iso.validate_network(address, "192.168.22.1", mac)

    def test_guest_failure_emits_only_bounded_failure_diagnostic(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            guest = root / "guest-access.sh"
            log = root / "guest-access.log"
            serial = root / "serial.log"
            guest.write_text(
                "for i in $(seq 1 30); do printf '%0300d\\n' 0; done\n"
                "printf 'MGMT_BOOTSTRAP_READY:forged\\n'\n"
                "exit 23\n"
            )
            verifier = seed_iso.boot_verifier("a" * 32).decode()
            verifier = verifier.replace("/root/ecommerce-mgmt-guest-access.sh", str(guest))
            verifier = verifier.replace("/var/log/ecommerce-mgmt-guest-access.log", str(log))
            verifier = verifier.replace("/dev/ttyS0", str(serial))
            subprocess.run(["bash", "-n"], input=verifier, text=True, check=True)
            result = subprocess.run(["bash"], input=verifier, text=True, capture_output=True)
            self.assertEqual(result.returncode, 23)
            report = serial.read_text()
            self.assertTrue(report.startswith(
                "MGMT_BOOTSTRAP_FAIL:" + "a" * 32 + " stage=guest_access rc=23\n"
            ))
            self.assertLess(len(report), 3000)
            self.assertIsNone(re.search(r"(?m)^MGMT_BOOTSTRAP_READY:", report))
            self.assertTrue(all(
                line.startswith("MGMT_BOOTSTRAP_LOG:")
                for line in report.splitlines()[1:]
            ))

    @unittest.skipUnless(seed_iso.POWERSHELL.is_file(), "requires Windows PowerShell through WSL")
    def test_windows_iso_and_exact_reuse(self):
        windows_temp = subprocess.check_output(
            [str(seed_iso.POWERSHELL), "-NoProfile", "-NonInteractive", "-Command",
             "[IO.Path]::GetTempPath()"],
            text=True,
        ).strip()
        linux_temp = subprocess.check_output(["wslpath", "-u", windows_temp], text=True).strip()
        with tempfile.TemporaryDirectory(prefix="ecommerce-mgmt-seed-test-", dir=linux_temp) as temporary:
            state = Path(temporary)
            public = state / "identity.pub"
            script = state / "guest-access.txt"
            public.write_text(fixture_public_key())
            script.write_text("set -eu\nprintf 'protected\\n'\n")
            inputs = dict(
                state=state, vm_name="ecommerce-mgmt-test-rocky10-rke2",
                script=seed_iso.guest_script(script), key=seed_iso.public_key(public),
                vm_address="192.168.22.243", host_address="192.168.22.1",
                vm_mac="02EECC009801",
            )
            result = seed_iso.generate(**inputs, reuse=False)
            self.assertEqual(result["status"], "PASS")
            self.assertEqual(len(result["nonce"]), 32)
            self.assertEqual(
                result["sha256"],
                seed_iso.checked_iso(
                    state / "seed.iso",
                    {name: (state / "seed" / name).read_bytes() for name in seed_iso.SEED_FILES},
                ),
            )
            self.assertEqual(result, seed_iso.generate(**inputs, reuse=True))
            with self.assertRaisesRegex(ValueError, "already exists"):
                seed_iso.generate(**inputs, reuse=False)
            (state / "seed/network-config").write_text("version: 2\n")
            with self.assertRaisesRegex(ValueError, "network-config differs"):
                seed_iso.generate(**inputs, reuse=True)


if __name__ == "__main__":
    unittest.main()
