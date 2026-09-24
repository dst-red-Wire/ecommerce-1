import json
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
ARCHITECTURE = ROOT / "architecture.lock.yaml"
MACHINE_LOCK = ROOT / "config/contracts/machine-image-lock.yaml"
TOOLCHAIN_LOCK = ROOT / "config/contracts/toolchain-lock.json"
PACKER = ROOT / "platform/packer/rocky-10.2/rocky-10.2.pkr.hcl"
LINUX_PIPELINE = ROOT / "scripts/linux_image_pipeline.py"


class LinuxPackerPipelineTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.architecture = yaml.safe_load(ARCHITECTURE.read_text(encoding="utf-8"))
        cls.machine = yaml.safe_load(MACHINE_LOCK.read_text(encoding="utf-8"))
        cls.toolchain = json.loads(TOOLCHAIN_LOCK.read_text(encoding="utf-8"))
        cls.packer = PACKER.read_text(encoding="utf-8")
        cls.pipeline = LINUX_PIPELINE.read_text(encoding="utf-8")

    def test_linux_profile_has_one_authority_per_responsibility(self):
        root = self.architecture["tooling"]["local_vm_image_pipeline"]
        profile = root["profiles"]["linux"]
        self.assertEqual("ubuntu-24.04-native", profile["developer_environment"])
        self.assertEqual("packer", profile["image_builder"]["authority"])
        self.assertEqual("qemu-kvm", profile["hypervisor"]["authority"])
        self.assertEqual(
            "qemu-kvm", profile["vm_lifecycle_and_smoke_test"]["authority"]
        )
        self.assertEqual("python-repoctl", profile["host_orchestration"]["authority"])
        self.assertEqual("ansible", root["guest_configuration"]["authority"])

    def test_linux_and_windows_outputs_cannot_overwrite_each_other(self):
        profiles = self.machine["packer_image"]["local_pipeline"]["profiles"]
        self.assertEqual(
            ".artifacts/packer/rocky-10.2/windows",
            profiles["windows"]["artifact_root"],
        )
        self.assertEqual(
            ".artifacts/packer/rocky-10.2/linux",
            profiles["linux"]["artifact_root"],
        )
        self.assertNotEqual(
            profiles["windows"]["artifact"], profiles["linux"]["artifact"]
        )

    def test_native_linux_tools_are_centrally_exact(self):
        active = self.toolchain["tool_lifecycle"]["active"]
        versions = self.toolchain["versions"]
        self.assertEqual(
            "native-linux-host", active["packer-linux"]["provision"]["type"]
        )
        self.assertEqual("1.16.1", versions["PACKER_VERSION"])
        self.assertEqual(
            "af38a9e93e4ed1b9ca68206ae969c64c300c82a3dde46a780dfa629f0867f651",
            versions["PACKER_SHA256_LINUX_AMD64"],
        )
        self.assertEqual("native-linux-host", active["qemu"]["provision"]["type"])
        self.assertEqual("8.2.2", versions["QEMU_VERSION"])
        self.assertEqual(
            "14602e262627adac030329d2cecfee5f6c0938b34566ff2ea2d4c9a9eb02430d",
            versions["QEMU_SHA256_LINUX_AMD64"],
        )
        self.assertEqual(
            ["linux/amd64"], self.toolchain["tools"]["packer-linux"]["platforms"]
        )

    def test_linux_profile_is_native_and_explicitly_rejects_wsl(self):
        self.assertIn('"/proc/sys/kernel/osrelease"', self.pipeline)
        self.assertIn('"microsoft" in release or "wsl" in release', self.pipeline)
        self.assertIn("requires a native Linux host", self.pipeline)
        self.assertIn('Path("/dev/kvm")', self.pipeline)
        self.assertIn("os.R_OK | os.W_OK", self.pipeline)
        self.assertIn('os_release.get("VERSION_ID") != "24.04"', self.pipeline)

    def test_qemu_build_uses_only_the_governed_source(self):
        self.assertIn('source "qemu" "base"', self.packer)
        self.assertIn('accelerator          = "kvm"', self.packer)
        self.assertIn('format               = "qcow2"', self.packer)
        self.assertIn('"-only=rocky-10.2-base.qemu.base"', self.pipeline)
        self.assertIn("find_qcow2", self.pipeline)
        self.assertNotIn("vagrant", self.pipeline.lower())

    def test_qemu_smoke_is_bounded_isolated_and_cleaned(self):
        self.assertIn('"-enable-kvm"', self.pipeline)
        self.assertIn("hostfwd=tcp:127.0.0.1", self.pipeline)
        self.assertIn('"virtio-net-pci,netdev=net0"', self.pipeline)
        self.assertIn('"smoke-overlay.qcow2"', self.pipeline)
        self.assertIn("for attempt in range(1, 13)", self.pipeline)
        self.assertIn("os.killpg(qemu_process.pid, signal.SIGTERM)", self.pipeline)
        self.assertIn("private_key.unlink(missing_ok=True)", self.pipeline)
        self.assertNotIn("shell=True", self.pipeline)

    def test_linux_build_qualification_and_release_are_distinct(self):
        for action in ("preflight", "build", "qualify", "release"):
            self.assertIn(f'args.action == "{action}"', self.pipeline)
        self.assertIn("QUALIFICATION_EVIDENCE", self.pipeline)
        self.assertIn("RELEASE_EVIDENCE", self.pipeline)
        self.assertIn('"remote_publication": "NOT_PERFORMED"', self.pipeline)
        self.assertIn('"source_clean": False', self.pipeline)

    def test_make_and_repoctl_expose_all_linux_stages(self):
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        repoctl = (ROOT / "scripts/repoctl.py").read_text(encoding="utf-8")
        for stage in ("preflight", "build", "qualify", "release"):
            target = f"image-rocky-linux-{stage}"
            self.assertIn(f"{target}:", makefile)
            self.assertIn(f"scripts/repoctl.py {target}", makefile)
            self.assertIn(f'args.cmd == "{target}"', repoctl)
        self.assertIn("linux_image_pipeline", repoctl)

    def test_pipeline_is_utf8_and_adds_no_shell_automation(self):
        raw = LINUX_PIPELINE.read_bytes()
        self.assertEqual(raw, raw.decode("utf-8").encode("utf-8"))
        self.assertFalse(raw.startswith(b"\xef\xbb\xbf"))
        self.assertEqual([], list((ROOT / "scripts").glob("*.sh")))


if __name__ == "__main__":
    unittest.main()
