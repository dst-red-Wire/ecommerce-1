"""Decision tests use a fake runner; they never start local VirtualBox VMs."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import vm_lifecycle as vm

ROOT = Path(__file__).resolve().parents[1]


class FakeRunner(vm.Runner):
    def __init__(self, fail_provision=False):
        self.calls = []
        self.fail_provision = fail_provision

    def run(self, argv, cwd, timeout=30):
        self.calls.append(argv)
        failed = self.fail_provision and "ansible-playbook" in argv[0]
        return subprocess.CompletedProcess(
            argv, 1 if failed else 0, "", "provision failed" if failed else ""
        )

    def tcp(self, host, port):
        return True


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.box = self.directory / "base.box"
        self.box.write_bytes(b"qualified image")
        self.manifest = self.box.with_suffix(".box.fingerprint.json")
        self.manifest.write_text(
            json.dumps({"fingerprint": "image-a", "sha256": vm.digest(self.box)})
        )
        self.config = {
            "vm": "test-vm",
            "output_box": str(self.box),
            "vagrant_dir": str(self.directory),
            "inventory": str(self.directory / "inventory"),
            "playbooks": ["platform/ansible/mgmt.yml"],
            "ansible_playbook": "ansible-playbook",
            "vagrant": "vagrant",
            "packer": "packer",
            "packer_vars": str(self.directory / "vars.pkr.hcl"),
            "image_profile": "rke2",
            "service_probe": "true",
        }
        (self.directory / "inventory").write_text("test-vm\n")
        (self.directory / "vars.pkr.hcl").write_text("# test\n")
        self.runner = FakeRunner()
        self.controller = vm.Reconciler(ROOT, self.config, self.runner)
        self.controller.state_dir = self.directory / "state"
        self.controller.preflight = lambda: "iso-digest"
        self.controller.vm_state = lambda: "running"
        self.controller.vm_uuid = lambda: "12345678-1234-1234-1234-123456789abc"
        self.controller.probe = lambda **kwargs: None
        self.controller.ssh = lambda remote: remote != "test -e /run/reboot-required"
        self.patch_image = patch.object(vm, "image_fingerprint", return_value="image-a")
        self.patch_runtime = patch.object(
            vm, "runtime_fingerprint", return_value="runtime-a"
        )
        self.patch_image.start()
        self.patch_runtime.start()
        self.addCleanup(self.patch_image.stop)
        self.addCleanup(self.patch_runtime.stop)

    def test_preflight_failure_prevents_any_mutation(self):
        self.controller.preflight = lambda: (_ for _ in ()).throw(
            vm.LifecycleError("PACKER_INPUT_INVALID", "bad")
        )
        with self.assertRaises(vm.LifecycleError):
            self.controller.reconcile()
        self.assertEqual([], self.runner.calls)

    def test_same_fingerprint_reuses_image_and_running_vm(self):
        result = self.controller.reconcile()
        self.assertEqual("reprovision", result["decision"])
        self.assertEqual("qualified", result["checkpoint"])
        self.assertEqual(0, result["metrics"]["rebuild_count"])
        self.assertFalse(
            any("up" in call or "destroy" in call for call in self.runner.calls)
        )
        self.runner.calls.clear()
        result = self.controller.reconcile()
        self.assertEqual("reuse", result["decision"])
        self.assertEqual(0, result["metrics"]["reprovision_count"])
        self.assertEqual([], self.runner.calls)

    def test_provision_failure_preserves_vm_and_bounds_retry(self):
        self.runner.fail_provision = True
        with self.assertRaises(vm.LifecycleError) as raised:
            self.controller.reconcile()
        self.assertEqual("PROVISION_FAILED", raised.exception.code)
        self.assertEqual(2, len(self.runner.calls))
        self.assertFalse(
            any("destroy" in call or "up" in call for call in self.runner.calls)
        )
        self.assertEqual(
            "os-ready",
            json.loads((self.controller.state_dir / "latest.json").read_text())[
                "checkpoint"
            ],
        )

    def test_changed_image_preserves_existing_vm(self):
        with (
            patch.object(vm, "image_fingerprint", return_value="image-b"),
            self.assertRaises(vm.LifecycleError) as raised,
        ):
            self.controller.reconcile()
        self.assertEqual("IMAGE_CORRUPT", raised.exception.code)
        self.assertEqual([], self.runner.calls)

    def test_changed_image_without_vm_rebuilds_once(self):
        self.controller.vm_state = lambda: "absent"
        with patch.object(vm, "image_fingerprint", return_value="image-b"):
            result = self.controller.reconcile()
        self.assertEqual(1, result["metrics"]["rebuild_count"])
        self.assertTrue(any("build" in call for call in self.runner.calls))
        self.assertFalse(any("destroy" in call for call in self.runner.calls))

    def test_corrupt_image_without_vm_rebuilds(self):
        self.manifest.write_text(
            json.dumps({"fingerprint": "image-a", "sha256": "0" * 64})
        )
        self.controller.vm_state = lambda: "absent"
        result = self.controller.reconcile()
        self.assertEqual(1, result["metrics"]["rebuild_count"])

    def test_policy_has_bounded_nondestructive_failures(self):
        required = {
            "PACKER_INPUT_INVALID",
            "PACKER_BUILD_FAILED",
            "IMAGE_CORRUPT",
            "VBOX_PROVIDER_ERROR",
            "VBOX_NETWORK_ERROR",
            "VM_BOOT_TIMEOUT",
            "TCP22_TIMEOUT",
            "SSH_TIMEOUT",
            "OS_READY_TIMEOUT",
            "PROVISION_FAILED",
            "REBOOT_REQUIRED",
            "REBOOT_TIMEOUT",
            "SERVICE_READY_TIMEOUT",
            "UNKNOWN_RUNTIME_FAILURE",
        }
        failures = self.controller.policy["failures"]
        self.assertEqual(required, set(failures))
        for failure in failures.values():
            self.assertFalse(failure["destructive"])
            self.assertLessEqual(failure["max_retries"], 1)
            self.assertGreaterEqual(failure["delay_seconds"], 0)

    def test_reboot_required_uses_reload(self):
        self.controller.ssh = lambda remote: True
        result = self.controller.reconcile()
        self.assertEqual("reload", result["decision"])
        self.assertEqual(1, result["metrics"]["reboot_count"])
        self.assertTrue(any("reload" in call for call in self.runner.calls))
        self.assertFalse(any("destroy" in call for call in self.runner.calls))

    def test_probe_timeout_has_bounded_global_budget(self):
        class Clock:
            now = 0

            def tick(self, seconds):
                self.now += seconds

        clock = Clock()
        self.controller.clock = lambda: clock.now
        self.controller.sleep = clock.tick
        self.controller.vm_state = lambda: "stopped"
        self.controller.probe = vm.Reconciler.probe.__get__(self.controller)
        with self.assertRaises(vm.LifecycleError) as raised:
            self.controller.probe(global_deadline=25)
        self.assertEqual("VM_BOOT_TIMEOUT", raised.exception.code)
        self.assertEqual(20, clock.now)
        self.assertEqual(1, self.controller.metrics["timeout_count"])

    def test_temporary_ssh_timeout_only_reprobes(self):
        probes = 0

        def transient_probe(**kwargs):
            nonlocal probes
            probes += 1
            if probes == 1:
                raise vm.LifecycleError("SSH_TIMEOUT", "temporary")

        self.controller.probe = transient_probe
        result = self.controller.reconcile()
        self.assertEqual(2, probes)
        self.assertEqual(0, result["metrics"]["destructive_retry_count"])
        self.assertFalse(
            any("destroy" in call or "up" in call for call in self.runner.calls)
        )

    def test_global_lock_prevents_parallel_launch(self):
        (ROOT / ".context").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT / ".context") as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps(self.config))
            fake = self.controller
            fake.state_dir = Path(directory) / "vm"
            fake.state_dir.mkdir()
            lock = fake.state_dir.parent / "reconcile.lock"
            lock.write_text("existing")
            with patch.object(vm, "Reconciler", return_value=fake):
                self.assertEqual(2, vm.reconcile_cli(ROOT, path))
            self.assertEqual("existing", lock.read_text())
            self.assertEqual([], self.runner.calls)


if __name__ == "__main__":
    unittest.main()
