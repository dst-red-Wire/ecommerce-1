"""Status prefers the protected native run and never reports an old PASS as current."""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import repoctl


class NativeNetworkStatusTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.campaign = "20260929T163821Z-9da62296f3d5"
        self.sha = "a" * 40
        self.vm_id = "e80d60f3-a12e-4734-a654-0cd24dce0fa1"
        self.vm_name = "ecommerce-rocky-10-2-smoke-9da62296f3d5"
        self.laboratory = root / "laboratory"
        self.shadows = root / "protected"
        self.shadow = self.shadows / f"{self.campaign}-{self.sha}"
        self.state_path = self.shadow / "native-boot.json"
        self.protected_result = self.shadow / "evidence/network-smoke" / self.campaign / "result.json"
        self.legacy_result = self.laboratory / "evidence/network-smoke" / self.campaign / "result.json"
        self.legacy_result.parent.mkdir(parents=True)
        self.legacy_result.write_text(json.dumps({
            "campaign_id": self.campaign, "status": "PASS", "source_git_sha": "b" * 40,
            "vm_name": self.vm_name, "virtualbox_backend": "NATIVE_VTX",
            "guest_security": "PASS", "network_smoke": {"ssh_auth_ready": "PASS"},
            "cleanup": {"vm_id": self.vm_id, "vm_preserved": True},
        }), encoding="utf-8")

    def create_shadow(self, phase: str = "BOOT_PENDING", run_status: str | None = None) -> None:
        self.protected_result.parent.mkdir(parents=True)
        self.protected_result.write_bytes(self.legacy_result.read_bytes())
        state = {
            "mode": "NETWORK_SMOKE_NATIVE", "campaign_id": self.campaign,
            "source_sha": self.sha, "shadow_root": repoctl._native_shadow_windows_path(self.shadow),
            "phase": phase, "vm_id": self.vm_id, "expected_vm_id": self.vm_id,
            "vm_name": self.vm_name,
        }
        if run_status is not None:
            state["run_status"] = run_status
        self.state_path.write_text(json.dumps(state), encoding="utf-8")

    def status(self) -> tuple[int, dict | None]:
        output = io.StringIO()
        with (contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()),
              mock.patch.object(repoctl.subprocess, "run", return_value=subprocess.CompletedProcess(
                  [], 0, 'VMState="running"\n', ""))):
            code = repoctl.lab_network_status(
                self.campaign, laboratory_root=self.laboratory, shadow_root=self.shadows,
            )
        return code, json.loads(output.getvalue()) if code == 0 else None

    def test_pending_shadow_hides_historical_success(self) -> None:
        self.create_shadow()
        code, status = self.status()
        self.assertEqual(code, 0)
        self.assertEqual(status["evidence_source"], "protected-shadow")
        self.assertEqual(status["evidence"], str(self.protected_result))
        self.assertEqual(status["source_sha"], self.sha)
        self.assertEqual(status["native_phase"], "BOOT_PENDING")
        self.assertEqual(status["native_status"], "PENDING")
        self.assertIsNone(status["guest_security"])
        self.assertIsNone(status["virtualbox_backend"])
        self.assertIsNone(status["ssh_handshake"])

    def test_recovered_pass_reads_digest_bound_shadow_result(self) -> None:
        self.create_shadow(phase="RECOVERED", run_status="PASS")
        result = json.loads(self.protected_result.read_text(encoding="utf-8"))
        result["resume_runner_source_sha"] = self.sha
        self.protected_result.write_text(json.dumps(result), encoding="utf-8")
        state = json.loads(self.state_path.read_text(encoding="utf-8"))
        state["result_sha256"] = hashlib.sha256(self.protected_result.read_bytes()).hexdigest()
        self.state_path.write_text(json.dumps(state), encoding="utf-8")
        self.legacy_result.write_text('{"status":"FAIL"}', encoding="utf-8")
        code, status = self.status()
        self.assertEqual(code, 0)
        self.assertEqual(status["native_status"], "PASS")
        self.assertEqual(status["guest_security"], "PASS")
        self.assertEqual(status["evidence"], str(self.protected_result))
        result["guest_security"] = "FAIL"
        self.protected_result.write_text(json.dumps(result), encoding="utf-8")
        self.assertNotEqual(self.status()[0], 0)

    def test_failed_native_run_does_not_show_old_protected_result(self) -> None:
        self.create_shadow(phase="RECOVERED", run_status="FAIL")
        code, status = self.status()
        self.assertEqual(code, 0)
        self.assertEqual(status["native_status"], "FAIL")
        self.assertIsNone(status["guest_security"])
        self.assertIsNone(status["ssh_handshake"])

    def test_invalid_shadow_fails_closed_without_legacy_fallback(self) -> None:
        self.create_shadow()
        state = json.loads(self.state_path.read_text(encoding="utf-8"))
        state["source_sha"] = "c" * 40
        self.state_path.write_text(json.dumps(state), encoding="utf-8")
        self.assertNotEqual(self.status()[0], 0)
        state["source_sha"] = self.sha
        self.state_path.write_text(json.dumps(state), encoding="utf-8")
        result = json.loads(self.protected_result.read_text(encoding="utf-8"))
        result["campaign_id"] = "20260929T163821Z-000000000000"
        self.protected_result.write_text(json.dumps(result), encoding="utf-8")
        self.assertNotEqual(self.status()[0], 0)
        result["campaign_id"] = self.campaign
        result["cleanup"] = []
        self.protected_result.write_text(json.dumps(result), encoding="utf-8")
        self.assertNotEqual(self.status()[0], 0)
        self.protected_result.unlink()
        self.protected_result.symlink_to(self.legacy_result)
        self.assertNotEqual(self.status()[0], 0)
        self.protected_result.unlink()
        self.protected_result.write_bytes(self.legacy_result.read_bytes())
        self.state_path.unlink()
        self.state_path.symlink_to(self.legacy_result)
        self.assertNotEqual(self.status()[0], 0)

    def test_multiple_shadows_fail_closed(self) -> None:
        self.create_shadow()
        (self.shadows / f"{self.campaign}-{'c' * 40}").mkdir()
        self.assertNotEqual(self.status()[0], 0)

    def test_legacy_result_is_used_only_without_shadow(self) -> None:
        code, status = self.status()
        self.assertEqual(code, 0)
        self.assertEqual(status["evidence_source"], "legacy-laboratory")
        self.assertEqual(status["evidence"], str(self.legacy_result))
        self.assertIsNone(status["native_phase"])
        self.assertEqual(status["guest_security"], "PASS")


if __name__ == "__main__":
    unittest.main()
