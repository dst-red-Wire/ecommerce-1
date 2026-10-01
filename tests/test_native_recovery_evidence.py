"""Byte-level fixture tests of native recovery validation, never runtime proof.

Only the Windows ACL observer and immutable box catalog are replaced. Protected
files, digest chains, source inputs, raw host observations and the M2.5 native
smoke/image validators execute unchanged against disposable fixture bytes.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import subprocess
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import native_recovery_evidence as recovery

_spec = importlib.util.spec_from_file_location(
    "native_recovery_m25_fixture", ROOT / "tests/test_m25_runtime_evidence.py")
fixture = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fixture)

HEAD, TREE, UUID = fixture.HEAD, fixture.TREE, fixture.UUID
CAMPAIGN = "20260929T163821Z-9da62296f3d5"
NORMAL = "{11111111-1111-1111-1111-111111111111}"
NATIVE = "{22222222-2222-2222-2222-222222222222}"
BOX_BYTES = b"small immutable box fixture: no VM is created\n"
PACKER_BYTES = b"immutable Packer log fixture: no build is run\n"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def encoded(value: dict) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


class NativeRecoveryEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        with mock.patch.object(fixture, "BOX_SHA", sha(BOX_BYTES)):
            fixture.M25RuntimeEvidenceTests.setUp(self)
        self.shadow = self.shadow_root / f"{CAMPAIGN}-{HEAD}"
        shadow_patch = mock.patch.object(recovery, "SHADOW_ROOT", self.shadow_root)
        shadow_patch.start()
        self.addCleanup(shadow_patch.stop)
        boundary_patch = mock.patch.object(recovery, "_protected_boundary", return_value=[])
        self.boundary = boundary_patch.start()
        self.addCleanup(boundary_patch.stop)
        self.result_relative = f"evidence/network-smoke/{CAMPAIGN}/result.json"
        self.smoke = json.loads((self.shadow / self.result_relative).read_bytes())
        self.vm_name = self.smoke["vm_name"]
        self.manifest["packer_log_sha256"] = sha(PACKER_BYTES)
        self.put("box/source.box", BOX_BYTES)
        self.put("box/packer.log", PACKER_BYTES)
        self.put("box/manifest.json", encoded(self.manifest))
        runner = {
            "source_sha": HEAD, "source_tree_sha": TREE, "campaign_id": CAMPAIGN,
            "runner_files": self.smoke["resume_runner_files"],
            "vagrantfile_sha256": self.smoke["resume_vagrantfile_sha256"],
            "package_lock_sha256": self.smoke["image_qualification"]["package_lock_sha256"],
        }
        for name in recovery.m25.NETWORK_RUNNER_FILES:
            self.put(f"runner-{HEAD}/scripts/windows/{name}",
                     (self.root / "scripts/windows" / name).read_bytes())
        self.put(f"runner-{HEAD}/runner.json", encoded(runner))
        for target, original in (
            ("smoke-run/Vagrantfile", "platform/vagrant/rocky-image-smoke/Vagrantfile"),
            ("config/artifacts/rocky-10.2-base-packages.lock.json",
             "config/artifacts/rocky-10.2-base-packages.lock.json"),
        ):
            self.put(f"{CAMPAIGN}/{target}", (self.root / original).read_bytes())
        self.put(f"{CAMPAIGN}/smoke-run/.vagrant/machines/default/virtualbox/id", UUID.encode())
        self.backup_relative = f"bcd/before-{CAMPAIGN}-{HEAD}-20261001T000000000Z.bak"
        self.put(self.backup_relative, b"BCD export fixture bytes\n" * 64)
        self.boot = json.loads((self.shadow / "native-boot.json").read_bytes())
        self.boot.update({
            "expected_vm_id": UUID, "boot_attempts": 1, "normal_boot_id": NORMAL,
            "native_boot_id": NATIVE,
            "runner_manifest_sha256": sha(encoded(runner)),
            "bcd_backup": str(recovery.WINDOWS_ROOT / self.shadow.name / self.backup_relative),
            "bcd_backup_sha256": sha((self.shadow / self.backup_relative).read_bytes()),
        })
        self.clock = datetime.now(timezone.utc) - timedelta(minutes=5)
        self.build_observations()
        self.rechain()
        self.documents = copy.deepcopy((self.boot, self.capture, self.restore, self.verification, self.smoke))
        self.proof, self.verdict = self.inspect()

    def put(self, relative: str, data: bytes) -> None:
        path = self.shadow / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    def at(self, seconds: int) -> str:
        return (self.clock + timedelta(seconds=seconds)).isoformat()

    def snapshot(self, start: int, *, restored: bool) -> dict:
        current = f"Windows Boot Loader\nidentifier {NORMAL}\npath \\Windows\\system32\\winload.efi\n"
        manager = f"Windows Boot Manager\nidentifier {{9dea862c-5cdd-4e70-acc1-f32b344d4795}}\ndefault {NORMAL}\n"
        if not restored:
            manager += f"bootsequence {NATIVE}\n"
        full = manager + "\n" + current
        if not restored:
            full += (f"\nWindows Boot Loader\nidentifier {NATIVE}\n"
                     "path \\Windows\\system32\\winload.efi\n"
                     "description Windows - Ecommerce Network Smoke Native VT-x\n")
        return {
            "observed_at": self.at(start), "completed_at": self.at(start + 1),
            "bcd": {"current_stdout": current, "bootmgr_stdout": manager, "all_stdout": full},
            "vbox_stdout": f'name="{self.vm_name}"\nUUID="{UUID}"\nVMState="poweroff"\n',
            "native_tasks": [] if restored else list(recovery.TASK_NAMES[:2]),
            "private_key_present": not restored,
        }

    def build_observations(self) -> None:
        common = {name: self.boot[name] for name in (
            "campaign_id", "source_sha", "source_tree_sha", "vm_id", "vm_name",
            "box_sha256", "runner_manifest_sha256", "shadow_root")}
        common["schema_version"] = 1
        self.capture = {
            **common, "phase": "capture", "observation": self.snapshot(0, restored=True),
            "shadow_initialization_started_at": self.at(2), "sealed_at": self.at(3),
            "bcd_backup": {"path": self.boot["bcd_backup"], "sha256": self.boot["bcd_backup_sha256"]},
        }
        self.boot.update({
            "shadow_initialization_started_at": self.at(2),
            "mutation_started_at": self.at(4), "prepared_at": self.at(5),
            "recovered_at": self.at(12),
        })
        self.restore = {
            **common, "phase": "restore", "started_at": self.at(7), "completed_at": self.at(11),
            "observation": self.snapshot(8, restored=False),
            "operations": {"bootsequence_removed": True, "native_loader_removed": True,
                           "tasks_removed": sorted(recovery.TASK_NAMES[:2]), "private_key_removed": True},
        }
        self.verification = {
            **common, "phase": "restore_verification", "observed_at": self.at(13),
            "observation": self.snapshot(13, restored=True),
        }

    def rechain(self) -> None:
        self.put(self.result_relative, encoded(self.smoke))
        self.boot["result_sha256"] = sha(encoded(self.smoke))
        self.put("recovery/capture.json", encoded(self.capture))
        capture_digest = sha(encoded(self.capture))
        self.boot["recovery_capture_sha256"] = capture_digest
        self.restore["capture_sha256"] = capture_digest
        self.put("recovery/restore.json", encoded(self.restore))
        self.put("native-boot.json", encoded(self.boot))
        self.verification.update({
            "capture_sha256": capture_digest, "restore_sha256": sha(encoded(self.restore)),
            "native_boot_sha256": sha(encoded(self.boot)),
        })
        self.put("recovery/verification.json", encoded(self.verification))

    def reset_documents(self) -> None:
        self.boot, self.capture, self.restore, self.verification, self.smoke = copy.deepcopy(self.documents)
        self.rechain()

    def inspect(self, **kwargs):
        return recovery._inspect(self.root, HEAD, TREE, CAMPAIGN, UUID, **kwargs)

    def rejected(self, message=None, **kwargs) -> None:
        with self.assertRaises((ValueError, OSError, KeyError, TypeError)) as caught:
            self.inspect(**kwargs)
        if message:
            self.assertIn(message, str(caught.exception))

    def test_valid_raw_observations_derive_host_recovery_only(self) -> None:
        verdict = recovery.validate(self.root, self.proof, HEAD, TREE)
        self.assertEqual(verdict["recovery"], {
            "capture": "PASS", "restore": "PASS", "restore_verification": "PASS"})
        self.assertEqual(self.proof["environment"], "host")
        self.assertEqual(self.proof["deployment_state"], "NOT_DEPLOYED")
        self.assertEqual(self.proof["paid_resources_created"], 0)
        self.assertNotIn("ready_for_real_provisioning", self.proof)
        self.assertIn("box/source.box", self.proof["source_evidence"])
        self.assertIn("recovery/verification.json", self.proof["source_evidence"])
        self.assertEqual(self.boundary.call_count, 4)

    def test_missing_each_phase_is_rejected(self) -> None:
        for name in ("capture", "restore", "verification"):
            with self.subTest(name=name):
                path = self.shadow / f"recovery/{name}.json"
                saved = path.read_bytes()
                path.unlink()
                self.rejected()
                path.write_bytes(saved)

    def test_self_declared_status_or_recovery_is_rejected(self) -> None:
        declared = copy.deepcopy(self.proof)
        declared["recovery"] = {name: "PASS" for name in ("capture", "restore", "restore_verification")}
        with self.assertRaisesRegex(ValueError, "self-declared recovery"):
            recovery.validate(self.root, declared, HEAD, TREE)
        for target in ("capture", "restore", "verification"):
            for field in ("status", "recovery"):
                with self.subTest(target=target, field=field):
                    self.reset_documents()
                    getattr(self, target)[field] = "PASS"
                    self.rechain()
                    self.rejected("declared recovery status")

    def test_exact_identity_and_full_sha_are_required(self) -> None:
        for field, value in (
            ("source_sha", "d"*40), ("source_tree_sha", "e"*40),
            ("vm_id", "87654321-1234-1234-1234-123456789abc"),
            ("campaign_id", "20260929T163821Z-000000000000"),
            ("shadow_root", r"C:\unprotected"),
        ):
            with self.subTest(field=field):
                self.reset_documents()
                self.boot[field] = value
                self.rechain()
                self.rejected("protected state identity differs")
        for head, tree in ((HEAD[:12], TREE), (HEAD, TREE[:12]), ("f"*40, TREE)):
            with self.subTest(head=head, tree=tree):
                with self.assertRaises(ValueError):
                    recovery._inspect(self.root, head, tree, CAMPAIGN, UUID)

    def test_each_common_record_identity_must_match(self) -> None:
        for target in ("capture", "restore", "verification"):
            for field in ("source_sha", "source_tree_sha", "campaign_id", "vm_id",
                          "vm_name", "box_sha256", "runner_manifest_sha256", "shadow_root"):
                with self.subTest(target=target, field=field):
                    self.reset_documents()
                    getattr(self, target)[field] = "wrong"
                    self.rechain()
                    self.rejected("differs from protected state")

    def test_digest_chain_and_immutable_artifact_bytes_are_rechecked(self) -> None:
        for relative in (
            "recovery/capture.json", "recovery/restore.json", "native-boot.json",
            "box/source.box", "box/packer.log", self.backup_relative,
            f"runner-{HEAD}/scripts/windows/LabNativeBoot.ps1",
        ):
            with self.subTest(relative=relative):
                path = self.shadow / relative
                original = path.read_bytes()
                path.write_bytes(original + b" ")
                self.rejected()
                path.write_bytes(original)
        self.verification["restore_sha256"] = "0"*64
        self.put("recovery/verification.json", encoded(self.verification))
        self.rejected("digest chain differs")

    def test_symlink_file_and_directory_and_hardlink_are_rejected(self) -> None:
        path = self.shadow / "recovery/capture.json"
        saved = path.read_bytes()
        outside = self.root / "outside-capture.json"
        outside.write_bytes(saved)
        path.unlink()
        path.symlink_to(outside)
        self.rejected("symlink")
        path.unlink()
        path.write_bytes(saved)
        original_directory = self.shadow / "recovery"
        moved_directory = self.root / "relocated-observations"
        original_directory.rename(moved_directory)
        original_directory.symlink_to(moved_directory, target_is_directory=True)
        self.rejected("symlink")
        original_directory.unlink()
        moved_directory.rename(original_directory)
        path.unlink()
        os.link(outside, path)
        self.rejected("multiple links")

    def test_shadow_directory_redirection_is_rejected(self) -> None:
        moved = self.root / "relocated-shadow"
        self.shadow.rename(moved)
        self.shadow.symlink_to(moved, target_is_directory=True)
        self.rejected("exact-head protected shadow")

    def test_mutation_during_validation_is_rejected(self) -> None:
        def observe_and_mutate(_files):
            path = self.shadow / "recovery/capture.json"
            path.write_bytes(path.read_bytes() + b" ")
            return []
        self.boundary.side_effect = observe_and_mutate
        self.rejected("changed during validation")

    def test_bcd_garbage_and_multi_entry_sequence_are_rejected(self) -> None:
        for variant in ("current-garbage", "all-garbage", "multi-sequence", "wrong-default"):
            with self.subTest(variant=variant):
                self.reset_documents()
                if variant == "current-garbage":
                    self.capture["observation"]["bcd"]["current_stdout"] = "garbage"
                elif variant == "all-garbage":
                    for record in (self.capture, self.verification):
                        record["observation"]["bcd"]["all_stdout"] = "garbage"
                elif variant == "multi-sequence":
                    self.restore["observation"]["bcd"]["bootmgr_stdout"] += f"             {NORMAL}\n"
                else:
                    self.verification["observation"]["bcd"]["bootmgr_stdout"] = f"default {NATIVE}\n"
                self.rechain()
                self.rejected()

    def test_inventory_cannot_contradict_dedicated_bcd_observations(self) -> None:
        for variant in ("default", "bootsequence", "loader-path"):
            with self.subTest(variant=variant):
                self.reset_documents()
                # Matching baseline/readback cannot legitimize contradictory views.
                for record in (self.capture, self.verification):
                    bcd = record["observation"]["bcd"]
                    inventory = bcd["all_stdout"]
                    if variant == "default":
                        inventory = inventory.replace(f"default {NORMAL}", f"default {NATIVE}")
                    elif variant == "bootsequence":
                        inventory = inventory.replace(
                            f"default {NORMAL}\n", f"default {NORMAL}\nbootsequence {NATIVE}\n")
                    else:
                        inventory = inventory.replace(
                            r"\Windows\system32\winload.efi", r"\Other\winload.efi")
                    bcd["all_stdout"] = inventory
                self.rechain()
                self.rejected("inventory contradicts")

    def test_bcd_view_comparison_accepts_crlf_and_trailing_spaces_only(self) -> None:
        for record in (self.capture, self.restore, self.verification):
            bcd = record["observation"]["bcd"]
            bcd["all_stdout"] = "\r\n".join(
                line + ("   " if line else "") for line in bcd["all_stdout"].splitlines()
            ) + "\r\n"
        self.rechain()
        proof, verdict = self.inspect()
        self.assertEqual(verdict["status"], "PASS")
        self.assertEqual(recovery.validate(self.root, proof, HEAD, TREE)["status"], "PASS")

    def test_observations_require_tasks_identity_and_complete_vm_state(self) -> None:
        for field in ("native_tasks", "private_key_present", "vbox_stdout"):
            with self.subTest(field=field):
                self.reset_documents()
                self.verification["observation"].pop(field)
                self.rechain()
                self.rejected()
        for name in recovery.TASK_NAMES:
            with self.subTest(task=name):
                self.reset_documents()
                self.verification["observation"]["native_tasks"] = [name]
                self.rechain()
                self.rejected("tasks or private identity remain")
        for name in recovery.TASK_NAMES[:2]:
            with self.subTest(missing_before=name):
                self.reset_documents()
                self.restore["observation"]["native_tasks"].remove(name)
                self.rechain()
                self.rejected("owned resources before restoration")
        for field, text in (
            ("private_key_present", True),
            ("vbox_stdout", f'name="{self.vm_name}"\nUUID="{UUID}"\nVMState="running"\n'),
            ("vbox_stdout", f'name="{self.vm_name}"\nVMState="poweroff"\n'),
        ):
            with self.subTest(field=field, value=text):
                self.reset_documents()
                self.verification["observation"][field] = text
                self.rechain()
                self.rejected()

    def test_only_actual_restoration_receipts_are_accepted(self) -> None:
        for field in ("bootsequence_removed", "native_loader_removed", "private_key_removed"):
            with self.subTest(field=field):
                self.reset_documents()
                self.restore["operations"][field] = False
                self.rechain()
                self.rejected("receipts differ")
        self.reset_documents()
        self.restore["operations"]["tasks_removed"] = []
        self.rechain()
        self.rejected("receipts differ")

    def test_recorded_observer_error_blocks_otherwise_valid_digest_chain(self) -> None:
        self.boot["recovery_evidence_error"] = "prospective observer unavailable"
        self.rechain()
        self.rejected("observer reported a failure")

    def test_prepared_only_and_failed_native_runs_are_rejected(self) -> None:
        for field, value in (("boot_attempts", 0), ("boot_attempts", True),
                             ("run_status", "FAIL"), ("phase", "PREPARED")):
            with self.subTest(field=field, value=value):
                self.reset_documents()
                self.boot[field] = value
                self.rechain()
                self.rejected("completed real native run")

    def test_native_smoke_and_vtx_log_are_still_authoritative(self) -> None:
        self.smoke["virtualbox_backend"] = "NEM"
        self.rechain()
        self.rejected("current-head native network")
        self.reset_documents()
        log_relative = self.smoke["image_qualification"]["virtualbox_log_relative"]
        self.put(f"{CAMPAIGN}/{log_relative}", b"NEM: active fallback\n")
        self.smoke["image_qualification"]["virtualbox_log_sha256"] = sha(b"NEM: active fallback\n")
        self.rechain()
        self.rejected("does not prove VT-x")

    def test_stale_current_proof_and_historical_tampering(self) -> None:
        self.clock -= timedelta(days=2)
        self.build_observations()
        self.rechain()
        self.rejected("stale")
        historical, verdict = self.inspect(historical=True)
        self.assertEqual(verdict["status"], "PASS")
        self.assertEqual(recovery.validate(
            self.root, historical, HEAD, TREE, historical=True)["status"], "PASS")
        self.put("box/source.box", BOX_BYTES + b"tampered")
        self.rejected(historical=True)

    def test_timestamp_order_and_future_observations_fail(self) -> None:
        for target, field, value in (
            ("capture", "sealed_at", self.at(100)),
            ("restore", "completed_at", self.at(1)),
            ("verification", "observed_at", self.at(0)),
        ):
            with self.subTest(target=target, field=field):
                self.reset_documents()
                getattr(self, target)[field] = value
                self.rechain()
                self.rejected()
        self.clock += timedelta(days=2)
        self.build_observations()
        self.rechain()
        self.rejected("future")

    def test_caller_proof_cannot_change_paid_or_deployment_state(self) -> None:
        for field, value in (("deployment_state", "DEPLOYED"), ("paid_resources_created", 1),
                             ("head_sha", "f"*40), ("head_tree_sha", "f"*40),
                             ("source_evidence", {})):
            with self.subTest(field=field):
                proof = copy.deepcopy(self.proof)
                proof[field] = value
                with self.assertRaisesRegex(ValueError, "metadata or referenced digests"):
                    recovery.validate(self.root, proof, HEAD, TREE)


class NativeRecoveryBoundaryScriptTests(unittest.TestCase):
    """Execute the real PS5.1 observer with in-memory filesystem metadata only."""

    def boundary(self, variant: str) -> subprocess.CompletedProcess[str]:
        source = r"""
$script:Variant='@@VARIANT@@'
$script:Leaf='C:\Program Files\EcommerceNativeSmoke\fixture\native-boot.json'
function Get-Item {
    param([string]$LiteralPath,[switch]$Force)
    $attributes=[IO.FileAttributes]::Directory
    if (($script:Variant -eq 'reparse' -and $LiteralPath -eq $script:Leaf) -or
        ($script:Variant -eq 'ancestor-reparse' -and $LiteralPath -eq 'C:\Program Files')) {
        $attributes=$attributes -bor [IO.FileAttributes]::ReparsePoint
    }
    return [pscustomobject]@{FullName=$LiteralPath;Attributes=$attributes}
}
function Get-Acl {
    param([string]$LiteralPath)
    $acl=New-Object Security.AccessControl.DirectorySecurity
    $admin=[Security.Principal.SecurityIdentifier]'S-1-5-32-544'
    $system=[Security.Principal.SecurityIdentifier]'S-1-5-18'
    $users=[Security.Principal.SecurityIdentifier]'S-1-5-32-545'
    $acl.SetOwner($admin)
    $acl.SetAccessRuleProtection($true,$false)
    foreach($sid in @($admin,$system)){
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $sid,[Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.AccessControlType]::Allow))
    }
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $users,[Security.AccessControl.FileSystemRights]::ReadAndExecute,
        [Security.AccessControl.AccessControlType]::Allow))
    $extra=$null
    if ($LiteralPath -eq $script:Leaf) {
        switch($script:Variant){
            'write' {$extra=[Security.AccessControl.FileSystemRights]::WriteData}
            'delete' {$extra=[Security.AccessControl.FileSystemRights]::Delete}
            'inheritance' {$acl.SetAccessRuleProtection($false,$true)}
            'owner' {$acl.SetOwner($users)}
        }
    }
    if ($LiteralPath -eq 'C:\Program Files') {
        switch($script:Variant){
            'ancestor-delete' {$extra=[Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles}
            'ancestor-permissions' {$extra=[Security.AccessControl.FileSystemRights]::ChangePermissions}
            'ancestor-owner' {$acl.SetOwner($users)}
        }
    }
    if($null -ne $extra){
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $users,$extra,[Security.AccessControl.AccessControlType]::Allow))
    }
    return $acl
}
"""
        source = source.replace("@@VARIANT@@", variant) + recovery._BOUNDARY_SCRIPT
        command = base64.b64encode(source.encode("utf-16-le")).decode("ascii")
        return subprocess.run([
            "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
            "-NoProfile", "-NonInteractive", "-EncodedCommand", command,
        ], input=json.dumps([r"C:\Program Files\EcommerceNativeSmoke\fixture\native-boot.json"]),
            text=True, encoding="utf-8", errors="replace", capture_output=True, timeout=30)

    def test_admin_owned_readonly_user_boundary_is_accepted(self) -> None:
        result = self.boundary("valid")
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = json.loads(result.stdout)
        self.assertEqual(len(rows), 3)
        self.assertTrue(all(row["owner"] == "S-1-5-32-544" for row in rows))

    def test_writable_redirected_or_unprotected_boundary_is_rejected(self) -> None:
        for variant in ("write", "delete", "ancestor-delete", "ancestor-permissions",
                        "ancestor-owner", "reparse", "ancestor-reparse", "inheritance", "owner"):
            with self.subTest(variant=variant):
                result = self.boundary(variant)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("Protected", result.stderr)


if __name__ == "__main__":
    unittest.main()
