"""Focused tests for exact-base qualification compatibility."""

from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest import mock

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import qualification_compatibility as compatibility
import repoctl
import trusted_qualification_policy


class CompatibilityEnvelopeTests(unittest.TestCase):
    BASE = "a" * 40
    HEAD = "b" * 40
    TREE = "c" * 40
    REPOSITORY = "dst-red-Wire/ecommerce-1"
    PR = 171

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        work = Path(self.temp.name)
        self.target = work / "target"
        self.base = work / "base"
        (self.target / ".context/evidence").mkdir(parents=True)
        (self.target / ".context/performance").mkdir(parents=True)
        (self.base / "scripts").mkdir(parents=True)
        self.controller = self.base / "scripts/repoctl.py"
        self.controller.write_text("trusted base controller\n", encoding="utf-8")
        self.raw = self.target / ".context/evidence" / f"{self.HEAD}.json"
        self.audit = self.target / ".context/performance" / f"{self.HEAD}.json"
        self.proof = {
            "schema_version": 5,
            "evidence_kind": "exact_commit",
            "exact_commit_evidence": True,
            "status": "PASS",
            "base_sha": self.BASE,
            "head_sha": self.HEAD,
            "head_tree_sha": self.TREE,
            "qualification_identity": "d" * 64,
            "created_at_epoch": time.time(),
            "gates": [
                {
                    "gate": "governance",
                    "status": "PASS",
                    "exit_code": 0,
                    "execution": "fresh",
                    "log": ".context/logs/governance.log",
                },
                {
                    "gate": "system",
                    "status": "PASS",
                    "exit_code": 0,
                    "execution": "parent-evidence",
                    "reused_from_sha": self.BASE,
                    "promoted_from_worktree": False,
                },
            ],
        }
        self.raw.write_text(json.dumps(self.proof), encoding="utf-8")
        self.audit.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "head_sha": self.HEAD,
                    "base_sha": self.BASE,
                    "evidence_status": "PASS",
                }
            ),
            encoding="utf-8",
        )

    def valid_raw(self, path: Path) -> bool:
        try:
            proof = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return False
        return (
            proof.get("status") == "PASS"
            and proof.get("head_sha") == self.HEAD
            and proof.get("base_sha") == self.BASE
            and proof.get("qualification_identity") == "d" * 64
        )

    def valid_audit(self, path: Path) -> bool:
        try:
            audit = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return False
        return (
            audit.get("evidence_status") == "PASS"
            and audit.get("head_sha") == self.HEAD
            and audit.get("base_sha") == self.BASE
        )

    def arguments(self):
        return {
            "repository": self.REPOSITORY,
            "pr_number": self.PR,
            "base_sha": self.BASE,
            "head_sha": self.HEAD,
            "tree_sha": self.TREE,
            "controller_path": self.controller,
            "validate_raw": self.valid_raw,
            "validate_audit": self.valid_audit,
        }

    def create(self):
        return compatibility.create_envelope(
            self.target,
            raw_proof_path=self.raw,
            audit_path=self.audit,
            **self.arguments(),
        )

    def test_archived_base_proof_and_gate_provenance_are_reverified(self):
        created = self.create()
        self.assertEqual("PASS", created["status"])
        self.assertTrue(created["envelope_sha256"].startswith("sha256:"))
        self.assertEqual(
            ["fresh", "parent-evidence"],
            [gate["execution"] for gate in created["gate_results"]],
        )
        self.assertEqual(self.BASE, created["gate_results"][1]["reused_from_sha"])
        envelope = json.loads((self.target / created["path"]).read_text())
        self.assertEqual(
            self.proof["created_at_epoch"],
            envelope["qualification"]["created_at_epoch"],
        )
        found = compatibility.find_envelope(self.target, **self.arguments())
        self.assertEqual(created["envelope_sha256"], found["envelope_sha256"])

    def test_head_only_envelope_does_not_grant_delivery_authority(self):
        self.create()
        arguments = self.arguments()
        arguments["validate_raw"] = lambda _path: False
        self.assertIsNone(compatibility.find_envelope(self.target, **arguments))

    def test_tampered_envelope_and_raw_archive_fail_closed(self):
        created = self.create()
        envelope = self.target / created["path"]
        payload = json.loads(envelope.read_text())
        payload["qualification"]["status"] = "FAIL"
        envelope.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaises(compatibility.CompatibilityError):
            compatibility.verify_envelope(
                self.target,
                envelope,
                **self.arguments(),
            )

        envelope.write_text(
            json.dumps(
                {
                    **payload,
                    "qualification": {**payload["qualification"], "status": "PASS"},
                }
            ),
            encoding="utf-8",
        )
        raw_archive = self.target / created["raw_proof_path"]
        raw_archive.write_text(raw_archive.read_text() + " ", encoding="utf-8")
        self.assertIsNone(compatibility.find_envelope(self.target, **self.arguments()))

    def test_wrong_pr_or_tree_cannot_reuse_envelope(self):
        created = self.create()
        envelope = self.target / created["path"]
        for field, value in (("pr_number", self.PR + 1), ("tree_sha", "e" * 40)):
            arguments = self.arguments()
            arguments[field] = value
            with self.subTest(field=field):
                with self.assertRaises(compatibility.CompatibilityError):
                    compatibility.verify_envelope(self.target, envelope, **arguments)

    def test_head_proof_is_archived_as_data_before_base_requalification(self):
        raw_bytes, audit_bytes = self.raw.read_bytes(), self.audit.read_bytes()
        archived = compatibility.archive_head_artifacts(
            self.target,
            head_sha=self.HEAD,
            raw_proof_path=self.raw,
            audit_path=self.audit,
            clear_originals=True,
        )
        self.assertFalse(archived["raw"]["authority"])
        self.assertFalse(archived["audit"]["authority"])
        self.assertEqual(
            raw_bytes, (self.target / archived["raw"]["path"]).read_bytes()
        )
        self.assertEqual(
            audit_bytes, (self.target / archived["audit"]["path"]).read_bytes()
        )
        self.assertFalse(self.raw.exists())
        self.assertFalse(self.audit.exists())


class TrustedQualificationBoundaryTests(unittest.TestCase):
    def test_trusted_toolchain_root_cannot_be_redirected_by_head(self):
        with (
            mock.patch.dict(
                repoctl.os.environ,
                {
                    "REPOCTL_TRUSTED_CONTROLLER": str(Path(repoctl.__file__).resolve()),
                    "REPOCTL_TRUSTED_POLICY_ROOT": str(repoctl.SCRIPT_DIR.parent),
                },
            ),
            mock.patch.object(repoctl, "ROOT", Path("/untrusted/head")),
        ):
            self.assertEqual(
                repoctl.SCRIPT_DIR.parent, repoctl._toolchain_policy_root()
            )
        with mock.patch.dict(
            repoctl.os.environ,
            {
                "REPOCTL_TRUSTED_CONTROLLER": "/untrusted/head/scripts/repoctl.py",
                "REPOCTL_TRUSTED_POLICY_ROOT": "/untrusted/head",
            },
        ):
            with self.assertRaises(RuntimeError):
                repoctl._toolchain_policy_root()

    def test_head_only_handler_command_is_rejected_without_execution(self):
        policy = yaml.safe_load(
            (ROOT / "config/contracts/qualification-execution-policy.yaml").read_text()
        )
        request = {
            "toolchain-pinned": {
                "sha256": "sha256:" + "1" * 64,
                "handler": "command",
                "argv": ["/bin/sh", "-c", "touch /tmp/should-not-run"],
            },
        }
        with mock.patch("subprocess.run") as executed:
            with self.assertRaises(
                trusted_qualification_policy.TrustedQualificationPolicyError
            ):
                trusted_qualification_policy.validate_trusted_capability_requests(
                    policy,
                    ["toolchain-pinned"],
                    request,
                )
            executed.assert_not_called()

    def test_trusted_policy_loader_never_selects_head_command_definition(self):
        trusted_policy = yaml.safe_load(
            (ROOT / "config/contracts/qualification-execution-policy.yaml").read_text()
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            head = Path(temp_dir)
            head_policy = head / "config/contracts/qualification-execution-policy.yaml"
            head_policy.parent.mkdir(parents=True)
            head_policy.write_text(
                "gates:\n  governance:\n    command:\n"
                "      handler: command\n      argv: [/bin/sh, -c, harmful]\n",
                encoding="utf-8",
            )
            trusted = {
                "trusted_root": ROOT,
                "target_root": head,
                "base_sha": "a" * 40,
                "head_sha": "b" * 40,
                "pr_number": 171,
            }
            with (
                mock.patch.object(repoctl, "ROOT", head),
                mock.patch.object(
                    repoctl, "_trusted_pr_execution_context", return_value=trusted
                ),
                mock.patch.object(repoctl, "_QUALIFICATION_EXECUTION_POLICY", None),
                mock.patch.object(
                    repoctl, "_QUALIFICATION_EXECUTION_POLICY_ROOT", None
                ),
                mock.patch.object(
                    repoctl, "_QUALIFICATION_EXECUTION_POLICY_TRUSTED", False
                ),
                mock.patch.object(
                    trusted_qualification_policy,
                    "load_trusted_execution_policy",
                    return_value=trusted_policy,
                ) as loader,
            ):
                selected = repoctl.qualification_execution_policy()
            loader.assert_called_once_with(ROOT, head, "a" * 40, "b" * 40)
            self.assertNotEqual(
                {"handler": "command", "argv": ["/bin/sh", "-c", "harmful"]},
                selected["gates"]["governance"]["command"],
            )
            self.assertEqual(
                "command", head_policy.read_text().split("handler: ")[1].splitlines()[0]
            )

    def test_explicit_repository_binding_works_in_finish_pr_subprocess(self):
        trusted = {
            "trusted_root": ROOT,
            "pr_number": 171,
            "base_sha": "a" * 40,
            "head_sha": "b" * 40,
        }
        found = {
            "raw_proof_path": ".context/evidence/controller-compatibility/v1/raw/proof.json",
            "performance_audit_path": ".context/evidence/controller-compatibility/v1/audit/audit.json",
            "path": ".context/evidence/controller-compatibility/v1/envelopes/171/proof.json",
            "envelope_sha256": "sha256:" + "e" * 64,
            "gate_results": [],
        }
        witness = (
            "dst-red-Wire/ecommerce-1",
            171,
            "a" * 40,
            "b" * 40,
            "c" * 40,
            found["envelope_sha256"],
        )
        token = repoctl._PR_LOOP_FRESH_WITNESS.set(witness)
        self.addCleanup(lambda: repoctl._PR_LOOP_FRESH_WITNESS.reset(token))
        with (
            mock.patch.object(
                repoctl, "_trusted_pr_execution_context", return_value=trusted
            ),
            mock.patch.object(
                repoctl,
                "git",
                side_effect=lambda *args: (
                    "a" * 40 if args[-1] == "a" * 40 else "c" * 40
                ),
            ),
            mock.patch.object(
                compatibility,
                "find_envelope",
                return_value=found,
            ) as lookup,
        ):
            result = repoctl._pr_loop_qualification(
                "a" * 40,
                "b" * 40,
                repository="dst-red-Wire/ecommerce-1",
            )
        self.assertEqual("PASS", result["status"])
        self.assertEqual(found["envelope_sha256"], result["compatibility_digest"])
        self.assertEqual(
            "dst-red-Wire/ecommerce-1",
            lookup.call_args.kwargs["repository"],
        )

    def test_invalid_envelope_inventory_returns_controlled_failure(self):
        trusted = {
            "trusted_root": ROOT,
            "pr_number": 171,
            "base_sha": "a" * 40,
            "head_sha": "b" * 40,
        }
        token = repoctl._PR_LOOP_FRESH_WITNESS.set(
            (
                "dst-red-Wire/ecommerce-1",
                171,
                "a" * 40,
                "b" * 40,
                "c" * 40,
                "sha256:" + "e" * 64,
            )
        )
        self.addCleanup(lambda: repoctl._PR_LOOP_FRESH_WITNESS.reset(token))
        with (
            mock.patch.object(
                repoctl, "_trusted_pr_execution_context", return_value=trusted
            ),
            mock.patch.object(
                repoctl,
                "git",
                side_effect=lambda *args: (
                    "a" * 40 if args[-1] == "a" * 40 else "c" * 40
                ),
            ),
            mock.patch.object(
                compatibility,
                "find_envelope",
                side_effect=compatibility.CompatibilityError("too many envelopes"),
            ),
        ):
            result = repoctl._pr_loop_qualification(
                "a" * 40,
                "b" * 40,
                repository="dst-red-Wire/ecommerce-1",
            )
        self.assertEqual("FAIL", result["status"])
        self.assertIn("too many envelopes", result["reason"])

    def test_non_object_raw_proof_is_rejected_without_traceback(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            context = root / ".context"
            (context / "evidence").mkdir(parents=True)
            (context / "evidence" / ("b" * 40 + ".json")).write_text(
                "[]",
                encoding="utf-8",
            )

            def git_value(*args):
                if args[:2] == ("rev-parse", "HEAD"):
                    return "b" * 40
                if args[0] == "rev-parse":
                    return "b" * 40
                return ""

            with (
                mock.patch.object(repoctl, "ROOT", root),
                mock.patch.object(
                    repoctl,
                    "CONTEXT",
                    context,
                ),
                mock.patch.object(repoctl, "git", side_effect=git_value),
            ):
                self.assertIsNone(
                    repoctl._valid_exact_evidence("a" * 40, "b" * 40),
                )

    def test_trusted_pr_qualification_ignores_canonical_head_evidence(self):
        trusted = {
            "trusted_root": ROOT,
            "pr_number": self_dummy_pr(),
            "base_sha": "a" * 40,
            "head_sha": "b" * 40,
        }
        token = repoctl._PR_LOOP_REPOSITORY.set("dst-red-Wire/ecommerce-1")
        self.addCleanup(lambda: repoctl._PR_LOOP_REPOSITORY.reset(token))
        with (
            mock.patch.object(
                repoctl, "_trusted_pr_execution_context", return_value=trusted
            ),
            mock.patch.object(
                repoctl,
                "git",
                side_effect=lambda *args: (
                    "a" * 40 if args[-1] == "a" * 40 else "c" * 40
                ),
            ),
            mock.patch.object(
                compatibility,
                "find_envelope",
                return_value=None,
            ) as find,
            mock.patch.object(
                repoctl,
                "_valid_exact_evidence",
            ) as raw,
        ):
            result = repoctl._pr_loop_qualification("a" * 40, "b" * 40)
        self.assertEqual("MISSING", result["status"])
        find.assert_not_called()
        raw.assert_not_called()


def self_dummy_pr() -> int:
    return 171


if __name__ == "__main__":
    unittest.main()
