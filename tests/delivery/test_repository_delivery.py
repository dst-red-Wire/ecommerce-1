from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "scripts/repository_delivery.py"
SPEC = importlib.util.spec_from_file_location("repository_delivery_test", MODULE)
assert SPEC and SPEC.loader
RD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RD)


class EvidenceMetricsTests(unittest.TestCase):
    def test_metrics_count_execution_reuse_and_saved_time(self):
        records = [
            {"gate": "governance", "status": "PASS", "duration_seconds": 2.0},
            {
                "gate": "frontend:storefront",
                "status": "PASS",
                "duration_seconds": 0.0,
                "reused_from_sha": "a" * 40,
                "source_duration_seconds": 20.0,
            },
            {"gate": "service:unimplemented", "status": "SKIP", "duration_seconds": 0.0},
        ]
        self.assertEqual(
            {
                "executed_gates": 1,
                "reused_gates": 1,
                "skipped_gates": 1,
                "executed_seconds": 2.0,
                "estimated_saved_seconds": 20.0,
                "equivalent_full_seconds": 22.0,
                "estimated_savings_percent": 90.9,
            },
            RD.evidence_metrics(records),
        )

    def test_compare_uses_measured_execution_time(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            full = td / "full.json"
            inc = td / "inc.json"
            full.write_text(
                json.dumps(
                    {
                        "status": "PASS",
                        "head_sha": "1" * 40,
                        "metrics": {"deliver_wall_seconds": 24.0},
                        "gates": [
                            {"gate": "governance", "status": "PASS", "duration_seconds": 2.0},
                            {"gate": "system", "status": "PASS", "duration_seconds": 18.0},
                        ],
                    }
                ),
                encoding="utf-8",
            )
            inc.write_text(
                json.dumps(
                    {
                        "status": "PASS",
                        "head_sha": "2" * 40,
                        "metrics": {"deliver_wall_seconds": 4.0},
                        "gates": [
                            {"gate": "governance", "status": "PASS", "duration_seconds": 1.5},
                            {
                                "gate": "system",
                                "status": "PASS",
                                "duration_seconds": 0.0,
                                "reused_from_sha": "1" * 40,
                                "source_duration_seconds": 18.0,
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )
            result = RD.compare_evidence(full, inc)
        self.assertEqual(20.0, result["full_executed_seconds"])
        self.assertEqual(1.5, result["incremental_executed_seconds"])
        self.assertEqual(18.5, result["measured_time_saved_seconds"])
        self.assertEqual(20.0, result["measured_deliver_time_saved_seconds"])
        self.assertEqual(83.3, result["measured_deliver_savings_percent"])
        self.assertEqual(1, result["incremental_reused_gates"])


class RemoteEvidenceTests(unittest.TestCase):
    def test_publish_requires_exact_pass_and_returns_immutable_digest(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            evidence = root / "evidence.json"
            sha = "c" * 40
            evidence.write_text(
                json.dumps({"status": "PASS", "exact_commit_evidence": True, "head_sha": sha}), encoding="utf-8"
            )

            def fake_sign(_root, _evidence, bundle):
                bundle.write_text("{}", encoding="utf-8")

            def fake_run(cmd, *, cwd, check=True, capture=False, env=None):
                self.assertIn("oras", cmd[0])
                return subprocess.CompletedProcess(
                    cmd, 0, json.dumps({"reference": f"registry.example/evidence@sha256:{'1' * 64}"}), ""
                )

            with (
                mock.patch.dict(RD.os.environ, {"CI_EVIDENCE_REPOSITORY": "registry.example/evidence"}, clear=True),
                mock.patch.object(RD, "require_command", return_value="oras"),
                mock.patch.object(RD, "_cosign_sign_blob", side_effect=fake_sign),
                mock.patch.object(RD, "_run", side_effect=fake_run),
            ):
                result = RD.publish_evidence(root, evidence)

        self.assertEqual(f"registry.example/evidence:sha-{sha}", result["tag_reference"])
        self.assertIn("@sha256:", result["digest_reference"])

    def test_fetch_authenticates_before_copying_exact_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            context = root / ".context"
            sha = "d" * 40

            def fake_run(cmd, *, cwd, check=True, capture=False, env=None):
                output_index = cmd.index("--output") + 1
                staging = Path(cmd[output_index])
                (staging / "evidence.json").write_text(
                    json.dumps({"status": "PASS", "exact_commit_evidence": True, "head_sha": sha}), encoding="utf-8"
                )
                (staging / "evidence.sigstore.json").write_text("{}", encoding="utf-8")
                return subprocess.CompletedProcess(cmd, 0, "", "")

            with (
                mock.patch.dict(RD.os.environ, {"CI_EVIDENCE_REPOSITORY": "registry.example/evidence"}, clear=True),
                mock.patch.object(RD, "require_command", return_value="oras"),
                mock.patch.object(RD, "_run", side_effect=fake_run),
                mock.patch.object(RD, "_cosign_verify_blob") as verify,
            ):
                destination = RD.fetch_evidence(root, context, sha)

            verify.assert_called_once()
            self.assertTrue(destination.is_file())
            self.assertEqual(sha, json.loads(destination.read_text(encoding="utf-8"))["head_sha"])

    def test_fetch_rejects_signed_evidence_for_a_different_sha(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            requested = "e" * 40

            def fake_run(cmd, *, cwd, check=True, capture=False, env=None):
                staging = Path(cmd[cmd.index("--output") + 1])
                (staging / "evidence.json").write_text(
                    json.dumps({"status": "PASS", "exact_commit_evidence": True, "head_sha": "f" * 40}),
                    encoding="utf-8",
                )
                (staging / "evidence.sigstore.json").write_text("{}", encoding="utf-8")
                return subprocess.CompletedProcess(cmd, 0, "", "")

            with (
                mock.patch.dict(RD.os.environ, {"CI_EVIDENCE_REPOSITORY": "registry.example/evidence"}, clear=True),
                mock.patch.object(RD, "require_command", return_value="oras"),
                mock.patch.object(RD, "_run", side_effect=fake_run),
                mock.patch.object(RD, "_cosign_verify_blob"),
            ):
                with self.assertRaisesRegex(RuntimeError, "not exact PASS evidence"):
                    RD.fetch_evidence(root, root / ".context", requested)


class BundleDeliveryTests(unittest.TestCase):
    def git(self, cwd: Path, *args: str) -> str:
        return subprocess.check_output(["git", *args], cwd=cwd, text=True).strip()

    def init_repo(self, path: Path) -> None:
        subprocess.run(["git", "init", "-b", "main", str(path)], check=True, capture_output=True, text=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=path, check=True)
        subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=path, check=True)
        (path / "README.md").write_text("base\n", encoding="utf-8")
        subprocess.run(["git", "add", "README.md"], cwd=path, check=True)
        subprocess.run(["git", "commit", "-m", "base"], cwd=path, check=True, capture_output=True, text=True)

    def test_bundle_branch_requires_exact_unique_feature_head(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "repo"
            self.init_repo(root)
            subprocess.run(["git", "switch", "-c", "feat/proof"], cwd=root, check=True, capture_output=True, text=True)
            (root / "feature.txt").write_text("x\n", encoding="utf-8")
            subprocess.run(["git", "add", "feature.txt"], cwd=root, check=True)
            subprocess.run(["git", "commit", "-m", "feature"], cwd=root, check=True, capture_output=True, text=True)
            head = self.git(root, "rev-parse", "HEAD")
            bundle = Path(td) / "change.bundle"
            subprocess.run(["git", "bundle", "create", str(bundle), "feat/proof"], cwd=root, check=True)
            self.assertEqual("feat/proof", RD._bundle_branch(root, bundle, head))
            with self.assertRaisesRegex(RuntimeError, "EXPECTED_HEAD"):
                RD._bundle_branch(root, bundle, head[:12])

    def test_bundle_delivery_uses_isolated_clone_and_preserves_dirty_caller(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            source = td / "source"
            self.init_repo(source)
            bare = td / "remote.git"
            subprocess.run(
                ["git", "clone", "--bare", str(source), str(bare)], check=True, capture_output=True, text=True
            )
            subprocess.run(["git", "remote", "add", "origin", str(bare)], cwd=source, check=True)
            subprocess.run(
                ["git", "switch", "-c", "feat/proof"], cwd=source, check=True, capture_output=True, text=True
            )
            (source / "feature.txt").write_text("x\n", encoding="utf-8")
            subprocess.run(["git", "add", "feature.txt"], cwd=source, check=True)
            subprocess.run(["git", "commit", "-m", "feature"], cwd=source, check=True, capture_output=True, text=True)
            head = self.git(source, "rev-parse", "HEAD")
            bundle = td / "change.bundle"
            subprocess.run(["git", "bundle", "create", str(bundle), "feat/proof"], cwd=source, check=True)
            # The caller may be dirty; bundle-deliver must preserve it byte-for-byte.
            (source / "dirty.txt").write_text("do not touch\n", encoding="utf-8")
            before = RD._worktree_snapshot(source)

            trusted = td / "trusted.py"
            trusted.write_text("print('trusted')\n", encoding="utf-8")

            seen = {}
            real_run = RD._run

            def fake_run(cmd, *, cwd, check=True, capture=False, env=None):
                if len(cmd) >= 2 and cmd[1] == str(trusted):
                    seen["cwd"] = Path(cwd)
                    seen["cmd"] = list(cmd)
                    seen["env"] = dict(env or {})
                    return subprocess.CompletedProcess(cmd, 0, "", "")
                return real_run(cmd, cwd=cwd, check=check, capture=capture, env=env)

            with mock.patch.object(RD, "_run", side_effect=fake_run):
                rc = RD.bundle_deliver(source, trusted, str(bundle), head, "Proof PR", "main", "python3")
            self.assertEqual(0, rc)
            self.assertEqual(before, RD._worktree_snapshot(source))
            self.assertNotEqual(source, seen["cwd"])
            self.assertIn(str(trusted), seen["cmd"])
            self.assertEqual(str(trusted), seen["env"]["REPOCTL_TRUSTED_CONTROLLER"])


class RemoteStatusTests(unittest.TestCase):
    class Response:
        status = 201

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    def test_github_status_binds_the_exact_sha_and_context(self):
        sha = "a" * 40
        captured = {}

        def fake_urlopen(request, timeout):
            captured["url"] = request.full_url
            captured["payload"] = json.loads(request.data.decode("utf-8"))
            return self.Response()

        env = {"GITHUB_REPOSITORY": "owner/repo", "GITHUB_TOKEN": "secret"}
        with (
            mock.patch.dict(RD.os.environ, env, clear=True),
            mock.patch.object(RD.urllib.request, "urlopen", side_effect=fake_urlopen),
        ):
            self.assertTrue(RD.publish_remote_status(sha, "success", "PASS"))
        self.assertTrue(captured["url"].endswith(f"/statuses/{sha}"))
        self.assertEqual(RD.REMOTE_STATUS_CONTEXT, captured["payload"]["context"])
        self.assertEqual("success", captured["payload"]["state"])

    def test_dual_forge_status_configuration_is_rejected(self):
        env = {
            "GITHUB_REPOSITORY": "owner/repo",
            "GITHUB_TOKEN": "github",
            "GITEA_API_URL": "https://gitea.example/api/v1",
            "GITEA_REPOSITORY": "owner/repo",
            "GITEA_TOKEN": "gitea",
        }
        with mock.patch.dict(RD.os.environ, env, clear=True):
            with self.assertRaisesRegex(RuntimeError, "exactly one"):
                RD.publish_remote_status("b" * 40, "pending", "running")


if __name__ == "__main__":
    unittest.main()
