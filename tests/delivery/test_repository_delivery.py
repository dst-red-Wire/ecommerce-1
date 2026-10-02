from __future__ import annotations

import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "scripts/repository_delivery.py"
SPEC = importlib.util.spec_from_file_location("repository_delivery_test", MODULE)
assert SPEC and SPEC.loader
RD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RD)

import managed_gh as MG


class EvidenceMetricsTests(unittest.TestCase):
    def test_metrics_count_execution_reuse_and_saved_time(self):
        records = [
            {"gate": "governance", "status": "PASS", "duration_seconds": 2.0, "content_cache_hits": 2},
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
                "execution_counts": {"fresh": 1, "parent-evidence": 1, "skipped": 1},
                "content_cache_gates": 1,
                "content_cache_direct_gates": 0,
                "content_cache_hits": 2,
                "content_cache_misses": 0,
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


class TrustedPRBindingTests(unittest.TestCase):
    def test_uses_rest_base_and_head_even_if_cli_sha_fields_disagree(self):
        base_sha, head_sha = "a" * 40, "b" * 40
        payload = {
            "number": 166, "state": "open", "draft": False,
            "base": {"ref": "main", "sha": base_sha},
            "head": {
                "ref": "feat/sync", "sha": head_sha,
                "repo": {"full_name": "owner/repo"},
            },
            "baseRefOid": "c" * 40,
            "headRefOid": "d" * 40,
        }
        with mock.patch.object(RD, "_output", return_value=json.dumps(payload)) as output:
            binding = RD._github_pr_binding(ROOT, "gh", "owner/repo", 166)
        output.assert_called_once_with(
            ["gh", "api", "repos/owner/repo/pulls/166"],
            cwd=ROOT, env=mock.ANY,
        )
        self.assertEqual("/usr/bin:/bin", output.call_args.kwargs["env"]["PATH"])
        self.assertEqual(base_sha, binding["base_sha"])
        self.assertEqual(head_sha, binding["head_sha"])

    def test_authenticated_gh_cannot_spawn_inherited_path_git(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            repo = root / "repo"
            subprocess.run(
                ["/usr/bin/git", "init", "-q", str(repo)], check=True
            )
            fake_bin = root / "fake-bin"
            fake_bin.mkdir()
            marker = root / "fake-git-ran"
            fake_git = fake_bin / "git"
            fake_git.write_text(
                f"#!/bin/sh\nprintf ran > {marker}\nexit 2\n",
                encoding="utf-8",
            )
            fake_git.chmod(0o700)
            fake_gh = root / "gh"
            fake_gh.write_text(
                "#!/bin/sh\n"
                "[ \"$GH_TOKEN\" = fixture-only ] || exit 3\n"
                "git rev-parse --show-toplevel >/dev/null || exit 4\n"
                "printf '%s\\n' '{\"nameWithOwner\":\"owner/repo\"}'\n",
                encoding="utf-8",
            )
            fake_gh.chmod(0o700)
            inherited = f"{fake_bin}:/usr/bin:/bin"
            subprocess.run(
                ["git", "--version"], cwd=repo,
                env={"PATH": inherited}, capture_output=True, check=False,
            )
            self.assertTrue(marker.exists(), "the fake PATH git must be executable")
            marker.unlink()
            with mock.patch.dict(
                RD.os.environ,
                {"PATH": inherited, "GH_TOKEN": "fixture-only"},
            ):
                self.assertEqual(
                    "owner/repo", RD._github_repository(repo, str(fake_gh))
                )
            self.assertFalse(marker.exists(), "pinned gh must use the fixed Git PATH")

    def test_cli_only_sha_fields_cannot_authorize_transition(self):
        payload = {
            "number": 166, "state": "open", "draft": False,
            "baseRefOid": "a" * 40, "headRefOid": "b" * 40,
        }
        with mock.patch.object(RD, "_output", return_value=json.dumps(payload)):
            with self.assertRaisesRegex(RuntimeError, "REST pull request base/head"):
                RD._github_pr_binding(ROOT, "gh", "owner/repo", 166)


class BundleDeliveryTests(unittest.TestCase):
    def git(self, cwd: Path, *args: str) -> str:
        return subprocess.check_output(["git", *args], cwd=cwd, text=True).strip()

    def init_repo(self, path: Path) -> None:
        subprocess.run(["git", "init", "-b", "main", str(path)], check=True, capture_output=True, text=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=path, check=True)
        subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=path, check=True)
        subprocess.run(["git", "config", "commit.gpgsign", "false"], cwd=path, check=True)
        (path / "README.md").write_text("base\n", encoding="utf-8")
        subprocess.run(["git", "add", "README.md"], cwd=path, check=True)
        subprocess.run(
            ["git", "-c", "commit.gpgsign=false", "commit", "-m", "base"],
            cwd=path,
            check=True,
            capture_output=True,
            text=True,
        )

    def test_bundle_branch_requires_exact_unique_feature_head(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "repo"
            self.init_repo(root)
            subprocess.run(["git", "switch", "-c", "feat/proof"], cwd=root, check=True, capture_output=True, text=True)
            (root / "feature.txt").write_text("x\n", encoding="utf-8")
            subprocess.run(["git", "add", "feature.txt"], cwd=root, check=True)
            subprocess.run(
                ["git", "-c", "commit.gpgsign=false", "commit", "-m", "feature"],
                cwd=root,
                check=True,
                capture_output=True,
                text=True,
            )
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
            subprocess.run(
                ["git", "-c", "commit.gpgsign=false", "commit", "-m", "feature"],
                cwd=source,
                check=True,
                capture_output=True,
                text=True,
            )
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
            self.assertEqual("isolated-delivery", seen["env"]["ECOMMERCE_EXECUTION_SCOPE"])

    def test_trusted_pr_transition_ignores_head_wrapper_and_controller(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            trusted = td / "trusted"
            self.init_repo(trusted)
            (trusted / "scripts").mkdir()
            trusted_wrapper = trusted / "scripts/repository_delivery.py"
            trusted_controller = trusted / "scripts/repoctl.py"
            trusted_wrapper.write_text("# trusted wrapper\n", encoding="utf-8")
            trusted_controller.write_text(
                "print('OWNER_AUTH_REQUIRED')\nraise SystemExit(1)\n",
                encoding="utf-8",
            )
            subprocess.run(["git", "add", "scripts"], cwd=trusted, check=True)
            subprocess.run(
                ["git", "commit", "-m", "trusted delivery boundary"],
                cwd=trusted,
                check=True,
                capture_output=True,
                text=True,
            )
            base_sha = self.git(trusted, "rev-parse", "HEAD")

            target = td / "target"
            subprocess.run(
                ["git", "clone", str(trusted), str(target)],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(["git", "config", "user.name", "Test"], cwd=target, check=True)
            subprocess.run(
                ["git", "config", "user.email", "test@example.invalid"], cwd=target, check=True
            )
            subprocess.run(["git", "config", "commit.gpgsign", "false"], cwd=target, check=True)
            subprocess.run(
                ["git", "switch", "-c", "feat/tamper"],
                cwd=target,
                check=True,
                capture_output=True,
                text=True,
            )
            marker = target / "head-controller-ran"
            (target / "scripts/repository_delivery.py").write_text(
                f"from pathlib import Path\nPath({str(marker)!r}).write_text('wrapper')\n",
                encoding="utf-8",
            )
            (target / "scripts/repoctl.py").write_text(
                f"from pathlib import Path\nPath({str(marker)!r}).write_text('controller')\n",
                encoding="utf-8",
            )
            subprocess.run(["git", "add", "scripts"], cwd=target, check=True)
            subprocess.run(
                ["git", "commit", "-m", "tamper with head delivery"],
                cwd=target,
                check=True,
                capture_output=True,
                text=True,
            )
            head_sha = self.git(target, "rev-parse", "HEAD")
            fsmonitor_marker = target / ".git/fsmonitor-ran"
            fsmonitor = target / ".git/fsmonitor-canary"
            fsmonitor.write_text(
                f"#!/bin/sh\nprintf ran > {fsmonitor_marker}\necho token\n",
                encoding="utf-8",
            )
            fsmonitor.chmod(0o700)
            subprocess.run(
                ["/usr/bin/git", "-C", str(target), "config", "core.fsmonitor", str(fsmonitor)],
                check=True,
            )
            # Prove that the fixture is executable under the old unguarded read.
            subprocess.run(
                ["/usr/bin/git", "-C", str(target), "status", "--porcelain"],
                check=True, capture_output=True, text=True,
            )
            self.assertTrue(fsmonitor_marker.exists())
            fsmonitor_marker.unlink()
            binding = {
                "number": 162,
                "state": "OPEN",
                "draft": False,
                "base_sha": base_sha,
                "head_sha": head_sha,
                "head_repository": "owner/repo",
            }
            seen = {}
            real_run = RD._run

            def recording_run(cmd, *, cwd, check=True, capture=False, env=None):
                if str(trusted_controller) in cmd:
                    seen["cmd"] = list(cmd)
                    seen["cwd"] = Path(cwd)
                    seen["env"] = dict(env or {})
                return real_run(cmd, cwd=cwd, check=check, capture=capture, env=env)

            with (
                mock.patch.object(RD, "__file__", str(trusted_wrapper)),
                mock.patch(
                    "managed_gh.resolve_managed_gh",
                    return_value=("gh", "2.0.0", "a" * 64),
                ) as resolve_gh,
                mock.patch.object(
                    RD, "require_command",
                    side_effect=AssertionError("inherited PATH must not select gh"),
                ),
                mock.patch.object(RD, "_github_pr_binding", return_value=binding),
                mock.patch.object(RD, "_github_repository", return_value="owner/repo"),
                mock.patch.object(RD, "_run", side_effect=recording_run),
            ):
                rc = RD.trusted_pr_transition(
                    trusted,
                    target,
                    162,
                    "python3",
                )

            self.assertEqual(1, rc)
            resolve_gh.assert_called_once()
            self.assertEqual(trusted, resolve_gh.call_args.args[0])
            self.assertEqual(
                "/usr/bin:/bin", resolve_gh.call_args.kwargs["env"]["PATH"]
            )
            self.assertFalse(marker.exists(), "the PR-head delivery code must never execute")
            self.assertFalse(
                fsmonitor_marker.exists(),
                "target-local fsmonitor must not run under owner credentials",
            )
            self.assertEqual(target, seen["cwd"])
            self.assertEqual(str(trusted_controller), seen["cmd"][2])
            self.assertEqual(base_sha, seen["env"]["REPOCTL_TRUSTED_BASE_SHA"])
            self.assertEqual(head_sha, seen["env"]["REPOCTL_TRUSTED_HEAD_SHA"])


class ManagedGhProbeTests(unittest.TestCase):
    def test_default_probes_ignore_inherited_git_and_credentials(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fake_bin = root / "fake-bin"
            fake_bin.mkdir()
            marker = root / "fake-git-ran"
            fake_git = fake_bin / "git"
            fake_git.write_text(f"#!/bin/sh\nprintf ran > {marker}\nexit 91\n", encoding="utf-8")
            fake_git.chmod(0o700)

            version = "2.101.0"
            tool_home = root / "tool-home"
            binary = tool_home / f"share/ecommerce-1/tools/gh-{version}/bin/gh"
            binary.parent.mkdir(parents=True)
            binary.write_text(
                "#!/bin/sh\n"
                "[ -z \"$GH_TOKEN\" ] || exit 70\n"
                "[ \"$PATH\" = /usr/bin:/bin ] || exit 71\n"
                "[ \"$HOME\" = /nonexistent ] || exit 72\n"
                "git --version >/dev/null || exit 73\n"
                "if [ \"$1\" = --version ]; then\n"
                f"  printf 'gh version {version} (fixture)\\n'\n"
                "elif [ \"$1\" = api ] && [ \"$2\" = --help ]; then\n"
                "  printf 'Flags: --paginate --slurp\\n'\n"
                "else\n"
                "  exit 74\n"
                "fi\n",
                encoding="utf-8",
            )
            binary.chmod(0o700)
            link = tool_home / "bin/gh"
            link.parent.mkdir(parents=True)
            link.symlink_to(binary)
            archive = tool_home / f"cache/gh-{version}-linux-amd64.tar.gz"
            archive.parent.mkdir(parents=True)
            with tarfile.open(archive, "w:gz") as package:
                member = tarfile.TarInfo(f"gh_{version}_linux_amd64/bin/gh")
                content = binary.read_bytes()
                member.size = len(content)
                member.mode = 0o755
                package.addfile(member, io.BytesIO(content))
            trusted = root / "trusted"
            lock = trusted / "config/contracts/toolchain-lock.json"
            lock.parent.mkdir(parents=True)
            lock.write_text(json.dumps({
                "versions": {
                    "GH_VERSION": version,
                    "GH_SHA256_LINUX_AMD64_TARGZ": hashlib.sha256(archive.read_bytes()).hexdigest(),
                },
                "tool_lifecycle": {"active": {"gh": {
                    "version_ref": "GH_VERSION",
                    "checksum_ref": "GH_SHA256_LINUX_AMD64_TARGZ",
                    "provision": {"type": "ansible", "tags": "gh"},
                }}},
                "capability_policy": {"managed_install_root": {
                    "environment": "ECOMMERCE_TOOL_HOME",
                    "fallback": "~/.local",
                    "bin_subdirectory": "bin",
                    "share_subdirectory": "share/ecommerce-1",
                    "cache_subdirectory": "cache",
                    "fallback_cache_root": "~/.cache/ecommerce-1",
                }},
            }), encoding="utf-8")
            with mock.patch.dict(MG.os.environ, {
                "ECOMMERCE_TOOL_HOME": str(tool_home),
                "PATH": f"{fake_bin}:/usr/bin:/bin",
                "GH_TOKEN": "fixture-secret",
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "core.fsmonitor",
                "GIT_CONFIG_VALUE_0": str(fake_git),
            }, clear=True):
                self.assertEqual(str(binary), MG.resolve_managed_gh(trusted)[0])
            self.assertFalse(marker.exists(), "managed gh probes must not execute inherited git")


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

    def test_gitea_https_profile_derives_api_without_enabling_status_by_itself(self):
        with mock.patch.dict(
            RD.os.environ, {"GITEA_HTTPS_URL": "https://gitea.ecommerce.local/"}, clear=True
        ):
            self.assertIsNone(RD._gitea_config())
        with mock.patch.dict(
            RD.os.environ,
            {
                "GITEA_HTTPS_URL": "https://gitea.ecommerce.local/",
                "GITEA_REPOSITORY": "dst-red-Wire/ecommerce-1",
                "GITEA_TOKEN": "secret",
            },
            clear=True,
        ):
            self.assertEqual(
                (
                    "https://gitea.ecommerce.local/api/v1",
                    "dst-red-Wire/ecommerce-1",
                    "secret",
                ),
                RD._gitea_config(),
            )

    def test_gitea_endpoint_conflict_is_rejected(self):
        with mock.patch.dict(
            RD.os.environ,
            {
                "GITEA_HTTPS_URL": "https://gitea.ecommerce.local/",
                "GITEA_API_URL": "https://other.example/api/v1",
            },
            clear=True,
        ):
            with self.assertRaisesRegex(RuntimeError, "contradicts"):
                RD._gitea_config()

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
