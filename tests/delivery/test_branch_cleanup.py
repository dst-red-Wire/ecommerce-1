from __future__ import annotations

import contextlib
import copy
import importlib.util
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("repoctl_branch_cleanup_test", ROOT / "scripts" / "repoctl.py")
assert SPEC and SPEC.loader
REPOCTL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPOCTL)
BASE_POLICY = REPOCTL.repository_delivery_policy()


class BranchCleanupTests(unittest.TestCase):
    def git(self, root: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", "-c", "commit.gpgsign=false", *args],
            cwd=root,
            check=check,
            text=True,
            capture_output=True,
        )

    def init_repo(self, directory: str) -> tuple[Path, Path]:
        base = Path(directory)
        remote = base / "remote.git"
        root = base / "repo"
        self.git(base, "init", "--bare", str(remote))
        self.git(base, "init", "-b", "main", str(root))
        self.git(root, "config", "user.name", "Branch Cleanup Test")
        self.git(root, "config", "user.email", "branch-cleanup@example.invalid")
        self.git(root, "config", "commit.gpgsign", "false")
        (root / "README.md").write_text("base\n", encoding="utf-8")
        self.git(root, "add", "README.md")
        self.git(root, "commit", "-m", "base")
        self.git(root, "remote", "add", "origin", str(remote))
        self.git(root, "push", "-u", "origin", "main")
        return root, remote

    def cleanup_policy(self) -> dict:
        return copy.deepcopy(BASE_POLICY)

    def unavailable_evidence(self) -> dict:
        return REPOCTL._unavailable_github_cleanup_evidence()

    def github_evidence(
        self,
        *,
        merged: dict[str, set[str]] | None = None,
        absorbed: dict[str, dict[str, dict]] | None = None,
        source_heads: dict[str, set[str]] | None = None,
        diagnostics: dict[str, str] | None = None,
    ) -> dict:
        return {
            "available": True,
            "merged_pr_heads": merged or {},
            "absorbed_pr_heads": absorbed or {},
            "absorption_source_heads": source_heads or {},
            "diagnostics": diagnostics or {},
        }

    def branch_exists(self, root: Path, branch: str) -> bool:
        return self.git(root, "show-ref", "--verify", "--quiet", f"refs/heads/{branch}", check=False).returncode == 0

    def remote_branch_exists(self, root: Path, branch: str) -> bool:
        return bool(self.git(root, "ls-remote", "--heads", "origin", f"refs/heads/{branch}").stdout.strip())

    def pull(
        self,
        number: int,
        branch: str,
        head: str,
        *,
        state: str = "CLOSED",
        base: str = "main",
        repository: str = "dst-red-Wire/ecommerce-1",
        head_repository: str | None = None,
        merge_commit: str = "",
        body: str = "",
    ) -> dict:
        merged = state == "MERGED"
        return {
            "number": number,
            "state": "closed" if state in {"CLOSED", "MERGED"} else "open",
            "merged_at": "2026-09-27T09:37:06Z" if merged else None,
            "merge_commit_sha": merge_commit if merged else None,
            "body": body,
            "head": {
                "ref": branch,
                "sha": head,
                "repo": {"full_name": head_repository or repository},
            },
            "base": {"ref": base, "sha": "9" * 40, "repo": {"full_name": repository}},
        }

    def proof(
        self,
        source_pr: int,
        source_head: str,
        source_branch: str,
        *,
        absorbing_pr: int = 159,
        absorbing_head: str = "d" * 40,
        repository: str = "dst-red-Wire/ecommerce-1",
        status: str = "ABSORBED",
        content_lineage: list[dict] | None = None,
    ) -> dict:
        proof = {
            "schema_version": 2,
            "kind": "PullRequestAbsorptionProof",
            "source_repository": repository,
            "source_pr": source_pr,
            "source_head_sha": source_head,
            "source_branch": source_branch,
            "source_base": "main",
            "absorbing_repository": repository,
            "absorbing_pr": absorbing_pr,
            "absorbing_head_sha": absorbing_head,
            "content_lineage": content_lineage
            if content_lineage is not None
            else [
                {
                    "from_sha": source_head,
                    "to_sha": absorbing_head,
                    "relation": "ancestor",
                }
            ],
            "proof_method": "git-content-lineage-v1",
            "status": status,
        }
        proof["proof_id"] = REPOCTL._canonical_absorption_proof_id(proof)
        return proof

    def proof_body(self, *proofs: dict) -> str:
        return "\n".join(
            f"<!-- pull-request-absorption-proof:v2\n{json.dumps(proof, sort_keys=True)}\n-->"
            for proof in proofs
        )

    def evaluate(
        self,
        pulls: list[dict],
        *,
        merge_in_main: bool = True,
        head_in_merge: bool = True,
        content_in_absorbing: bool = True,
        tree_matches: bool = True,
    ) -> dict:
        policy = self.cleanup_policy()

        def ancestor(head: str, base: str) -> bool:
            if base == "origin/main":
                return merge_in_main
            if head == "d" * 40 and base == "e" * 40:
                return head_in_merge
            return content_in_absorbing

        def tree(commit: str) -> str:
            return "7" * 40 if tree_matches or commit == "a" * 40 else "8" * 40

        with (
            mock.patch.object(REPOCTL, "_git_is_ancestor", side_effect=ancestor),
            mock.patch.object(REPOCTL, "_git_tree_sha", side_effect=tree),
        ):
            return REPOCTL._evaluate_github_cleanup_evidence(
                pulls,
                repository="dst-red-Wire/ecommerce-1",
                default_branch="main",
                base_ref="origin/main",
                merge_method="merge",
                proof_contract=policy["cleanup"]["automatic_branch_cleanup"]["absorbed_pr_proof"],
            )

    def one_source_fixture(self) -> tuple[list[dict], dict]:
        source_head = "a" * 40
        proof = self.proof(149, source_head, "feat/source")
        pulls = [
            self.pull(149, "feat/source", source_head),
            self.pull(
                159,
                "integration/sources",
                "d" * 40,
                state="MERGED",
                merge_commit="e" * 40,
                body=self.proof_body(proof),
            ),
        ]
        return pulls, proof

    def test_repository_delivery_policy_rejects_incomplete_cleanup_contract(self):
        policy = REPOCTL.repository_delivery_policy()
        broken = {
            **policy,
            "cleanup": {
                **policy["cleanup"],
                "automatic_branch_cleanup": {
                    "enabled": True,
                },
            },
        }
        with self.assertRaisesRegex(RuntimeError, "automatic branch cleanup policy drift"):
            REPOCTL._validate_repository_delivery_policy(broken)

    def test_central_contract_enables_safe_automatic_cleanup(self):
        cleanup = REPOCTL.repository_delivery_policy()["cleanup"]["automatic_branch_cleanup"]
        self.assertIs(True, cleanup["enabled"])
        self.assertEqual(["git-sync", "finish-pr"], cleanup["triggers"])
        self.assertEqual(
            [
                "head-is-ancestor-of-default-branch",
                "merged-pr-head-matches-current-branch-head",
                "closed-pr-proven-absorbed-by-merged-pr",
            ],
            cleanup["delete_when"],
        )
        proof = cleanup["absorbed_pr_proof"]
        self.assertIs(True, proof["required"])
        self.assertIs(True, proof["fail_closed"])
        self.assertEqual("pull-request-absorption-proof:v2", proof["marker"])
        self.assertEqual("sha256-canonical-binding", proof["proof_id"])
        self.assertEqual("git-content-lineage-v1", proof["proof_method"])
        self.assertEqual(["ancestor", "same-tree"], proof["content_lineage"]["allowed_relations"])
        self.assertTrue(
            proof["destructive_revalidation"]["required_immediately_before_each_delete"]
        )
        self.assertEqual("exact-head-sha", cleanup["github_merge_proof"])
        self.assertIs(True, cleanup["remote_delete_requires_exact_lease"])
        self.assertIs(True, cleanup["local_delete_requires_compare_and_delete"])
        self.assertIn("active-worktree", cleanup["preserve"])
        self.assertIn("branch-advanced-after-merged-pr", cleanup["preserve"])

    def test_real_three_source_fixture_is_absorbed_by_exact_merged_pr(self):
        absorbing_head = "c8073533c6afc1ac2e471bf51580c11fcabf47f9"
        merge_commit = "542e3998f6c0fee1daba021467173badd1208a08"
        replay_149 = "8a31633ade74a5396cb94e55207d0086533e66b1"
        replay_150 = "b793b4630d9803b605f624a31cb8f40322256c6c"
        replay_151 = "880b7cd8e149673779c7321f512b7f1c82367299"
        sources = [
            (149, "feat/execution-properties-policy", "a29ccf5c50f52a68bd0305278c49747038c6350b"),
            (150, "governance/capability-resolver", "57c431515ef839d099319919e1dd2abbf5622384"),
            (151, "fix/execution-profile-runtime-boundary", "8169361feff2a8429caaf1411ba88fe96a4c1a23"),
        ]
        source_149 = sources[0][2]
        source_150 = sources[1][2]
        source_151 = sources[2][2]
        lineages = {
            149: [
                {"from_sha": source_149, "to_sha": replay_149, "relation": "same-tree"},
                {"from_sha": replay_149, "to_sha": source_150, "relation": "ancestor"},
                {"from_sha": source_150, "to_sha": replay_150, "relation": "same-tree"},
                {"from_sha": replay_150, "to_sha": source_151, "relation": "ancestor"},
                {"from_sha": source_151, "to_sha": replay_151, "relation": "same-tree"},
                {"from_sha": replay_151, "to_sha": absorbing_head, "relation": "ancestor"},
            ],
            150: [
                {"from_sha": source_150, "to_sha": replay_150, "relation": "same-tree"},
                {"from_sha": replay_150, "to_sha": source_151, "relation": "ancestor"},
                {"from_sha": source_151, "to_sha": replay_151, "relation": "same-tree"},
                {"from_sha": replay_151, "to_sha": absorbing_head, "relation": "ancestor"},
            ],
            151: [
                {"from_sha": source_151, "to_sha": replay_151, "relation": "same-tree"},
                {"from_sha": replay_151, "to_sha": absorbing_head, "relation": "ancestor"},
            ],
        }
        proofs = [
            self.proof(
                number,
                head,
                branch,
                absorbing_head=absorbing_head,
                content_lineage=lineages[number],
            )
            for number, branch, head in sources
        ]
        pulls = [self.pull(number, branch, head) for number, branch, head in sources]
        pulls.append(
            self.pull(
                159,
                "integration/pr149-151-signed",
                absorbing_head,
                state="MERGED",
                merge_commit=merge_commit,
                body=self.proof_body(*proofs),
            )
        )
        with (
            mock.patch.object(REPOCTL, "_git_is_ancestor", return_value=True),
            mock.patch.object(REPOCTL, "_git_tree_sha", return_value="4" * 40),
        ):
            evidence = REPOCTL._evaluate_github_cleanup_evidence(
                pulls,
                repository="dst-red-Wire/ecommerce-1",
                default_branch="main",
                base_ref="origin/main",
                merge_method="merge",
                proof_contract=self.cleanup_policy()["cleanup"]["automatic_branch_cleanup"]["absorbed_pr_proof"],
            )

        self.assertEqual({branch for _number, branch, _head in sources}, set(evidence["absorbed_pr_heads"]))
        for number, branch, head in sources:
            proof = evidence["absorbed_pr_heads"][branch][head]
            self.assertEqual(number, proof["source_pr"])
            self.assertEqual(159, proof["absorbing_pr"])
            self.assertEqual(absorbing_head, proof["absorbing_head"])
            self.assertEqual(merge_commit, proof["merge_commit"])

    def test_normal_merge_with_advanced_base_uses_lineage_not_tree_equality(self):
        pulls, _proof = self.one_source_fixture()
        evidence = self.evaluate(pulls)
        detail = evidence["absorbed_pr_heads"]["feat/source"]["a" * 40]
        self.assertEqual("d" * 40, detail["absorbing_head"])
        self.assertEqual("e" * 40, detail["merge_commit"])

    def test_absorption_evidence_fails_closed_for_source_and_absorbing_pr_state(self):
        cases = {
            "source-pr-still-open": lambda pulls: pulls[0].update(state="open"),
            "source-pr-was-merged": lambda pulls: pulls[0].update(
                merged_at="2026-09-27T09:00:00Z", merge_commit_sha="f" * 40
            ),
            "source-pr-base-mismatch": lambda pulls: pulls[0]["base"].update(ref="develop"),
            "absorbing-pr-not-merged-open": lambda pulls: pulls[1].update(state="open", merged_at=None),
            "absorbing-pr-not-merged-closed": lambda pulls: pulls[1].update(merged_at=None),
            "absorbing-pr-base-mismatch": lambda pulls: pulls[1]["base"].update(ref="develop"),
            "absorbing-head-sha-mismatch": lambda pulls: pulls[1]["head"].update(sha="f" * 40),
            "source-repository-mismatch": lambda pulls: pulls[0]["head"]["repo"].update(
                full_name="someone/fork"
            ),
            "absorbing-repository-mismatch": lambda pulls: pulls[1]["head"]["repo"].update(
                full_name="someone/fork"
            ),
        }
        expected = {
            "source-pr-still-open": "source-pr-still-open",
            "source-pr-was-merged": "source-pr-was-merged",
            "source-pr-base-mismatch": "source-pr-base-mismatch",
            "absorbing-pr-not-merged-open": "absorbing-pr-not-merged",
            "absorbing-pr-not-merged-closed": "absorbing-pr-not-merged",
            "absorbing-pr-base-mismatch": "absorbing-pr-base-mismatch",
            "absorbing-head-sha-mismatch": "absorbing-head-sha-mismatch",
            "source-repository-mismatch": "source-repository-mismatch",
            "absorbing-repository-mismatch": "absorbing-repository-mismatch",
        }
        for name, mutate in cases.items():
            with self.subTest(name=name):
                pulls, _proof = self.one_source_fixture()
                mutate(pulls)
                evidence = self.evaluate(pulls)
                self.assertEqual({}, evidence["absorbed_pr_heads"])
                self.assertEqual(expected[name], evidence["diagnostics"]["feat/source"])

    def test_absorption_evidence_requires_merge_commit_and_absorbing_head_in_merge_lineage(self):
        pulls, _proof = self.one_source_fixture()
        absent = self.evaluate(pulls, merge_in_main=False)
        self.assertEqual("merge-commit-absent-from-default", absent["diagnostics"]["feat/source"])
        self.assertEqual({}, absent["absorbed_pr_heads"])

        moved = self.evaluate(pulls, head_in_merge=False)
        self.assertEqual(
            "absorbing-head-absent-from-merge-lineage", moved["diagnostics"]["feat/source"]
        )
        self.assertEqual({}, moved["absorbed_pr_heads"])

    def test_absorption_evidence_requires_verified_content_lineage(self):
        pulls, _proof = self.one_source_fixture()
        ancestry_mismatch = self.evaluate(pulls, content_in_absorbing=False)
        self.assertEqual(
            "content-lineage-ancestry-mismatch",
            ancestry_mismatch["diagnostics"]["feat/source"],
        )
        self.assertEqual({}, ancestry_mismatch["absorbed_pr_heads"])

        proof = self.proof(
            149,
            "a" * 40,
            "feat/source",
            content_lineage=[
                {"from_sha": "a" * 40, "to_sha": "d" * 40, "relation": "same-tree"}
            ],
        )
        pulls[1]["body"] = self.proof_body(proof)
        tree_mismatch = self.evaluate(pulls, tree_matches=False)
        self.assertEqual(
            "content-lineage-tree-mismatch", tree_mismatch["diagnostics"]["feat/source"]
        )
        self.assertEqual({}, tree_mismatch["absorbed_pr_heads"])

    def test_content_lineage_verifies_complete_tree_replay_followed_by_ancestry(self):
        with tempfile.TemporaryDirectory() as directory:
            root, _remote = self.init_repo(directory)
            self.git(root, "switch", "-c", "source")
            (root / "feature.txt").write_text("feature\n", encoding="utf-8")
            self.git(root, "add", "feature.txt")
            self.git(root, "commit", "-m", "source implementation")
            source = self.git(root, "rev-parse", "HEAD").stdout.strip()

            self.git(root, "switch", "main")
            self.git(root, "switch", "-c", "integration")
            (root / "feature.txt").write_text("feature\n", encoding="utf-8")
            self.git(root, "add", "feature.txt")
            self.git(root, "commit", "-m", "signed replay")
            replay = self.git(root, "rev-parse", "HEAD").stdout.strip()
            (root / "fix.txt").write_text("qualified fix\n", encoding="utf-8")
            self.git(root, "add", "fix.txt")
            self.git(root, "commit", "-m", "post-replay correction")
            absorbing = self.git(root, "rev-parse", "HEAD").stdout.strip()

            proof = {
                "content_lineage": [
                    {"from_sha": source, "to_sha": replay, "relation": "same-tree"},
                    {"from_sha": replay, "to_sha": absorbing, "relation": "ancestor"},
                ]
            }
            with mock.patch.object(REPOCTL, "ROOT", root):
                self.assertEqual("", REPOCTL._content_lineage_reason(proof))

                proof["content_lineage"][0]["to_sha"] = absorbing
                self.assertEqual(
                    "content-lineage-tree-mismatch", REPOCTL._content_lineage_reason(proof)
                )

    def test_missing_and_ambiguous_absorption_proofs_are_preserved(self):
        pulls, proof_159 = self.one_source_fixture()
        pulls[1]["body"] = ""
        missing = self.evaluate(pulls)
        self.assertEqual("missing-absorption-proof", missing["diagnostics"]["feat/source"])

        proof_160 = self.proof(149, "a" * 40, "feat/source", absorbing_pr=160, absorbing_head="f" * 40)
        pulls[1]["body"] = self.proof_body(proof_159)
        pulls.append(
            self.pull(
                160,
                "integration/other",
                "f" * 40,
                state="MERGED",
                merge_commit="1" * 40,
                body=self.proof_body(proof_160),
            )
        )
        ambiguous = self.evaluate(pulls)
        self.assertEqual("ambiguous-absorption", ambiguous["diagnostics"]["feat/source"])
        self.assertEqual({}, ambiguous["absorbed_pr_heads"])

    def test_explicit_supersession_removes_only_the_exact_proof_id(self):
        pulls, proof = self.one_source_fixture()
        superseded = {**proof, "status": "SUPERSEDED"}
        pulls[1]["body"] = self.proof_body(proof, superseded)
        evidence = self.evaluate(pulls)
        self.assertEqual({}, evidence["absorbed_pr_heads"])
        self.assertEqual("missing-absorption-proof", evidence["diagnostics"]["feat/source"])

    def test_plain_yaml_status_and_forged_or_malformed_bindings_are_not_proof(self):
        contract = self.cleanup_policy()["cleanup"]["automatic_branch_cleanup"]["absorbed_pr_proof"]
        self.assertEqual([], REPOCTL._parse_absorption_proofs("status: ABSORBED", contract))
        self.assertEqual([], REPOCTL._parse_absorption_proofs("```yaml\nstatus: ABSORBED\n```", contract))

        proof = self.proof(149, "a" * 40, "feat/source")
        for name, mutate, reason in (
            ("bad-sha", lambda item: item.update(source_head_sha="abc"), "malformed-sha"),
            ("bad-pr", lambda item: item.update(source_pr="149"), "malformed-pr-number"),
            ("bad-id", lambda item: item.update(proof_id="sha256:" + "0" * 64), "forged-absorption-proof"),
            ("bad-method", lambda item: item.update(proof_method="similar-diff"), "forged-absorption-proof"),
            (
                "disconnected-lineage",
                lambda item: item["content_lineage"][0].update(from_sha="b" * 40),
                "malformed-content-lineage",
            ),
            (
                "lineage-does-not-reach-absorbing-head",
                lambda item: item["content_lineage"][0].update(to_sha="c" * 40),
                "malformed-content-lineage",
            ),
        ):
            with self.subTest(name=name):
                candidate = copy.deepcopy(proof)
                mutate(candidate)
                self.assertEqual(reason, REPOCTL._absorption_proof_shape_reason(candidate, contract))

    def test_forged_marker_blocks_concurrent_valid_proof_for_same_branch(self):
        pulls, proof = self.one_source_fixture()
        forged = {**proof, "source_pr": 150}
        pulls[1]["body"] = self.proof_body(proof, forged)
        evidence = self.evaluate(pulls)
        self.assertEqual({}, evidence["absorbed_pr_heads"])
        self.assertEqual("forged-absorption-proof", evidence["diagnostics"]["feat/source"])

    def test_stale_source_or_absorbing_sha_preserves_branch(self):
        pulls, _proof = self.one_source_fixture()
        pulls[0]["head"]["sha"] = "b" * 40
        source_stale = self.evaluate(pulls)
        self.assertEqual("source-head-sha-mismatch", source_stale["diagnostics"]["feat/source"])

        pulls, _proof = self.one_source_fixture()
        pulls[1]["head"]["sha"] = "c" * 40
        absorbing_stale = self.evaluate(pulls)
        self.assertEqual("absorbing-head-sha-mismatch", absorbing_stale["diagnostics"]["feat/source"])

    def test_planner_preserves_current_worktree_and_advanced_branch(self):
        plan = REPOCTL._plan_branch_cleanup(
            {
                "main": "a" * 40,
                "absorbed": "b" * 40,
                "advanced": "c" * 40,
                "worktree": "d" * 40,
            },
            {
                "main": "a" * 40,
                "absorbed": "b" * 40,
                "advanced": "c" * 40,
                "worktree": "d" * 40,
            },
            current_branch="main",
            default_branch="main",
            active_worktrees={"main", "worktree"},
            ancestor_heads={
                "a" * 40: True,
                "b" * 40: True,
                "c" * 40: False,
                "d" * 40: True,
            },
            github_evidence=self.github_evidence(merged={"advanced": {"e" * 40}}),
        )
        by_key = {(item["scope"], item["branch"]): item for item in plan}
        self.assertEqual("delete", by_key[("local", "absorbed")]["action"])
        self.assertEqual("head-is-ancestor-of-default-branch", by_key[("local", "absorbed")]["reason"])
        self.assertEqual("keep", by_key[("remote", "advanced")]["action"])
        self.assertEqual("branch-advanced-after-merged-pr", by_key[("remote", "advanced")]["reason"])
        self.assertEqual("keep", by_key[("local", "worktree")]["action"])
        self.assertEqual("active-worktree", by_key[("local", "worktree")]["reason"])
        self.assertEqual("keep", by_key[("local", "main")]["action"])
        self.assertEqual("protected-branch", by_key[("local", "main")]["reason"])

    def test_planner_preserves_all_refs_when_one_side_has_unabsorbed_work(self):
        absorbed = "b" * 40
        unique = "c" * 40
        plan = REPOCTL._plan_branch_cleanup(
            {"diverged": unique},
            {"diverged": absorbed},
            current_branch="main",
            default_branch="main",
            active_worktrees={"main"},
            ancestor_heads={absorbed: True, unique: False},
            github_evidence=self.github_evidence(),
        )
        by_scope = {item["scope"]: item for item in plan}
        self.assertEqual("keep", by_scope["remote"]["action"])
        self.assertEqual("branch-with-unabsorbed-head", by_scope["remote"]["reason"])
        self.assertEqual("keep", by_scope["local"]["action"])
        self.assertEqual("branch-with-unabsorbed-head", by_scope["local"]["reason"])

    def test_planner_uses_exact_absorption_and_preserves_advanced_branch(self):
        source_head = "a" * 40
        advanced_head = "b" * 40
        detail = {
            "criterion": "closed-pr-proven-absorbed-by-merged-pr",
            "source_pr": 149,
            "source_head": source_head,
            "absorbing_pr": 159,
            "absorbing_head": "d" * 40,
            "merge_commit": "e" * 40,
            "default_branch": "main",
            "proof_id": "sha256:" + "1" * 64,
        }
        evidence = self.github_evidence(
            absorbed={"source": {source_head: detail}, "advanced": {source_head: detail}},
            source_heads={"source": {source_head}, "advanced": {source_head}},
        )
        plan = REPOCTL._plan_branch_cleanup(
            {"source": source_head, "advanced": advanced_head},
            {"source": source_head, "advanced": advanced_head},
            current_branch="main",
            default_branch="main",
            active_worktrees={"main"},
            ancestor_heads={source_head: False, advanced_head: False},
            github_evidence=evidence,
        )
        by_key = {(item["scope"], item["branch"]): item for item in plan}
        self.assertEqual("delete", by_key[("remote", "source")]["action"])
        self.assertEqual(
            "closed-pr-proven-absorbed-by-merged-pr", by_key[("remote", "source")]["reason"]
        )
        self.assertEqual(detail, by_key[("remote", "source")]["evidence"])
        self.assertEqual("keep", by_key[("local", "advanced")]["action"])
        self.assertEqual("branch-advanced-after-absorption", by_key[("local", "advanced")]["reason"])

    def test_github_unavailable_preserves_non_ancestor_but_not_ancestor(self):
        ancestor = "a" * 40
        unique = "b" * 40
        plan = REPOCTL._plan_branch_cleanup(
            {"ancestor": ancestor, "unique": unique},
            {},
            current_branch="main",
            default_branch="main",
            active_worktrees={"main"},
            ancestor_heads={ancestor: True, unique: False},
            github_evidence=self.unavailable_evidence(),
        )
        by_branch = {item["branch"]: item for item in plan}
        self.assertEqual("delete", by_branch["ancestor"]["action"])
        self.assertEqual("head-is-ancestor-of-default-branch", by_branch["ancestor"]["reason"])
        self.assertEqual("keep", by_branch["unique"]["action"])
        self.assertEqual("github-evidence-unavailable", by_branch["unique"]["reason"])

    def test_remote_delete_uses_exact_sha_lease(self):
        sha = "a" * 40
        completed = subprocess.CompletedProcess([], 0, "", "")
        with mock.patch.object(REPOCTL, "run", return_value=completed) as run:
            ok, detail = REPOCTL._delete_branch_ref("remote", "feature", sha)
        self.assertTrue(ok)
        self.assertEqual("", detail)
        command = run.call_args.args[0]
        self.assertEqual(
            [
                "git",
                "push",
                f"--force-with-lease=refs/heads/feature:{sha}",
                "origin",
                ":refs/heads/feature",
            ],
            command,
        )

    def test_local_delete_uses_compare_and_delete_old_sha(self):
        sha = "b" * 40
        completed = subprocess.CompletedProcess([], 0, "", "")
        with mock.patch.object(REPOCTL, "run", return_value=completed) as run:
            ok, detail = REPOCTL._delete_branch_ref("local", "feature", sha)
        self.assertTrue(ok)
        self.assertEqual("", detail)
        self.assertEqual(
            ["git", "update-ref", "-d", "refs/heads/feature", sha],
            run.call_args.args[0],
        )

    def test_delete_rejects_non_exact_sha_before_git(self):
        with mock.patch.object(REPOCTL, "run") as run:
            ok, detail = REPOCTL._delete_branch_ref("remote", "feature", "abc")
        self.assertFalse(ok)
        self.assertIn("not exact", detail)
        run.assert_not_called()

    def test_absorption_authorization_is_refetched_and_must_match_exactly(self):
        source_head = "a" * 40
        detail = {
            "criterion": "closed-pr-proven-absorbed-by-merged-pr",
            "source_pr": 149,
            "source_head": source_head,
            "absorbing_pr": 159,
            "absorbing_head": "d" * 40,
            "absorbing_branch": "integration/sources",
            "merge_commit": "e" * 40,
            "proof_id": "sha256:" + "1" * 64,
            "proof_method": "git-content-lineage-v1",
            "content_lineage": [
                {"from_sha": source_head, "to_sha": "d" * 40, "relation": "ancestor"}
            ],
            "default_branch": "main",
        }
        item = {
            "branch": "feat/source",
            "head_sha": source_head,
            "evidence": detail,
        }
        fresh = self.github_evidence(
            absorbed={"feat/source": {source_head: copy.deepcopy(detail)}},
            source_heads={"feat/source": {source_head}},
        )
        completed = subprocess.CompletedProcess([], 0, "", "")
        with (
            mock.patch.object(REPOCTL, "run", return_value=completed) as run,
            mock.patch.object(REPOCTL, "_github_cleanup_evidence", return_value=fresh) as github,
        ):
            authorized, reason = REPOCTL._revalidate_absorption_authorization(
                item,
                default_branch="main",
                base_ref="origin/main",
                merge_method="merge",
                proof_contract=self.cleanup_policy()["cleanup"]["automatic_branch_cleanup"][
                    "absorbed_pr_proof"
                ],
            )
        self.assertTrue(authorized)
        self.assertEqual("", reason)
        self.assertEqual(["git", "fetch", "origin", "--prune"], run.call_args.args[0])
        github.assert_called_once()

        revoked = self.github_evidence(diagnostics={"feat/source": "source-pr-still-open"})
        with (
            mock.patch.object(REPOCTL, "run", return_value=completed),
            mock.patch.object(REPOCTL, "_github_cleanup_evidence", return_value=revoked),
        ):
            authorized, reason = REPOCTL._revalidate_absorption_authorization(
                item,
                default_branch="main",
                base_ref="origin/main",
                merge_method="merge",
                proof_contract=self.cleanup_policy()["cleanup"]["automatic_branch_cleanup"][
                    "absorbed_pr_proof"
                ],
            )
        self.assertFalse(authorized)
        self.assertIn("source-pr-still-open", reason)

    def test_cleanup_preserves_absorbed_branch_when_authorization_changes_after_planning(self):
        with tempfile.TemporaryDirectory() as directory:
            root, _remote = self.init_repo(directory)
            self.git(root, "switch", "-c", "absorbed-source")
            (root / "feature.txt").write_text("feature\n", encoding="utf-8")
            self.git(root, "add", "feature.txt")
            self.git(root, "commit", "-m", "feature")
            source_head = self.git(root, "rev-parse", "HEAD").stdout.strip()
            self.git(root, "push", "-u", "origin", "absorbed-source")
            self.git(root, "switch", "main")
            detail = {
                "criterion": "closed-pr-proven-absorbed-by-merged-pr",
                "source_pr": 149,
                "source_head": source_head,
                "absorbing_pr": 159,
                "absorbing_head": "d" * 40,
                "absorbing_branch": "integration/sources",
                "merge_commit": "e" * 40,
                "proof_id": "sha256:" + "1" * 64,
                "proof_method": "git-content-lineage-v1",
                "content_lineage": [
                    {"from_sha": source_head, "to_sha": "d" * 40, "relation": "ancestor"}
                ],
                "default_branch": "main",
            }
            planned = self.github_evidence(
                absorbed={"absorbed-source": {source_head: detail}},
                source_heads={"absorbed-source": {source_head}},
            )
            revoked = self.github_evidence(
                diagnostics={"absorbed-source": "source-pr-still-open"}
            )
            with (
                mock.patch.object(REPOCTL, "ROOT", root),
                mock.patch.object(
                    REPOCTL, "repository_delivery_policy", return_value=self.cleanup_policy()
                ),
                mock.patch.object(
                    REPOCTL, "_github_cleanup_evidence", side_effect=[planned, revoked]
                ) as github,
                mock.patch.object(REPOCTL, "_delete_branch_ref") as delete,
            ):
                self.assertEqual(1, REPOCTL.branch_cleanup())

            self.assertEqual(2, github.call_count)
            delete.assert_not_called()
            self.assertTrue(self.branch_exists(root, "absorbed-source"))
            self.assertTrue(self.remote_branch_exists(root, "absorbed-source"))

    def test_cleanup_deletes_branch_whose_head_is_already_in_main(self):
        with tempfile.TemporaryDirectory() as directory:
            root, _remote = self.init_repo(directory)
            self.git(root, "switch", "-c", "absorbed")
            (root / "absorbed.txt").write_text("absorbed\n", encoding="utf-8")
            self.git(root, "add", "absorbed.txt")
            self.git(root, "commit", "-m", "absorbed")
            self.git(root, "push", "-u", "origin", "absorbed")
            self.git(root, "switch", "main")
            self.git(root, "merge", "--ff-only", "absorbed")
            self.git(root, "push", "origin", "main")

            with (
                mock.patch.object(REPOCTL, "ROOT", root),
                mock.patch.object(REPOCTL, "repository_delivery_policy", return_value=self.cleanup_policy()),
                mock.patch.object(REPOCTL, "_github_cleanup_evidence", return_value=self.github_evidence()),
            ):
                self.assertEqual(0, REPOCTL.branch_cleanup())

            self.assertFalse(self.branch_exists(root, "absorbed"))
            self.assertFalse(self.remote_branch_exists(root, "absorbed"))

    def test_cleanup_deletes_exact_head_of_merged_pr_even_when_not_ancestor(self):
        with tempfile.TemporaryDirectory() as directory:
            root, _remote = self.init_repo(directory)
            self.git(root, "switch", "-c", "squash-merged")
            (root / "feature.txt").write_text("feature\n", encoding="utf-8")
            self.git(root, "add", "feature.txt")
            self.git(root, "commit", "-m", "feature")
            head = self.git(root, "rev-parse", "HEAD").stdout.strip()
            self.git(root, "push", "-u", "origin", "squash-merged")
            self.git(root, "switch", "main")

            with (
                mock.patch.object(REPOCTL, "ROOT", root),
                mock.patch.object(REPOCTL, "repository_delivery_policy", return_value=self.cleanup_policy()),
                mock.patch.object(
                    REPOCTL,
                    "_github_cleanup_evidence",
                    return_value=self.github_evidence(merged={"squash-merged": {head}}),
                ),
            ):
                self.assertEqual(0, REPOCTL.branch_cleanup())

            self.assertFalse(self.branch_exists(root, "squash-merged"))
            self.assertFalse(self.remote_branch_exists(root, "squash-merged"))

    def test_cleanup_preserves_branch_advanced_after_merged_pr(self):
        with tempfile.TemporaryDirectory() as directory:
            root, _remote = self.init_repo(directory)
            self.git(root, "switch", "-c", "advanced")
            (root / "feature.txt").write_text("first\n", encoding="utf-8")
            self.git(root, "add", "feature.txt")
            self.git(root, "commit", "-m", "first")
            merged_head = self.git(root, "rev-parse", "HEAD").stdout.strip()
            (root / "feature.txt").write_text("second\n", encoding="utf-8")
            self.git(root, "commit", "-am", "second")
            self.git(root, "push", "-u", "origin", "advanced")
            self.git(root, "switch", "main")

            with (
                mock.patch.object(REPOCTL, "ROOT", root),
                mock.patch.object(REPOCTL, "repository_delivery_policy", return_value=self.cleanup_policy()),
                mock.patch.object(
                    REPOCTL,
                    "_github_cleanup_evidence",
                    return_value=self.github_evidence(merged={"advanced": {merged_head}}),
                ),
            ):
                self.assertEqual(0, REPOCTL.branch_cleanup())

            self.assertTrue(self.branch_exists(root, "advanced"))
            self.assertTrue(self.remote_branch_exists(root, "advanced"))

    def test_absorbed_branch_dry_run_reports_full_proof_without_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            root, _remote = self.init_repo(directory)
            self.git(root, "switch", "-c", "absorbed-source")
            (root / "feature.txt").write_text("feature\n", encoding="utf-8")
            self.git(root, "add", "feature.txt")
            self.git(root, "commit", "-m", "feature")
            source_head = self.git(root, "rev-parse", "HEAD").stdout.strip()
            self.git(root, "push", "-u", "origin", "absorbed-source")
            self.git(root, "switch", "main")
            detail = {
                "criterion": "closed-pr-proven-absorbed-by-merged-pr",
                "source_pr": 149,
                "source_head": source_head,
                "absorbing_pr": 159,
                "absorbing_head": "d" * 40,
                "merge_commit": "e" * 40,
                "default_branch": "main",
                "proof_id": "sha256:" + "1" * 64,
                "content_lineage": [
                    {"from_sha": source_head, "to_sha": "d" * 40, "relation": "ancestor"}
                ],
            }
            evidence = self.github_evidence(
                absorbed={"absorbed-source": {source_head: detail}},
                source_heads={"absorbed-source": {source_head}},
            )
            output = io.StringIO()
            with (
                mock.patch.object(REPOCTL, "ROOT", root),
                mock.patch.object(REPOCTL, "repository_delivery_policy", return_value=self.cleanup_policy()),
                mock.patch.object(REPOCTL, "_github_cleanup_evidence", return_value=evidence),
                mock.patch.object(REPOCTL, "_delete_branch_ref") as delete,
                contextlib.redirect_stdout(output),
            ):
                self.assertEqual(0, REPOCTL.branch_cleanup(dry_run=True))

            delete.assert_not_called()
            self.assertTrue(self.branch_exists(root, "absorbed-source"))
            self.assertTrue(self.remote_branch_exists(root, "absorbed-source"))
            report = output.getvalue()
            self.assertIn("WOULD_DELETE remote absorbed-source", report)
            self.assertIn("criterion=closed-pr-proven-absorbed-by-merged-pr", report)
            self.assertIn("source_pr=149", report)
            self.assertIn("absorbing_pr=159", report)
            self.assertIn("content_lineage=", report)

    def test_git_sync_automatically_runs_cleanup(self):
        with (
            mock.patch.object(REPOCTL, "git", side_effect=["feature\n", ""]),
            mock.patch.object(REPOCTL, "run"),
            mock.patch.object(REPOCTL, "branch_cleanup", return_value=0) as cleanup,
        ):
            self.assertEqual(0, REPOCTL.git_sync())
        cleanup.assert_called_once_with(dry_run=False, fetch_remote=False)


if __name__ == "__main__":
    unittest.main()
