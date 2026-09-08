from __future__ import annotations

import ast
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("repoctl_worktree_promotion_test", ROOT / "scripts/repoctl.py")
assert SPEC and SPEC.loader
REPOCTL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPOCTL)
MAKEFILE = (ROOT / "Makefile").read_text(encoding="utf-8")


class WorktreeEvidencePromotionTests(unittest.TestCase):
    def init_repo(self, root: Path) -> str:
        subprocess.run(["git", "init", "-q"], cwd=root, check=True)
        subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=root, check=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=root, check=True)
        (root / ".gitignore").write_text(".context/\n", encoding="utf-8")
        (root / "README.md").write_text("base\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=root, check=True)
        subprocess.run(["git", "commit", "-qm", "base"], cwd=root, check=True)
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()

    def test_make_ci_is_evidence_producing_and_ci_full_remains_available(self):
        self.assertIn(
            'ci: ## Run global + affected repository CI and cache promotable worktree evidence\n\t@$(PYTHON) scripts/repoctl.py verify-change --base "$${BASE:-origin/main}" --head WORKTREE',
            MAKEFILE,
        )
        self.assertIn(
            "ci-full: governance contracts automation lint test security terraform ansible ## Run exhaustive portable repository CI checks",
            MAKEFILE,
        )

    def test_worktree_security_scans_materialized_exact_tree_not_checkout_caches(self):
        source = (ROOT / "scripts/repoctl.py").read_text(encoding="utf-8")
        module = ast.parse(source)
        security = next(node for node in module.body if isinstance(node, ast.FunctionDef) and node.name == "security")

        worktree_guards = [
            node
            for node in ast.walk(security)
            if isinstance(node, ast.Compare)
            and any(isinstance(value, ast.Constant) and value.value == "WORKTREE" for value in node.comparators)
            and any(isinstance(value, ast.Constant) and value.value == "HEAD" for value in ast.walk(node.left))
        ]
        self.assertTrue(worktree_guards)
        self.assertTrue(
            any(
                isinstance(node, ast.Assign)
                and any(isinstance(target, ast.Name) and target.id == "tree_sha" for target in node.targets)
                and isinstance(node.value, ast.Call)
                and isinstance(node.value.func, ast.Name)
                and node.value.func.id == "worktree_tree_sha"
                for node in ast.walk(security)
            )
        )

        command_vectors = []
        for call in ast.walk(security):
            if (
                isinstance(call, ast.Call)
                and isinstance(call.func, ast.Name)
                and call.func.id == "run"
                and call.args
                and isinstance(call.args[0], ast.List)
            ):
                vector = []
                for item in call.args[0].elts:
                    if isinstance(item, ast.Constant) and isinstance(item.value, str):
                        vector.append(item.value)
                    elif isinstance(item, ast.Name):
                        vector.append(f"${item.id}")
                    elif (
                        isinstance(item, ast.Call)
                        and isinstance(item.func, ast.Name)
                        and item.func.id == "str"
                        and len(item.args) == 1
                        and isinstance(item.args[0], ast.Name)
                    ):
                        vector.append(f"$str:{item.args[0].id}")
                    else:
                        vector.append("$other")
                command_vectors.append(vector)

        self.assertIn(
            ["git", "archive", "--format=tar", "--output", "$str:archive", "$tree_sha"],
            command_vectors,
        )
        self.assertIn(
            [
                "gitleaks",
                "dir",
                "--config",
                ".gitleaks.toml",
                "--redact",
                "--no-banner",
                "$str:scan_root",
            ],
            command_vectors,
        )

    def test_worktree_tree_sha_does_not_mutate_the_real_index(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.init_repo(root)
            (root / "README.md").write_text("changed\n", encoding="utf-8")
            (root / "new.txt").write_text("new\n", encoding="utf-8")
            index = Path(
                subprocess.check_output(
                    ["git", "rev-parse", "--path-format=absolute", "--git-path", "index"],
                    cwd=root,
                    text=True,
                ).strip()
            )
            before = index.read_bytes()
            with mock.patch.object(REPOCTL, "ROOT", root):
                tree = REPOCTL.worktree_tree_sha()
            self.assertEqual(before, index.read_bytes())
            subprocess.run(["git", "add", "-A"], cwd=root, check=True)
            expected = subprocess.check_output(["git", "write-tree"], cwd=root, text=True).strip()
            self.assertEqual(expected, tree)

    def test_stale_worktree_evidence_is_not_promotable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base = self.init_repo(root)
            context = root / ".context"
            evidence_dir = context / "evidence"
            evidence_dir.mkdir(parents=True)
            (root / "README.md").write_text("validated\n", encoding="utf-8")
            with mock.patch.object(REPOCTL, "ROOT", root), mock.patch.object(REPOCTL, "CONTEXT", context):
                tree = REPOCTL.worktree_tree_sha()
                evidence = {
                    "schema_version": 4,
                    "evidence_kind": "worktree",
                    "base_ref": base,
                    "base_sha": base,
                    "head_ref": "WORKTREE",
                    "head_sha": base,
                    "source_head_sha": base,
                    "source_tree_sha": tree,
                    "exact_commit_evidence": False,
                    "status": "PASS",
                    "changed_paths": ["README.md"],
                    "affected_components": ["global"],
                    "gates": [{"gate": "governance", "status": "PASS", "duration_seconds": 2.0}],
                    "verification": {
                        "mode": "worktree",
                        "source_head_sha": base,
                        "source_tree_sha": tree,
                        "tree_stable": True,
                    },
                }
                (evidence_dir / "worktree.json").write_text(json.dumps(evidence), encoding="utf-8")
                self.assertIsNotNone(REPOCTL._load_promotable_worktree_evidence(base))
                (root / "README.md").write_text("changed after validation\n", encoding="utf-8")
                self.assertIsNone(REPOCTL._load_promotable_worktree_evidence(base))

    def test_exact_commit_promotion_binds_parent_tree_base_and_metrics(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base = self.init_repo(root)
            context = root / ".context"
            evidence_dir = context / "evidence"
            evidence_dir.mkdir(parents=True)
            (root / "README.md").write_text("validated\n", encoding="utf-8")
            with mock.patch.object(REPOCTL, "ROOT", root), mock.patch.object(REPOCTL, "CONTEXT", context):
                tree = REPOCTL.worktree_tree_sha()
                evidence = {
                    "schema_version": 4,
                    "evidence_kind": "worktree",
                    "base_ref": base,
                    "base_sha": base,
                    "head_ref": "WORKTREE",
                    "head_sha": base,
                    "source_head_sha": base,
                    "source_tree_sha": tree,
                    "exact_commit_evidence": False,
                    "status": "PASS",
                    "changed_paths": ["README.md"],
                    "affected_components": ["global"],
                    "gates": [
                        {"gate": "governance", "status": "PASS", "duration_seconds": 12.5},
                        {
                            "gate": "service:catalog",
                            "status": "SKIP",
                            "duration_seconds": 0.0,
                            "reason": "not implemented",
                        },
                    ],
                    "verification": {
                        "mode": "worktree",
                        "source_head_sha": base,
                        "source_tree_sha": tree,
                        "tree_stable": True,
                    },
                }
                (evidence_dir / "worktree.json").write_text(json.dumps(evidence), encoding="utf-8")
                candidate = REPOCTL._load_promotable_worktree_evidence(base)
                self.assertIsNotNone(candidate)
                subprocess.run(["git", "add", "-A"], cwd=root, check=True)
                subprocess.run(["git", "commit", "-qm", "change"], cwd=root, check=True)
                head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
                promoted_path = REPOCTL._promote_worktree_evidence(base, head, candidate)
                self.assertIsNotNone(promoted_path)
                promoted = json.loads(promoted_path.read_text(encoding="utf-8"))
                self.assertTrue(promoted["exact_commit_evidence"])
                self.assertEqual("exact_commit", promoted["evidence_kind"])
                self.assertEqual(head, promoted["head_sha"])
                self.assertEqual(base, promoted["base_sha"])
                self.assertEqual("promoted-worktree", promoted["verification"]["mode"])
                self.assertEqual(tree, promoted["verification"]["commit_tree_sha"])
                self.assertEqual(0, promoted["metrics"]["executed_gates"])
                self.assertEqual(1, promoted["metrics"]["reused_gates"])
                self.assertEqual(12.5, promoted["metrics"]["estimated_saved_seconds"])
                gate = promoted["gates"][0]
                self.assertTrue(gate["promoted_from_worktree"])
                self.assertEqual(0.0, gate["duration_seconds"])
                self.assertEqual(12.5, gate["source_duration_seconds"])

    def test_promotion_refuses_parent_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base = self.init_repo(root)
            context = root / ".context"
            (root / "README.md").write_text("validated\n", encoding="utf-8")
            with mock.patch.object(REPOCTL, "ROOT", root), mock.patch.object(REPOCTL, "CONTEXT", context):
                tree = REPOCTL.worktree_tree_sha()
                source = {
                    "schema_version": 4,
                    "evidence_kind": "worktree",
                    "base_sha": base,
                    "head_sha": "f" * 40,
                    "source_head_sha": "f" * 40,
                    "source_tree_sha": tree,
                    "status": "PASS",
                    "exact_commit_evidence": False,
                    "changed_paths": ["README.md"],
                    "affected_components": ["global"],
                    "gates": [{"gate": "governance", "status": "PASS", "duration_seconds": 1.0}],
                }
                subprocess.run(["git", "add", "-A"], cwd=root, check=True)
                subprocess.run(["git", "commit", "-qm", "change"], cwd=root, check=True)
                head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
                self.assertIsNone(REPOCTL._promote_worktree_evidence(base, head, source))


if __name__ == "__main__":
    unittest.main()
