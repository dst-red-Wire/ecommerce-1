import ast
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
CONTROLLER = (ROOT / "scripts/repoctl.py").read_text(encoding="utf-8")
MAKEFILE = (ROOT / "Makefile").read_text(encoding="utf-8")


class DeliverContractTests(unittest.TestCase):
    def test_make_target_uses_native_controller(self):
        self.assertIn("deliver:", MAKEFILE)
        self.assertIn("scripts/repoctl.py deliver", MAKEFILE)
        self.assertNotIn("git-deliver.sh", MAKEFILE)

    def test_deliver_never_merges_or_force_pushes(self):
        module = ast.parse(CONTROLLER)
        deliver = next(node for node in module.body if isinstance(node, ast.FunctionDef) and node.name == "deliver")
        source = ast.get_source_segment(CONTROLLER, deliver) or ""
        self.assertNotIn('"merge"', source)
        self.assertNotIn("push -f", source)
        self.assertNotIn("--force-with-lease", source)
        self.assertNotIn("--admin", source)

    def test_delivery_binds_exact_evidence_and_verifies_pr_head(self):
        self.assertIn("exact_commit_evidence", CONTROLLER)
        self.assertIn(".context", CONTROLLER)
        self.assertIn("PR head mismatch", CONTROLLER)

        module = ast.parse(CONTROLLER)
        deliver = next(node for node in module.body if isinstance(node, ast.FunctionDef) and node.name == "deliver")
        pr_list_calls = []
        for call in ast.walk(deliver):
            if (
                isinstance(call, ast.Call)
                and isinstance(call.func, ast.Name)
                and call.func.id == "output"
                and call.args
                and isinstance(call.args[0], ast.List)
            ):
                items = call.args[0].elts
                if (
                    len(items) >= 3
                    and isinstance(items[0], ast.Name)
                    and items[0].id == "gh"
                    and isinstance(items[1], ast.Constant)
                    and items[1].value == "pr"
                    and isinstance(items[2], ast.Constant)
                    and items[2].value == "list"
                ):
                    pr_list_calls.append(items)

        self.assertEqual(1, len(pr_list_calls))
        literal_args = [
            item.value for item in pr_list_calls[0] if isinstance(item, ast.Constant) and isinstance(item.value, str)
        ]
        for required in ("--head", "--base", "--state", "open", "--json", "number,url"):
            self.assertIn(required, literal_args)

    def test_delivery_enforces_canonical_github_forge(self):
        policy = (ROOT / "config/contracts/review-policy.yaml").read_text(encoding="utf-8")
        self.assertIn("forge: github", policy)
        self.assertNotIn("forge: gitea", policy)

        module = ast.parse(CONTROLLER)
        deliver = next(node for node in module.body if isinstance(node, ast.FunctionDef) and node.name == "deliver")
        calls = [node for node in ast.walk(deliver) if isinstance(node, ast.Call)]
        central_policy_call = any(
            isinstance(call.func, ast.Name) and call.func.id == "repository_delivery_policy"
            for call in calls
        )
        direct_policy_call = any(
            isinstance(call.func, ast.Name)
            and call.func.id == "ruby_yaml"
            and call.args
            and isinstance(call.args[0], ast.Constant)
            and call.args[0].value == "config/contracts/review-policy.yaml"
            for call in calls
        )
        self.assertTrue(central_policy_call or direct_policy_call)
        self.assertIn("must be github", CONTROLLER)


if __name__ == "__main__":
    unittest.main()
