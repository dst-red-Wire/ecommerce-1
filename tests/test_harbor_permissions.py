import importlib.util
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("local_services_manage", Path("platform/local-services/manage.py"))
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def robot(actions, namespace="ecommerce", kind="project", access=None):
    if access is None:
        access = [{"resource": "repository", "action": action} for action in actions]
    return {"permissions": [{"kind": kind, "namespace": namespace, "access": access}]}


class HarborPermissionTests(unittest.TestCase):
    def test_exact_actions_and_order_independence(self):
        expected = frozenset({("repository", "pull"), ("repository", "push")})
        self.assertEqual(MODULE.normalize_harbor_permissions(robot(["pull", "push"])), expected)
        self.assertEqual(MODULE.normalize_harbor_permissions(robot(["push", "pull"])), expected)

    def test_missing_or_extra_actions_fail_closed(self):
        for actions in (["pull"], ["push"], ["pull", "push", "delete"], ["pull", "push", "scan"]):
            with self.subTest(actions=actions):
                with self.assertRaises(RuntimeError):
                    MODULE.normalize_harbor_permissions(robot(actions))

    def test_duplicate_and_second_scope_fail_closed(self):
        for access in (
            [{"resource": "repository", "action": "pull"}, {"resource": "repository", "action": "pull"}, {"resource": "repository", "action": "push"}],
            [{"resource": "repository", "action": "pull"}, {"resource": "repository", "action": "push"}],
        ):
            value = robot([], access=access)
            if access == [{"resource": "repository", "action": "pull"}, {"resource": "repository", "action": "push"}]:
                value["permissions"].append(value["permissions"][0].copy())
            with self.assertRaises(RuntimeError):
                MODULE.normalize_harbor_permissions(value)

    def test_wrong_scope_kind_resource_and_malformed_values_fail_closed(self):
        cases = [
            robot(["pull", "push"], namespace="other"),
            robot(["pull", "push"], kind="system"),
            robot([], access=[{"resource": "artifact", "action": "pull"}, {"resource": "repository", "action": "push"}]),
            {"permissions": [{"kind": "project", "namespace": "ecommerce"}]},
            {"permissions": "invalid"},
            {"permissions": []},
        ]
        for value in cases:
            with self.subTest(value=value):
                with self.assertRaises(RuntimeError):
                    MODULE.normalize_harbor_permissions(value)


if __name__ == "__main__":
    unittest.main()
