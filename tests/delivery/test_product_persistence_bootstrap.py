from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
TASKS = (ROOT / "platform/ansible/roles/product_persistence/tasks/main.yml").read_text(encoding="utf-8")


class ProductPersistenceBootstrapContractTest(unittest.TestCase):
    def test_sqlc_generation_precedes_dependency_resolution(self):
        self.assertLess(
            TASKS.index("Generate Product sqlc bindings"),
            TASKS.index("Reconcile exact Product persistence Go dependencies"),
        )

    def test_go_dependency_resolution_is_workspace_isolated(self):
        self.assertIn("GOWORK: 'off'", TASKS)

    def test_dependency_versions_remain_exact(self):
        for dependency in (
            "github.com/jackc/pgx/v5@v5.10.0",
            "github.com/jackc/tern/v2@v2.4.3",
            "github.com/testcontainers/testcontainers-go@v0.44.0",
            "github.com/testcontainers/testcontainers-go/modules/postgres@v0.44.0",
        ):
            self.assertIn(dependency, TASKS)


if __name__ == "__main__":
    unittest.main()
