from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "bootstrap-product-persistence.sh"


class ProductPersistenceBootstrapContractTest(unittest.TestCase):
    def test_sqlc_generation_precedes_go_dependency_resolution(self):
        text = SCRIPT.read_text()
        first_generate = text.find("sqlc generate")
        first_go_get = text.find("go get github.com/jackc/pgx/v5@v5.10.0")
        self.assertGreaterEqual(first_generate, 0)
        self.assertGreaterEqual(first_go_get, 0)
        self.assertLess(
            first_generate,
            first_go_get,
            "sqlc must generate the repository-local sqlcgen package before go get resolves imports",
        )

    def test_bootstrap_fails_if_sqlcgen_is_not_generated(self):
        text = SCRIPT.read_text()
        self.assertIn("internal/infrastructure/postgres/sqlcgen", text)
        self.assertIn("sqlcgen package was not generated", text)

    def test_go_dependency_resolution_is_workspace_isolated(self):
        text = SCRIPT.read_text()
        isolation = text.find("export GOWORK=off")
        first_go_get = text.find("go get github.com/jackc/pgx/v5@v5.10.0")
        self.assertGreaterEqual(isolation, 0)
        self.assertGreaterEqual(first_go_get, 0)
        self.assertLess(
            isolation,
            first_go_get,
            "module dependency reconciliation must not mutate root go.work",
        )

    def test_workspace_go_floor_matches_testcontainers_requirement(self):
        workspace = (ROOT / "go.work").read_text().splitlines()
        self.assertIn("go 1.25.0", workspace)
        self.assertIn("use ./services/product", workspace)

    def test_dependency_versions_remain_exact(self):
        text = SCRIPT.read_text()
        for dependency in (
            "github.com/jackc/pgx/v5@v5.10.0",
            "github.com/jackc/tern/v2@v2.4.3",
            "github.com/testcontainers/testcontainers-go@v0.44.0",
            "github.com/testcontainers/testcontainers-go/modules/postgres@v0.44.0",
        ):
            self.assertIn(dependency, text)


if __name__ == "__main__":
    unittest.main()
