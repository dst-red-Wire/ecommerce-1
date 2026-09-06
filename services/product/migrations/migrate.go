package migrations

import (
	"context"
	"embed"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/tern/v2/migrate"
)

// Files is the canonical forward-only Product migration set.
//
//go:embed *.sql
var Files embed.FS

// Up migrates the Product database to the latest embedded schema version.
func Up(ctx context.Context, conn *pgx.Conn) error {
	migrator, err := migrate.NewMigrator(ctx, conn, "public.schema_version")
	if err != nil {
		return err
	}
	if err := migrator.LoadMigrations(Files); err != nil {
		return err
	}
	return migrator.Migrate(ctx)
}
