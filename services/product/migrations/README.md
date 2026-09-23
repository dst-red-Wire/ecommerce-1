# Product migrations

This directory owns the Product domain PostgreSQL schema migrations. No other service may read or mutate `product-db` directly.

Migrations are loaded by `github.com/jackc/tern/v2/migrate` and are forward-only by default. `001_initial_schema.sql` creates Product/SKU authority plus the durable idempotency command journal. `002_transactional_outbox.sql` expands the schema with the transactional outbox and terminal dead-letter table.

Apply the latest migration with:

```sh
PRODUCT_DATABASE_URL='postgres://...' make product-migrate
```

The database URI is runtime configuration/secret material and must never be committed.

Evolution follows expand -> migrate/backfill -> contract. Application rollback keeps additive migrations in place and restores the previous immutable image. A destructive contraction is a separate reviewed release and requires verified restore evidence.
