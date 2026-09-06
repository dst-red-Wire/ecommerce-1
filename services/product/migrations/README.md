# Product migrations

This directory owns the Product domain PostgreSQL schema migrations. No other service may read or mutate `product-db` directly.

Migrations are loaded by `github.com/jackc/tern/v2/migrate` and are forward-only by default. `001_initial_schema.sql` creates Product/SKU authority plus the durable idempotency command journal. Transactional outbox tables are intentionally reserved for the later M2 outbox/Kafka tranche rather than being faked here.

Apply the latest migration with:

```sh
PRODUCT_DATABASE_URL='postgres://...' make product-migrate
```

The database URI is runtime configuration/secret material and must never be committed.
