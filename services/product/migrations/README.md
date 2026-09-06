# Product migrations

Database migrations are intentionally deferred to the next M2 persistence tranche. M2A uses only the local in-memory adapter for executable contract-first development and tests.

When PostgreSQL is introduced, this directory will own Product schema migrations, including durable idempotency and outbox tables. No other service may read `product-db` directly.
