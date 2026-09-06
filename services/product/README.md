# Product golden service - M2B PostgreSQL persistence

This service is the first executable backend implementation for ecommerce-1 and is bound to `contracts/openapi/product.v1.yaml`.

## Implemented through M2B

- product-owned base facts and SKUs only;
- one application service shared by transports and persistence adapters;
- REST `/v1/products` and SKU routes matching the registered OpenAPI contract;
- `Idempotency-Key` replay protection for writes;
- ETag / `If-Match` optimistic concurrency;
- RFC 7807-style `application/problem+json` errors;
- PostgreSQL persistence through pgx v5 and sqlc-generated queries;
- versioned forward-only Tern migrations under `migrations/`;
- durable command-journal rows so idempotent responses survive process restarts;
- PostgreSQL-backed readiness checks;
- integration tests against a digest-pinned PostgreSQL container;
- explicit in-memory adapter retained only for local/unit development.

The authoritative runtime store is PostgreSQL. `PRODUCT_STORAGE` defaults to `postgres`; the process fails closed when `PRODUCT_DATABASE_URL` is missing. Memory mode must be selected explicitly.

## Database migration

Set a non-secret PostgreSQL connection URI through the runtime environment or approved secret injection path. Never commit it.

```sh
PRODUCT_DATABASE_URL='postgres://...' make product-migrate
```

The initial schema creates `products`, `skus`, `command_journal`, and Tern's schema-version table. The migration is forward-only; rollback of the initial schema is database recreation/restore rather than an in-place destructive DOWN migration.

## Run

PostgreSQL-backed runtime:

```sh
PRODUCT_DATABASE_URL='postgres://...' make product-run
```

Explicit local memory fallback:

```sh
make product-run-memory
```

The default bind address is `:8080`; override with `PRODUCT_HTTP_ADDR`.

Health endpoints do not require authentication:

```text
GET /healthz
GET /readyz
```

`/readyz` probes PostgreSQL in the default runtime. Business endpoints still require an `Authorization: Bearer <token>` header. Signature/audience validation remains for the IAM/security tranche.

## Persistence bootstrap

After changing Product SQL, sqlc configuration, or persistence dependencies, reconcile generated code and exact module pins with:

```sh
make product-bootstrap-persistence
```

## Validation

```sh
make product-check
```

This verifies formatting, sqlc generation/vet, Go race tests, a real PostgreSQL integration test, and `go vet`. The integration test uses a digest-pinned PostgreSQL image and verifies that data plus idempotency journal entries survive a new process/pool instance.

## Still remaining in M2

- atomic command + idempotency journal + transactional outbox boundary;
- gRPC/Buf contract and transport;
- Kafka Protobuf events/outbox publisher;
- OpenTelemetry wiring;
- immutable-digest service container and Kubernetes/Fleet manifests;
- full Keycloak signature/audience/authorization enforcement.
