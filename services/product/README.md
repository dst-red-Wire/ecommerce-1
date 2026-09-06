# Product golden service - M2A runtime core

This service is the first executable backend implementation for ecommerce-1 and is bound to `contracts/openapi/product.v1.yaml`.

## Scope in this tranche

Implemented now:

- product-owned base facts and SKUs only;
- one application service shared by the HTTP transport and repository boundary;
- REST `/v1/products` and SKU routes matching the registered OpenAPI contract;
- bearer-token presence gate for the local runtime boundary;
- `Idempotency-Key` replay protection for writes;
- ETag / `If-Match` optimistic concurrency;
- RFC 7807-style `application/problem+json` errors;
- health and readiness endpoints;
- deterministic unit/HTTP contract tests;
- an in-memory adapter used only for local development and tests.

Not claimed complete in M2A:

- PostgreSQL/pgx/sqlc persistence and migrations;
- durable idempotency/outbox tables;
- gRPC/Buf contract and transport;
- Kafka Protobuf events/outbox publisher;
- OpenTelemetry wiring;
- immutable-digest Dockerfile and Kubernetes/Fleet manifests;
- Keycloak signature/audience verification.

Those are the next M2 tranche. The in-memory adapter is not a production source of truth.

## Local run

From the repository root:

```sh
make product-run
```

The default bind address is `:8080`; override with `PRODUCT_HTTP_ADDR`.

Health endpoints do not require authentication:

```text
GET /healthz
GET /readyz
```

Business endpoints require an `Authorization: Bearer <token>` header. M2A checks presence only; real Keycloak verification is intentionally deferred to the security integration tranche rather than faked here.

## Validation

```sh
make product-check
```

This runs formatting verification and all Product Go tests. Repository-wide `make test` also discovers this module.
