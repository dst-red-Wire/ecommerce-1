# Product golden service

Product is the M2 production-grade reference service. It owns products, SKUs, attributes, and base product facts only. Pricing, inventory, catalog presentation, and search projections remain outside this database and codebase.

## Architecture

```text
REST/OpenAPI       gRPC/Protobuf
      \               /
       application use cases
          /          \
 query repository   command repository
                         |
       PostgreSQL aggregate + idempotency journal + outbox
                         |
              bounded async publisher
                         |
                 Kafka / franz-go
```

REST and gRPC are adapters over the same `application.Service`; neither transport owns business rules. Query and command persistence ports are separate. PostgreSQL is the authoritative runtime store, while the in-memory adapter exists only for unit tests and explicit local development.

The canonical contracts are:

- REST: `contracts/openapi/product.v1.yaml`;
- gRPC and event wire format: `contracts/proto/ecommerce/product/v1/product.proto`;
- event names and consumers: `config/contracts/event-contracts.yaml`;
- Product ownership and dependencies: `config/contracts/service-ownership.yaml` and `config/contracts/dependency-map.yaml`.

## Runtime

Apply migrations first, then run the API. Runtime values shown below are examples only; never commit a real database URI or credential.

```sh
PRODUCT_DATABASE_URL='postgres://...' make product-migrate
PRODUCT_DATABASE_URL='postgres://...' \
PRODUCT_KAFKA_BROKERS='kafka-0.example:9092' \
PRODUCT_HOME_SITE='preprod-a' \
PRODUCT_OIDC_ISSUER='https://identity.example/realms/ecommerce' \
PRODUCT_OIDC_AUDIENCE='admin' \
OTEL_EXPORTER_OTLP_ENDPOINT='http://rotel.example:4317' \
make product-run
```

For local behavior without external dependencies:

```sh
PRODUCT_STORAGE=memory make product-run
```

The default listeners are REST `:8080` and gRPC `:9090`.

### Configuration

| Variable | Purpose | Default |
|---|---|---|
| `PRODUCT_STORAGE` | `postgres` or explicit local `memory` | `postgres` |
| `PRODUCT_DATABASE_URL` | Product-owned PostgreSQL connection URI; secret | required for PostgreSQL |
| `PRODUCT_HTTP_ADDR` | REST/health bind address | `:8080` |
| `PRODUCT_GRPC_ADDR` | gRPC bind address | `:9090` |
| `PRODUCT_HOME_SITE` | persisted event home-site identity | required for PostgreSQL |
| `PRODUCT_KAFKA_BROKERS` | comma-separated broker endpoints | required for PostgreSQL |
| `PRODUCT_KAFKA_TOPIC` | Product event topic | `ecommerce.product.events.v1` |
| `PRODUCT_OIDC_ISSUER` | Keycloak-compatible OIDC issuer | required for PostgreSQL |
| `PRODUCT_OIDC_AUDIENCE` | required REST token audience | required for PostgreSQL |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | Rotel OTLP endpoint | telemetry no-op when absent locally |
| `PRODUCT_OUTBOX_MAX_ATTEMPTS` | per-event publish budget before DLQ | `5` |

All retry, lease, polling, delivery, and shutdown durations are externalized with `PRODUCT_OUTBOX_*`, `PRODUCT_KAFKA_*`, and `PRODUCT_SHUTDOWN_TIMEOUT`. Invalid or incomplete PostgreSQL configuration fails closed. Logs are JSON `slog` records and never include authorization headers, tokens, request/response bodies, database URIs, or event payloads.

## REST and gRPC

REST writes require a valid OIDC bearer token in the configured admin audience. The mesh remains authoritative for internal gRPC caller identity and authorization.

```sh
curl --fail-with-body \
  -H 'Authorization: Bearer <token>' \
  -H 'Idempotency-Key: product-example-0001' \
  -H 'Content-Type: application/json' \
  -d '{"name":"NOMA Lamp","status":"active"}' \
  http://127.0.0.1:8080/v1/products
```

```sh
grpcurl -plaintext \
  -d '{"idempotencyKey":"product-example-0001","name":"NOMA Lamp","status":"active"}' \
  127.0.0.1:9090 ecommerce.product.v1.ProductService/CreateProduct
```

Write commands require an 8-128 character idempotency key. Replaying the same key and payload returns the original result without a second mutation or event. Reusing the key with a different payload fails deterministically. Updates also require the current `If-Match`/`if_match` ETag.

`GET /healthz` proves that the process is alive. `GET /readyz` checks PostgreSQL connectivity and the complete Product aggregate, command-journal, outbox, and DLQ schema. Kafka is asynchronous: an outage does not lose or roll back already committed commands because the event remains in the outbox.

## PostgreSQL, migrations, and outbox

`pgx` owns runtime connections and `sqlc` owns generated SQL bindings. Migrations are embedded and applied by Tern in numeric order:

- `001_initial_schema.sql`: Product/SKU authority and durable command journal;
- `002_transactional_outbox.sql`: outbox and terminal dead-letter storage.

Every write inserts the command journal, changes the aggregate, and inserts the Protobuf event in one PostgreSQL transaction. If any of the three writes fails, all three roll back. The integration test forces an outbox constraint failure and proves that neither business state nor journal survives.

The franz-go publisher claims rows with `FOR UPDATE SKIP LOCKED`, publishes with an aggregate key, and records completion. Delivery is at least once. A crash after Kafka acknowledgement but before the database acknowledgement can replay an event; consumers must remain idempotent as required by the central event contract. Retry uses a bounded exponential delay. Exhausted events move atomically to `outbox_dead_letters`; there is no unbounded per-event retry loop.

Schema evolution follows expand -> migrate/backfill -> contract. Do not perform destructive contraction in the same release that removes a field from readers. Rollback normally means rolling the application back to the previous immutable digest while leaving additive migrations in place. Destructive schema rollback requires a reviewed restore/recreation procedure.

## Observability and security

OpenTelemetry instruments REST and gRPC and exports OTLP to the configured Rotel endpoint. W3C trace/baggage propagation is enabled. Correlation and causation identifiers enter the durable event envelope without logging sensitive bodies.

The OCI runtime is scratch, non-root UID/GID `65532`, has no shell/package manager/compiler, and exposes only ports 8080/9090. The Fleet chart applies Pod Security `restricted`, drops every Linux capability, disables privilege escalation and service-account token mounting, uses a read-only root filesystem, defines requests/limits and probes, and starts with default-deny NetworkPolicy.

The database URI is referenced from `product-runtime/database-url`; OpenBao/ESO in M4 owns materialization. The repository never contains a Secret value.

## Validation

```sh
make api-generate
make product-check
make contracts
```

`make product-check` validates generated sqlc and Protobuf drift, formatting, vet/build, race tests, and the digest-pinned PostgreSQL Testcontainers suite. If Docker daemon access or forwarding is unavailable, the repository gate reports `BLOCKED_RUNTIME`; use the independent unit/static gates rather than changing the architecture or workstation runtime implicitly.

The Fleet chart and Tekton release pipeline are statically validated in M2. Real Fleet reconciliation, Harbor push, Trivy scan of the pushed digest, Syft SBOM, Cosign signature/attestation, and remote Tekton evidence are not claimed until M4 supplies those runtimes.

## Reusable golden-service conventions

- autonomous Go module, migrations, tests, and one `Containerfile` per service;
- domain/application/port/adapter boundaries with shared REST/gRPC use cases;
- CQRS-oriented query and command persistence ports;
- fail-closed typed environment configuration and secret references only;
- JSON structured logging, OpenTelemetry, correlation, health, and dependency readiness;
- pgx/sqlc ownership, additive migrations, optimistic concurrency, and restart-safe idempotence;
- aggregate mutation + command journal + Protobuf outbox in one transaction;
- franz-go publisher with aggregate ordering key, bounded retry, and durable DLQ;
- scratch non-root multi-architecture container baseline;
- Fleet/Helm Pod Security, probes, resources, autoscaling, and default-deny network baseline;
- Tekton exact-SHA gates followed by OCI build, Trivy, Syft, Cosign, Harbor digest, and evidence;
- unit, transport contract, generated-code drift, and PostgreSQL/Testcontainers integration tests.

These conventions are reusable. Product business rules, Product schemas, and Product events are not shared libraries and must not be copied into other domains.
