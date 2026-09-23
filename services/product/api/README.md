# Product API authority

The canonical public REST contract is repository-owned at:

`contracts/openapi/product.v1.yaml`

Do not copy or fork that OpenAPI document inside the service. The implementation must adapt to the canonical contract rather than introducing a second source of truth.

The canonical internal gRPC service and Kafka event envelope are repository-owned at:

`contracts/proto/ecommerce/product/v1/product.proto`

Generated Go bindings live under `api/generated/product/v1`. `make api-generate` is the only supported regeneration entry point and produces Go only.
