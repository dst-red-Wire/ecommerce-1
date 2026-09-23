# Product integration tests

Fast unit and transport contract tests live beside their packages. They cover REST behavior, a real in-memory gRPC connection, shared application idempotence, Protobuf event encoding, bounded outbox retry/DLQ behavior, probes, and configuration failure modes.

The PostgreSQL integration suite is tagged `integration` and uses a digest-pinned Testcontainers image. It proves migration replay, restart-safe idempotence, one durable outbox event per committed command, no duplicate event on replay, and full rollback when the outbox insert fails.

When the workstation has no supported Docker daemon or forwarding capability, `make product-check` reports `BLOCKED_RUNTIME`. Unit, compilation, generated-code, contract, Helm, and Tekton static checks remain independently executable.
