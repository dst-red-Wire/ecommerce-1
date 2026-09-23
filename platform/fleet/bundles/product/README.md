# Product Fleet bundle

This Helm chart is the M2 static GitOps contract for the Product golden service. Fleet is the reconciler; Tekton must never apply these manifests directly.

The chart fails closed until promotion supplies an immutable Harbor repository/digest, the site identity, Kafka brokers, and the Rotel OTLP endpoint. `product-runtime/database-url` is an interface to the OpenBao/ESO secret-delivery flow and is never materialized in Git.

M2 validates this bundle with synthetic non-secret values only. Real Fleet reconciliation, Harbor pull, ESO materialization, and measured resource promotion are `REMOTE_RUNTIME_NOT_AVAILABLE` until M4. The checked-in resource values are provisional bootstrap candidates and must not be promoted to PROD without the preproduction measurement required by `config/contracts/runtime-efficiency.yaml`.

The default-deny NetworkPolicy and Pod Security `restricted` namespace labels are active in the rendered baseline. M4 owns environment-specific allow policies for the declared Product callers, PostgreSQL, Kafka, and Rotel; this bundle does not guess their namespaces or workload selectors.
