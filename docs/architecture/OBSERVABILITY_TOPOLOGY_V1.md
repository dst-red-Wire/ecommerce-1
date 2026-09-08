# Observability topology v1

This document explains the exact machine contract in `config/contracts/observability-topology.yaml`.
The YAML contract is authoritative when prose and machine-readable state disagree.

## Responsibility split

Application telemetry uses OpenTelemetry instrumentation and OTLP. Rotel is the application edge gateway.
Application traces and logs flow to ClickHouse and are explored in HyperDX. Application metrics flow through
vmagent to VictoriaMetrics.

Infrastructure and SRE metrics use the Prometheus exposition ecosystem. vmagent scrapes native endpoints and
only the exporters explicitly required by the contract. VictoriaMetrics is the primary metrics store. Grafana
is the SRE dashboard surface.

Infrastructure logs are collected and enriched by OpenTelemetry Collector, stored in VictoriaLogs, and viewed
in Grafana. vmalert evaluates metric and log rules; Alertmanager owns grouping, deduplication, routing, and
notification delivery.

Data Prepper remains active only for security/SIEM ingestion and enrichment before OpenSearch/Wazuh. It is not
the general application or infrastructure log pipeline.

## Deliberate non-duplication

There is no Prometheus server TSDB in the target topology. Prometheus-compatible endpoints and exporters remain
part of the metrics ecosystem and are scraped by vmagent. Fluent Bit is removed as the general log shipper.
OpenSearch is retained for security search/analytics only, not as the general log store.

HyperDX may use MongoDB for HyperDX metadata only. That database is not a business datastore and must never own
or receive ecommerce domain data.
