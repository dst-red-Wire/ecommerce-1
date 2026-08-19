# k6 performance profiles

The single versioned scenario supports `smoke`, `baseline`, `load`, `stress`,
`spike`, and `soak`. It targets only an explicitly authorized environment and
uses synthetic data.

`make test-performance` runs `k6 inspect` only and generates no traffic.
Traffic requires `RUN_LOAD_TESTS=1`, `TARGET_URL`, and an explicit profile:

```sh
RUN_LOAD_TESTS=1 TARGET_URL=https://staging.example.test \
TEST_PROFILE=load make test-load
```

Thresholds are configurable with `MAX_P50_MS`, `MAX_P95_MS`, `MAX_P99_MS`,
`MAX_ERROR_RATE`, and `MIN_CHECK_RATE`. The exported summary includes latency,
throughput, request rate, error rate, and check rate. CPU, memory, disk, network,
throttling, and saturation must be correlated from Prometheus/Grafana for the
same test window.

Heavy profiles must never run in normal pull-request CI or against production.
