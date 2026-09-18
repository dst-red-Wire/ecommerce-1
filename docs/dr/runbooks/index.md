# DR Runbook Index

This index tracks the runbooks required by the DR program.

| Runbook | Component / scope | Tier | Status |
|---|---|---|---|
| `dns.md` | PowerDNS, dnsdist, ExternalDNS, DNSSEC, GSLB | Tier-0 | planned |
| `openbao.md` | OpenBao, Raft snapshots, HSM dependencies | Tier-0 | planned |
| `keycloak.md` | Keycloak IAM/RBAC and backing database | Tier-0 | planned |
| `kubernetes.md` | Kubernetes, Velero, CSI, Cilium reconstruction | Tier-0 | planned |
| `postgresql.md` | CloudNativePG, WAL/PITR, failover/fencing | Tier-0 | planned |
| `kafka.md` | Strimzi, Kafka, MirrorMaker2, offsets/replay | Tier-0 / Tier-1 | planned |
| `minio.md` | MinIO objects, versioning, Object Lock, replication | Tier-0 recovery / Tier-1 | planned |
| `harbor.md` | Harbor OCI registry, metadata, images by digest | Tier-0 recovery | planned |
| `multisite-failover.md` | WAN/site loss, fencing, GSLB, failback | Integrated DR | planned |

## Mandatory runbook structure

Every runbook must contain these sections:

1. Symptoms / trigger
2. Preconditions
3. Safety guards
4. Diagnosis
5. Restore or failover procedure
6. Functional validation
7. Rollback / failback
8. Metrics to record
9. Expected evidence
10. Escalation when RTO is exceeded

## Status values

- `planned`: required but not yet written.
- `draft`: procedure exists but has not been demonstrated.
- `tested`: procedure has recent successful evidence.
- `gap`: a known recovery defect or RPO/RTO miss exists and is tracked by a corrective issue.

## Closure rule

A runbook is not promoted to `tested` because it looks complete. It requires a successful execution matching `../testing-policy.md`.