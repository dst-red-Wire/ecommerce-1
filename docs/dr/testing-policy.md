# DR Testing Policy

## Purpose

Define how disaster-recovery objectives are tested, measured, evidenced, and kept safe.

## Environment policy

Non-destructive verification may run in CI when dependencies and read-only credentials are available.

Destructive tests require both:

```text
DR_ALLOW_DESTRUCTIVE=1
DR_ENVIRONMENT=lab|staging
```

Rules:

- production and `production` are always rejected by destructive scripts;
- an empty or unknown environment is rejected;
- destructive tests are never part of the default `make ci` path;
- the target environment must be explicit and visible in logs without exposing credentials;
- scripts must fail closed when a prerequisite cannot be verified.

## Measurement rules

### RPO

RPO is measured from the latest **actually recoverable** point. A successful scheduled job is insufficient evidence if the artifact cannot be restored or validated.

### RTO

RTO starts when the recovery action is declared and stops only after technical and functional validation succeeds.

### HA

HA tests validate local continuity, such as node or instance loss. HA success does not prove backup or DR recovery.

## Minimum cadence

| Test | Minimum cadence |
|---|---|
| Automated backup verification | every execution |
| Sample restore / integrity check | daily |
| Keycloak login/token synthetic | continuous where supported |
| Harbor critical image pull by digest | daily |
| PostgreSQL isolated PITR restore | weekly |
| OpenSearch rebuild sample | weekly |
| Full OpenSearch rebuild | monthly |
| OpenBao isolated restore | monthly |
| Kubernetes namespace/Velero restore | monthly |
| GitOps clean-cluster reconstruction | monthly |
| Kafka broker-loss test | monthly |
| RabbitMQ/Redis/Ceph node-loss test | monthly |
| Apicurio restore and compatibility check | monthly |
| Edge/API clean-environment reconstruction | monthly |
| DNS/MinIO logical-corruption exercise | quarterly |
| Full Site A or Site B loss | quarterly, alternating sites |
| End-to-end DR plus failback | at least every six months |

## Required test evidence

Evidence is stored outside Git in CI artifacts, observability, or an approved audit store.

Every exercise records at minimum:

- `component`;
- `test_id`;
- `environment`;
- `started_at` and `finished_at` in UTC;
- expected and measured RPO;
- expected and measured RTO;
- result: `PASS` or `FAIL`;
- deployed commit/version;
- references to logs, metrics, or artifacts;
- corrective issue when the result fails a target.

Evidence must not contain secrets, private keys, bearer tokens, kubeconfigs, or Terraform state.

## Required scenarios

The DR program must eventually demonstrate:

- Kubernetes critical-node loss;
- PostgreSQL primary loss;
- Kafka broker loss;
- RabbitMQ node loss;
- Redis node loss;
- Ceph OSD/node loss;
- authoritative DNS server loss;
- logical DNS zone corruption/deletion;
- MinIO object/version deletion;
- temporary OpenBao unavailability;
- Keycloak unavailability;
- Apicurio Registry loss;
- Harbor loss followed by critical workload rescheduling;
- OpenSearch loss followed by index rebuild;
- Edge/API component loss and alternate-path recovery;
- inter-site WAN loss;
- complete Site A loss;
- complete Site B loss;
- controlled failback to nominal topology.

## Safety requirements

- Use synthetic test data where possible.
- Never inject fake business transactions into production to prove DR.
- All chaos targets must be narrowly scoped.
- Timeouts are mandatory.
- Cleanup/rollback is part of the scenario definition.
- If fencing or quorum state is ambiguous, write promotion must stop.
- A failed or incomplete restore is reported as failure, never as partial success.

## Acceptance rule

A Tier-0 component is not considered DR-ready until there is recent evidence that its documented recovery procedure succeeds within the validated target, or a corrective issue explicitly tracks the gap.