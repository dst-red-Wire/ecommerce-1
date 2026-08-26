# Disaster Recovery

This directory is the repository source of truth for disaster recovery policy and operational runbooks.

## Scope

The DR program covers the full e-commerce platform, including DNS/GSLB, edge/API, identity, Kubernetes, storage, databases, messaging, registries, observability, and multi-site failover.

Related GitHub tracking:

- EPIC: #2 — Platform Resilience & Disaster Recovery
- Backlog and DR matrix: #10 — Observability, RPO/RTO & recovery testing

## Definitions

- **Tier-0**: component whose loss blocks traffic, critical transactions, identity/trust, or recovery capability.
- **Tier-0 recovery dependency**: component required to rebuild or recover the platform after a disaster.
- **Tier-1**: component whose loss causes major degradation but permits partial continuity or delayed rebuild.
- **RPO**: maximum acceptable data loss measured from the latest actually recoverable point.
- **RTO**: maximum target time to restore the component after disaster declaration.
- **HA target**: local continuity objective. HA does not replace backup, RPO, or RTO.

## Sources of truth

The platform keeps clear ownership of durable state:

- Git: manifests, policies, contracts, dashboards, declarative configuration, runbooks.
- PostgreSQL: transactional domain state where designated as application source of truth.
- Kafka critical topics: durable event streams required for workflows, replay, saga, and outbox recovery.
- MinIO critical buckets: durable object data and immutable backup repositories where configured.
- OpenBao/HSM: secrets and protected key material. Root/decryption keys are never stored with the backups they protect.

## Reconstructible state

The following must not become hidden sources of truth:

- Redis caches and rate-limiting state.
- OpenSearch/CQRS projections.
- ATS and application caches.
- Kubernetes runtime objects that are reproducible from GitOps.

A rebuild path must exist from an authoritative source before a component can be classified as reconstructible.

## Core principles

1. Replication is not backup.
2. A backup is not accepted as operational until a restore has been tested.
3. Tier-0 backups require at least one copy independent of both production sites when applicable.
4. Recovery keys and backup data are kept separate.
5. RPO is measured from a recoverable point, not from a successful cron timestamp.
6. RTO is measured end-to-end during restore/failover tests.
7. DNS/GSLB never triggers an unsafe write promotion before fencing/quorum validation.
8. Destructive DR tests are forbidden on production by default.
9. DR automation must be idempotent, restartable, and fail closed.

## Documents

- [Tier / RPO / RTO matrix](tier-rpo-rto.md)
- [DR testing policy](testing-policy.md)
- [Runbook index](runbooks/index.md)

## Definition of done

The DR program is considered effective only when Tier-0 components have current measured restore/recovery evidence, alerting is operational, runbooks match tested procedures, and full site-loss plus failback scenarios have been demonstrated.