# DATA OWNERSHIP MATRIX V2 — EXACT

Status: `EXACT`

## Authoritative stores

| Domain | Authoritative data | Store | Rebuildable projections/caches |
|---|---|---|---|
| catalog | category tree, assortment/presentation metadata | `catalog-db` PostgreSQL | OpenSearch/catalog cache |
| product | products, SKUs, attributes, base product facts | `product-db` PostgreSQL | OpenSearch/search projection |
| inventory | stock, reservations, adjustments | `inventory-db` PostgreSQL | Redis availability cache where used |
| cart | persisted cart intent/state | `cart-db` PostgreSQL | Redis hot cart cache |
| pricing | price rules, promotion rules, rule versions | `pricing-db` PostgreSQL | Redis calculation cache |
| tax | tax rules/versioned tax configuration | `tax-db` PostgreSQL or approved versioned config-backed store | calculation cache |
| order | order aggregate, Saga state, immutable checkout snapshot | `order-db` PostgreSQL | CQRS/OpenSearch read model |
| payment | PSP transaction state, auth/capture/refund records | `payment-db` PostgreSQL | operational read model |
| shipping | shipment/order-to-carrier state | `shipping-db` PostgreSQL | carrier/cache projection |
| tracking | tracking timeline normalized from carrier updates | `tracking-db` PostgreSQL | OpenSearch/read projection |
| returns | return/RMA lifecycle | `returns-db` PostgreSQL | admin projection |
| billing | invoices, credit notes, e-invoicing state, immutable object references | `billing-db` PostgreSQL + SeaweedFS object refs | reporting projection |
| fraud-risk | risk decisions, review queue, review decisions | `fraud-db` PostgreSQL | risk feature cache |
| search | none authoritative | OpenSearch only | itself is a projection |
| review | reviews, moderation state | `review-db` PostgreSQL | search/catalog projection |
| user-profile | minimized customer profile/preferences/privacy workflow metadata | `user-profile-db` PostgreSQL | Redis preference cache where justified |
| notification | delivery intent, attempts, status | `notification-db` PostgreSQL | RabbitMQ job transport |

## Platform data ownership

- Keycloak DB owns human IAM realm/user/session-authoritative state required by IAM.
- OpenBao owns secret-management state; Git never contains secret values.
- Harbor owns OCI registry metadata/blobs for published artifacts; Git owns desired configuration and image references/digests.
- SeaweedFS owns S3 object data; PostgreSQL stores references/checksums/metadata when a business domain requires object linkage.
- Kafka owns durable event log state but does not replace the owning service's transactional aggregate authority unless an explicit event-sourced domain ADR states otherwise.
- RabbitMQ transports operational jobs and is not a business source of truth.
- Redis is never the only copy of durable business state.
- OpenSearch is never the only copy of business-authoritative state.

## Cross-domain data rules

1. No SQL joins across domain databases.
2. No foreign keys across service-owned databases.
3. Cross-domain identifiers are opaque references.
4. Data replication into a read model must carry source/version metadata.
5. Deletion/privacy workflows must propagate by explicit contract/event, not ad-hoc DB access.
6. Sensitive data is minimized at source; downstream projections must not copy fields they do not require.
7. Any new durable data set must name exactly one authoritative owner before implementation.
