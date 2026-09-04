# EVENT CONTRACT MATRIX V2 — EXACT

Status: `EXACT CONTRACT BOUNDARIES`

All durable domain events use Kafka + Protobuf + versioned compatibility policy. RabbitMQ is reserved for operational jobs and retries that are not authoritative business event streams.

## Topic naming

Default pattern:

`ecommerce.<domain>.<event-name>.v<major>`

Examples:

- `ecommerce.order.order-created.v1`
- `ecommerce.payment.payment-authorized.v1`

The schema registry subject must map deterministically to the topic/schema. Major version changes require explicit compatibility review and migration plan.

## Envelope

Every durable event includes at minimum:

- `event_id`
- `event_type`
- `schema_version`
- `occurred_at_utc`
- `producer`
- `aggregate_type`
- `aggregate_id`
- `correlation_id`
- `causation_id`
- `home_site`
- `trace_id` when available
- payload

No secret, credential, access token or unnecessary PII in events.

## Core event matrix

| Producer | Event | Primary consumers | Idempotency key |
|---|---|---|---|
| product | ProductCreated.v1 | catalog, search, review | event_id |
| product | ProductUpdated.v1 | catalog, search | event_id |
| product | SKUUpdated.v1 | catalog, search, inventory | event_id |
| catalog | CatalogPublished.v1 | search, storefront projections | event_id |
| pricing | PriceRuleChanged.v1 | cart, order cache invalidation/projections | event_id |
| inventory | StockReserved.v1 | order | event_id/reservation_id |
| inventory | StockReleased.v1 | order | event_id/reservation_id |
| inventory | StockAdjusted.v1 | catalog/search projections | event_id |
| cart | CartUpdated.v1 | analytics/notification where approved | event_id |
| order | OrderCreated.v1 | inventory, fraud-risk, notification | event_id/order_id |
| fraud-risk | FraudApproved.v1 | order | event_id/order_id |
| fraud-risk | FraudRejected.v1 | order, notification | event_id/order_id |
| fraud-risk | FraudReviewRequired.v1 | order, notification/admin workflow | event_id/order_id |
| payment | PaymentAuthorized.v1 | order, billing | event_id/payment_id |
| payment | PaymentFailed.v1 | order, notification | event_id/payment_id |
| payment | PaymentCaptured.v1 | order, billing, notification | event_id/payment_id |
| order | OrderConfirmed.v1 | shipping, billing, notification | event_id/order_id |
| order | OrderCancelled.v1 | inventory, payment, notification | event_id/order_id |
| shipping | ShipmentCreated.v1 | tracking, notification | event_id/shipment_id |
| shipping | ShipmentDispatched.v1 | tracking, notification | event_id/shipment_id |
| tracking | TrackingUpdated.v1 | notification, storefront projection | event_id/tracking_id |
| tracking | Delivered.v1 | order, notification, returns eligibility projection | event_id/tracking_id |
| returns | ReturnRequested.v1 | notification, admin workflow | event_id/return_id |
| returns | ReturnApproved.v1 | shipping, notification | event_id/return_id |
| returns | ReturnReceived.v1 | inventory, payment, notification | event_id/return_id |
| returns | RefundRequested.v1 | payment | event_id/return_id |
| payment | RefundCompleted.v1 | returns, billing, notification | event_id/refund_id |
| billing | InvoiceIssued.v1 | notification, accounting adapter | event_id/invoice_id |
| billing | CreditNoteIssued.v1 | notification, accounting adapter | event_id/credit_note_id |
| review | ReviewSubmitted.v1 | moderation/admin | event_id/review_id |
| review | ReviewPublished.v1 | catalog/search projection | event_id/review_id |
| user-profile | ProfileUpdated.v1 | notification/preferences projections only | event_id/profile_id |
| notification | NotificationDelivered.v1 | observability/audit projection | event_id/notification_id |

## Ordering

Ordering is required only within the relevant aggregate key, not globally. Producers use the aggregate identifier as the Kafka message key unless a domain-specific partitioning rule is documented.

## Delivery semantics

- At-least-once delivery is assumed.
- Consumers must be idempotent.
- Producer side uses transactional outbox for business events coupled to database commits.
- Consumer offsets are committed only after durable side effects complete or are safely deduplicated.
- Poison messages go to versioned DLQ/retry flows with bounded retries and operational visibility.

## MirrorMaker2

Inter-site replication preserves topic namespace and headers required for deduplication and origin tracking. `home_site` is carried in the event envelope. Mirror replication never creates multi-writer business authority.

## Compatibility gate

A producer change cannot merge/deploy unless:

1. schema lint passes;
2. backward/forward compatibility policy for the topic is satisfied;
3. affected consumers are identified;
4. contract tests run;
5. breaking major-version migration path is documented when required.
