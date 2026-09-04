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

## Active event matrix

This is the complete active durable-event catalogue. `config/contracts/event-contracts.yaml` is the machine-canonical source; this table is its review-oriented representation and must match it exactly. `none` means that no cross-service consumer is currently declared, not that the event is omitted from the contract.

| Producer | Event | Primary consumers | Idempotency key |
|---|---|---|---|
| product | ProductCreated.v1 | catalog, search, review | event_id |
| product | ProductUpdated.v1 | catalog, search | event_id |
| product | SKUUpdated.v1 | catalog, search, inventory | event_id |
| catalog | CatalogPublished.v1 | search | event_id |
| catalog | CatalogEntryChanged.v1 | search | event_id |
| pricing | PriceRuleChanged.v1 | cart, order | event_id |
| pricing | PriceCalculated.v1 | none | event_id/calculation_id |
| inventory | StockReserved.v1 | order | event_id/reservation_id |
| inventory | StockReleased.v1 | order | event_id/reservation_id |
| inventory | StockAdjusted.v1 | catalog, search | event_id |
| inventory | OutOfStock.v1 | catalog, search, notification | event_id/sku_id |
| cart | CartUpdated.v1 | none | event_id/cart_id |
| cart | CartExpired.v1 | notification | event_id/cart_id |
| tax | TaxCalculated.v1 | none | event_id/calculation_id |
| tax | TaxRuleChanged.v1 | pricing, order | event_id |
| order | OrderCreated.v1 | inventory, fraud-risk, notification | event_id/order_id |
| fraud-risk | FraudApproved.v1 | order | event_id/order_id |
| fraud-risk | FraudRejected.v1 | order, notification | event_id/order_id |
| fraud-risk | FraudReviewRequired.v1 | order, notification | event_id/order_id |
| search | SearchIndexUpdated.v1 | none | event_id |
| payment | PaymentAuthorized.v1 | order, billing | event_id/payment_id |
| payment | PaymentFailed.v1 | order, notification | event_id/payment_id |
| payment | PaymentCaptured.v1 | order, billing, notification | event_id/payment_id |
| order | OrderConfirmed.v1 | shipping, billing, notification | event_id/order_id |
| order | OrderCancelled.v1 | inventory, payment, notification | event_id/order_id |
| order | OrderFailed.v1 | notification | event_id/order_id |
| shipping | ShipmentCreated.v1 | tracking, notification | event_id/shipment_id |
| shipping | ShipmentDispatched.v1 | tracking, notification | event_id/shipment_id |
| shipping | DeliveryException.v1 | order, notification | event_id/shipment_id |
| tracking | TrackingUpdated.v1 | notification | event_id/tracking_id |
| tracking | Delivered.v1 | order, notification, returns | event_id/tracking_id |
| returns | ReturnRequested.v1 | notification | event_id/return_id |
| returns | ReturnApproved.v1 | shipping, notification | event_id/return_id |
| returns | ReturnReceived.v1 | inventory, payment, notification | event_id/return_id |
| returns | RefundRequested.v1 | payment | event_id/return_id |
| payment | RefundCompleted.v1 | returns, billing, notification | event_id/refund_id |
| billing | InvoiceIssued.v1 | notification | event_id/invoice_id |
| billing | CreditNoteIssued.v1 | notification | event_id/credit_note_id |
| billing | EInvoiceSubmitted.v1 | notification | event_id/invoice_id |
| review | ReviewSubmitted.v1 | none | event_id/review_id |
| review | ReviewPublished.v1 | catalog, search | event_id/review_id |
| review | ReviewRejected.v1 | notification | event_id/review_id |
| user-profile | ProfileUpdated.v1 | notification | event_id/profile_id |
| user-profile | PrivacyRequestRecorded.v1 | notification | event_id/request_id |
| notification | NotificationQueued.v1 | none | event_id/notification_id |
| notification | NotificationDelivered.v1 | none | event_id/notification_id |
| notification | NotificationFailed.v1 | none | event_id/notification_id |

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
