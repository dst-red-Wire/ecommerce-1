# SERVICE OWNERSHIP MATRIX V2 — EXACT

Status: `EXACT`

No service may read another service's database directly. Cross-domain access uses versioned REST/gRPC contracts or durable events. `order` owns checkout orchestration; no `checkout` service exists.

| Service | Owns | Authoritative store | Main synchronous dependencies | Core emitted events |
|---|---|---|---|---|
| catalog | category/navigation presentation, product assortment projection | catalog-db + rebuildable OpenSearch projection | product, pricing, inventory | CatalogPublished, CatalogEntryChanged |
| product | SKU/product attributes, base commercial product data | product-db | none required for authority | ProductCreated, ProductUpdated, SKUUpdated |
| inventory | available/reserved stock, reservations | inventory-db | order for reservation correlation only via contract | StockReserved, StockReleased, StockAdjusted, OutOfStock |
| cart | active cart state and persisted cart intent | cart-db; Redis may accelerate only | pricing, inventory, product | CartUpdated, CartExpired |
| pricing | computed prices, promotions/rules/version | pricing-db | product, tax context as contract input | PriceRuleChanged, PriceCalculated |
| tax | tax rules/calculation result/version | tax-db/config | none authoritative | TaxCalculated, TaxRuleChanged |
| order | checkout orchestration, Saga state, immutable order snapshot, order lifecycle | order-db | pricing, tax, inventory, fraud-risk, payment, shipping | OrderCreated, OrderConfirmed, OrderCancelled, OrderFailed |
| payment | PSP authorization/capture/refund state | payment-db | Stripe external PSP; order callback contract | PaymentAuthorized, PaymentCaptured, PaymentFailed, RefundCompleted |
| shipping | shipment creation/options/carrier handoff | shipping-db | order, inventory; external carrier adapters | ShipmentCreated, ShipmentDispatched, DeliveryException |
| tracking | shipment tracking timeline/projection | tracking-db + rebuildable projection | shipping/external carrier feeds | TrackingUpdated, Delivered |
| returns | return request/RMA lifecycle | returns-db | order, shipping, payment, inventory | ReturnRequested, ReturnApproved, ReturnReceived, RefundRequested |
| billing | invoices, credit notes, e-invoicing adapter state | billing-db + immutable document/object refs | order, payment; Qonto PA adapter | InvoiceIssued, CreditNoteIssued, EInvoiceSubmitted |
| fraud-risk | risk assessment and manual review queue/state | fraud-db | order/payment context | FraudApproved, FraudRejected, FraudReviewRequired |
| search | search index/read model only | OpenSearch index; configuration in Git | product/catalog events | SearchIndexUpdated |
| review | customer product reviews/moderation state | review-db | product, user-profile identity reference | ReviewSubmitted, ReviewPublished, ReviewRejected |
| user-profile | minimal customer profile/preferences and privacy state | user-profile-db | Keycloak identity reference only | ProfileUpdated, PrivacyRequestRecorded |
| notification | notification intent/delivery status/templates references | notification-db + RabbitMQ jobs | events from business services; external channels | NotificationQueued, NotificationDelivered, NotificationFailed |

## Ownership constraints

### Product vs Catalog

- `product` owns SKU/attributes/base product facts.
- `catalog` owns navigation/presentation/assortment composition.
- Search indexes are projections, never product/catalog authority.

### Pricing / Tax / Order

- Cart prices are indicative.
- Order requests final calculation from Pricing and Tax.
- Order persists an immutable snapshot of price, discount, tax, total and version identifiers.

### Payment / Billing

- Payment owns PSP money movement state.
- Billing owns invoices/credit notes/e-invoicing artifacts.
- Billing never mutates Payment state directly.

### Shipping / Tracking

- Shipping owns shipment creation and carrier handoff.
- Tracking owns the tracking timeline/read model.

### Returns

- Returns orchestrates RMA/return policy workflow.
- Refund execution remains Payment-owned; stock reintegration remains Inventory-owned.

### User identity

- Keycloak owns authentication identity/credentials.
- `user-profile` owns only minimized business profile data.
- privileged workforce identities remain in the workforce IAM realm, not user-profile.

## Contract rule

Every synchronous dependency listed above must have an OpenAPI or gRPC contract and timeout/retry/idempotency semantics. Every emitted durable event must have a versioned Protobuf schema and compatibility test before producer/consumer deployment.
