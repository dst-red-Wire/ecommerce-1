# SERVICE OWNERSHIP MATRIX V2 — EXACT

Status: `EXACT`

No service may read another service's database directly. Cross-domain access uses versioned REST/gRPC contracts or durable events. `checkout`, `order`, `payment` and `fulfillment` are autonomous bounded contexts with separate persistence and lifecycle ownership.

| Service | Owns | Authoritative store | Outbound synchronous dependencies | Event/context relationships | Durable events emitted |
|---|---|---|---|---|---|
| catalog | category/navigation presentation, product assortment projection | catalog-db + rebuildable OpenSearch projection | product, pricing, inventory | consumes product/inventory/review events | CatalogPublished, CatalogEntryChanged |
| product | SKU/product attributes, base commercial product data | product-db | none | none | ProductCreated, ProductUpdated, SKUUpdated |
| inventory | available/reserved stock, reservations | inventory-db | none | consumes order/return events; reservation correlation is received through contracts | StockReserved, StockReleased, StockAdjusted, OutOfStock |
| cart | active cart state and persisted cart intent | cart-db; Redis may accelerate only | pricing, inventory, product | consumes price-rule changes | CartUpdated, CartExpired |
| checkout | checkout session, final validation and checkout orchestration state | checkout-db | cart, pricing, tax, inventory, fraud-risk, shipping, order | consumes cart expiry, pricing/tax, reservation and fraud-decision events | none |
| pricing | computed prices, promotions/rules/version | pricing-db | product | tax context is request input, not an outbound call | PriceRuleChanged, PriceCalculated |
| tax | tax rules/calculation result/version | tax-db/config | none | calculation context is received from callers | TaxCalculated, TaxRuleChanged |
| order | durable order aggregate, immutable commercial snapshot, order lifecycle | order-db | none | consumes payment and fulfillment outcome events | OrderCreated, OrderConfirmed, OrderCancelled, OrderFailed |
| payment | PSP authorization/capture/refund state | payment-db | stripe | order callback/correlation is inbound; consumes order/return events | PaymentAuthorized, PaymentCaptured, PaymentFailed, RefundCompleted |
| fulfillment | fulfillment order, allocation, pick/pack and execution lifecycle | fulfillment-db | inventory, shipping | consumes confirmed/cancelled orders and physical delivery outcomes | FulfillmentStarted, FulfillmentCompleted, FulfillmentFailed |
| shipping | shipment creation/options/carrier handoff | shipping-db | carrier-adapters | consumes return events and inbound fulfillment requests | ShipmentCreated, ShipmentDispatched, DeliveryException |
| tracking | shipment tracking timeline/projection | tracking-db + rebuildable projection | shipping | consumes shipment events and inbound carrier updates | TrackingUpdated, Delivered |
| returns | return request/RMA lifecycle | returns-db | order, shipping | inventory/payment actions are event-driven; consumes delivery/refund events | ReturnRequested, ReturnApproved, ReturnReceived, RefundRequested |
| billing | invoices, credit notes, e-invoicing adapter state | billing-db + immutable document/object refs | order, payment, qonto-pa | consumes order/payment/refund events | InvoiceIssued, CreditNoteIssued, EInvoiceSubmitted |
| fraud-risk | risk assessment and manual review queue/state | fraud-db | none | order/payment context is received or event-driven | FraudApproved, FraudRejected, FraudReviewRequired |
| search | search index/read model only | OpenSearch index; configuration in Git | none | projection consumes product/catalog/inventory/review events | SearchIndexUpdated |
| review | customer product reviews/moderation state | review-db | product, user-profile | moderation is internal; consumes product events | ReviewSubmitted, ReviewPublished, ReviewRejected |
| user-profile | minimal customer profile/preferences and privacy state | user-profile-db | keycloak-reference | identity reference only; no Keycloak data ownership | ProfileUpdated, PrivacyRequestRecorded |
| notification | notification intent/delivery status/templates references | notification-db + RabbitMQ jobs | none | consumes business events; channel delivery is an operational adapter/job | NotificationQueued, NotificationDelivered, NotificationFailed |

## Ownership constraints

### Product vs Catalog

- `product` owns SKU/attributes/base product facts.
- `catalog` owns navigation/presentation/assortment composition.
- Search indexes are projections, never product/catalog authority.

### Pricing / Tax / Checkout / Order

- Cart prices are indicative.
- Checkout requests the final Pricing and Tax calculation, validates stock, fraud/risk and delivery context, then owns the checkout workflow until order creation.
- Order accepts validated checkout input and persists an immutable snapshot of price, discount, tax, total, delivery selection and version identifiers.
- Checkout state never becomes the source of truth for a confirmed order.

### Payment / Billing

- Payment owns PSP money movement state.
- Billing owns invoices/credit notes/e-invoicing artifacts.
- Billing never mutates Payment state directly.

### Fulfillment / Shipping / Tracking

- Fulfillment owns allocation, pick/pack and physical execution orchestration after order confirmation.
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

`sync_dependencies` means only a service or external system to which the row service initiates a synchronous REST/gRPC/API call during business operation. Event producers/consumers, inbound request context, projections, and correlations initiated by another service are not synchronous dependencies. The machine-exact list is `config/contracts/service-ownership.yaml`.

Every outbound synchronous dependency listed above must have an OpenAPI or gRPC contract and timeout/retry/idempotency semantics. Every emitted durable event must have a versioned Protobuf schema and compatibility test before producer/consumer deployment.
