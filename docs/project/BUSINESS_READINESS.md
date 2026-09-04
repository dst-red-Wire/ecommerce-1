# BUSINESS READINESS — E-COMMERCE

Status: `CHATGPT PM BASELINE`

This file defines non-code readiness gates so engineering can progress without discovering launch blockers late.

## Business model baseline

- B2C.
- Mono-vendeur.
- France + EU target scope.
- EUR.
- FR + EN.
- Guest checkout.
- Stripe payment flow with SCA/3DS support.
- Billing separate from Payment.
- Returns/refunds supported.
- Fraud/Risk includes manual review path.
- Qonto PA integration boundary in Billing for French e-invoicing readiness.

## Readiness domains

| Domain | Required output | Primary execution surface | Required by |
|---|---|---|---|
| Provider accounts/contracts | confirmed accounts, regions, API access, billing contacts, blockers | Work | M3/M8 |
| Infrastructure budget | approved or documented cost envelope for JIT PREPROD and PROD | Business owner + Work evidence, ChatGPT tracking | before real M3 provisioning / M9 |
| Payment operations | Stripe account/config readiness, webhook ownership, refund/capture operations | Work + Codex implementation | M6/M9 |
| E-invoicing/accounting | Qonto PA integration readiness and accounting review items | Work | M6/M9 |
| Legal/privacy | notices, terms, cookie/tracking approach if applicable, GDPR operational matrix, processor/vendor inventory | Work + qualified human review where required | M9 |
| Customer support | support channels, escalation, returns/refund handling, incident comms | Work | M9 |
| Fraud operations | review owner, queue handling, escalation and validated response SLA | Work + business owner | M6/M9 |
| Catalog/content | initial catalog ingestion/quality process, media ownership, localization flow | Work/business | M6/M9 |
| Shipping/returns | carrier/service assumptions, tracking/returns operational process | Work/business | M6/M9 |
| Launch KPI pack | technical + business KPIs, baseline/thresholds, first-week review | ChatGPT + Work | M8/M9 |
| Incident ownership | P0/P1 contacts, vendor escalation, business communications | Work | M9 |

## Mandatory business gates

### Gate B1 — Build scope stable
Required before M5:
- business model assumptions unchanged or change-controlled;
- primary customer journeys enumerated;
- payment/refund/returns/fraud ownership identified;
- localization scope fixed for launch.

### Gate B2 — Operational model ready
Required before M7 exit:
- support/refund/fraud operational owners named;
- provider accounts needed for certification accessible;
- legal/privacy/accounting review gaps explicitly tracked;
- launch exclusions documented.

### Gate B3 — Commercial launch ready
Required before M9:
- infrastructure/provider commercial readiness confirmed;
- payment production readiness confirmed;
- customer-facing policy/support materials ready;
- e-invoicing/accounting launch path reviewed;
- launch KPI pack approved;
- escalation matrix complete;
- no unresolved launch-critical `BLOCKED` item.

## KPI categories to prepare before launch

Technical:
- availability/SLO compliance;
- p95/p99 latency;
- error rate;
- checkout/payment failure rate;
- Kafka/RabbitMQ backlog health;
- restore/failover readiness;
- infrastructure saturation.

Business/operations:
- checkout completion/conversion where analytics are approved;
- payment authorization/capture failure rate;
- fraud review volume/age;
- refund/return queue age;
- customer support contact/incident volume;
- shipping/tracking exception rate;
- invoice generation failure rate;
- infrastructure/provider spend versus approved envelope.

Exact numeric business targets are not invented here; they must be set from business objectives and early measurements before M9.

## Blocking rule

A missing engineering feature belongs to Codex. A missing external fact/account/contract belongs to Work/business owner. A structural business or architecture conflict returns to ChatGPT change control. None may be silently transferred to another role.