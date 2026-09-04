# WORK HANDOFFS — BUSINESS, VENDORS, EVIDENCE, LAUNCH

Status: `CHATGPT PREPARED`

Work is not a second engineering owner. It receives bounded research, browser, evidence and finished-deliverable tasks. It must return source-referenced outputs to ChatGPT for decisions or program status.

## Global Work prompt

You are supporting the E-COMMERCE delivery program as a business/research/evidence operator. Use the project architecture and business scope as constraints; do not redesign technical architecture. For every external fact, capture the source and date. Separate verified fact, provider claim, assumption, unresolved question and recommendation. Do not mark a technical milestone complete from documentation alone. When a task depends on authenticated portals or contracts, collect what is actually available and clearly report inaccessible fields instead of guessing.

## W1 — Vendor & commercial due diligence

Run early and refresh before M3/M8/M9 if provider data may have changed.

### Scope

- phoenixNAP PREPROD bare-metal availability and provisioning capabilities;
- Hetzner production dedicated hardware/network options matching the certified BOM;
- ClouDNS registrar/DNS features relevant to locks, MFA, DNSSEC and secondary DNS;
- Stripe features/constraints relevant to Payment Element, PaymentIntents, SCA/3DS, authorization/capture and webhooks;
- Qonto PA/e-invoicing integration information relevant to the Billing adapter;
- any approved external dependency whose current terms materially affect deployment.

### Output

Create a dated vendor-readiness report containing for each provider:
- required capability;
- verified offering/current documentation;
- region/location constraints;
- API/automation capability;
- support/SLA or operational dependency information where published/available;
- pricing/cost evidence where accessible;
- contractual/account prerequisites;
- risk/limitation;
- source reference;
- status `CONFIRMED / CONDITIONAL / BLOCKED / NEEDS HUMAN CONTRACT REVIEW`.

Never invent negotiated prices or contractual guarantees.

## W2 — Business & compliance readiness

Run in parallel with M2-M6.

### Business scope to verify operationally

- B2C mono-vendeur;
- France + EU;
- EUR;
- FR + EN;
- guest checkout;
- returns/refunds/customer support path;
- invoice/credit-note and French e-invoicing adapter readiness;
- privacy notice/data minimization/retention operationalization;
- customer-facing policies and support processes;
- payment/fraud operational escalation path.

### Output

Produce a readiness matrix:

| Domain | Requirement | Owner | Evidence/source | Gap | Required before | Status |
|---|---|---|---|---|---|---|

Classify gaps as `BUSINESS`, `LEGAL_REVIEW`, `FINANCE/ACCOUNTING`, `OPERATIONS`, `PRODUCT`, or `TECHNICAL_HANDOFF`.

Do not provide binding legal/accounting advice. Flag items that require qualified review.

## W3 — PREPROD evidence pack

Start when M7 produces evidence and continue through M8.

### Inputs

- signed release manifest/digests;
- exact configuration/version references;
- CI/test artifacts;
- performance/chaos/DR results;
- restore evidence;
- campaign timestamps;
- exceptions/corrective issues.

### Output

For each campaign create a concise evidence index:
- release ID/commit/digest;
- campaign type;
- environment/hardware identity;
- start/end;
- gate list with PASS/FAIL/INCOMPLETE;
- evidence links;
- reused evidence and equivalence justification;
- new/replayed entry gates after reconstruction;
- corrective issue references;
- final campaign conclusion.

Do not copy secrets or raw sensitive runtime logs into a report.

## W4 — Executive GO/NO-GO dossier

Start after M8 campaign 3 reaches a candidate PASS.

### Output

Create a decision pack with:
- business scope included/excluded at launch;
- architecture/release ID;
- certification summary;
- unresolved risks and accepted residual risks;
- provider readiness;
- support/incident ownership;
- rollback and communications readiness;
- privacy/compliance checklist status;
- customer support readiness;
- business KPI baseline/alert thresholds if already approved;
- explicit recommendation `GO / NO-GO / GO WITH CONDITIONS`.

The final production authorization remains governed by release governance; Work supplies the dossier, not the authority.

## W5 — PROD launch operations pack

Prepare during M8, finalize immediately before M9.

Include:
- contact/escalation matrix;
- launch sequence and time windows supplied by release plan;
- support scripts/templates;
- customer-impact communication templates;
- vendor dependency contacts/portals;
- rollback communication template;
- incident status update template;
- post-launch KPI review template;
- first-day/first-week operational review checklist.

## W6 — Post-launch business review

After M9 reaches `PROVEN`, build a review from actual evidence:
- availability and incident summary;
- performance vs target;
- conversion/checkout/payment operational signals where available;
- support/returns/fraud queue observations;
- infrastructure/vendor cost observations;
- corrective opportunities;
- proposed backlog candidates.

Do not convert observations into architecture changes directly; return recommendations to ChatGPT change control.