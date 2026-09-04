# Production readiness and CI/CD gates

Tekton owns CI only. It validates, tests, builds, scans, creates an SBOM,
signs, publishes, and proposes a Git desired-state change. Flux alone owns
deployment and reconciliation. Production is never changed directly by a
Tekton task.

## Execution mapping

| Stage | Mandatory scope | Heavy traffic |
|---|---|---|
| Pull request | lint, unit, API/contract smoke, Gitleaks, Trivy/SAST/IaC, manifest and supply-chain source checks | Forbidden |
| CI main branch | PR scope plus build, image scan, SBOM, provenance, Cosign sign/verify and immutable publication | Forbidden |
| Integration/staging-lite | full integration/API/authorization, DAST, identity/fraud/abuse, resilience, performance, load/stress as scheduled | Authorized and bounded |
| Production promotion | verify every immutable gate artifact and approved Git promotion | No security or load attack against production |

The machine-readable policy is
`tests/production-readiness/gates.json`. Every production gate requires a
complete `GateEvidence` at `artifacts/gates/<gate-id>.json` and a detached
Sigstore bundle at `artifacts/gates/<gate-id>.sigstore.json`. The JSON schema is
`contracts/supply-chain/gate-evidence.schema.json`. A status-only object such
as `{"status":"pass"}` is rejected. Missing cryptographic verification is
reported as `NOT PROVEN`, never as a pass. Generated reports are ignored by Git
and must be retained by the CI artifact store.

## PASS and FAIL rules

- Any CRITICAL finding blocks production.
- Any HIGH finding blocks production unless a named, approved, time-bounded
  exception is attached to the promotion evidence.
- A missing mandatory artifact is a failure, never an implicit pass.
- Tests use synthetic accounts and data in an authorized integration environment.
- Identity and fraud tests pass only when the request is blocked as expected
  and the corresponding audit/detection event is observable.
- Performance passes only when p50, p95, p99, throughput, error rate and
  saturation thresholds all pass for the same test window.
- Supply chain passes only with immutable digest, scan, SBOM, provenance,
  Cosign signature and successful verification.
- Every gate is bound to the same repository, source commit, image digest and
  production environment, includes issuer and expiration, and is verified
  against independently distributed trust material.

## Required evidence

Use JUnit for test outcomes, SARIF for SAST/IaC findings, JSON for policy and
audit assertions, k6 summaries for performance, Trivy reports for
vulnerabilities, CycloneDX or SPDX for SBOM, and Cosign bundles for signatures
and provenance. Evidence must include source revision, image digest,
environment, timestamps and tool versions.

## Identity, fraud and abuse safety

Scenario definitions live under `tests/security/`. They prohibit real users,
real phishing, real payments, third-party targets and production execution.
Account takeover, recovery, MFA, session, token, IDOR/RBAC, coupon, checkout,
payment/refund, webhook, scraping, trusted-header and privacy controls are
covered as staging gates. Execution implementations should be added alongside
the relevant service once its API contract exists.
