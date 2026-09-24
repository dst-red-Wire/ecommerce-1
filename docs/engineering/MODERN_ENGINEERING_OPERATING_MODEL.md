# Modern Engineering Operating Model

`architecture.lock.yaml` remains the repository's single architecture authority. This document explains how its existing Quality Cloud Engineering model is operated; it does not define a second framework or duplicate machine policy.

## Operating loop

The nine QCE sectors remain closed and unchanged in count. `measuring_engineering` owns measurement mechanisms and produces reproducible evidence. The transverse `data_driven` control consumes that evidence through the governed loop: observe, measure, detect, form a hypothesis, run a small experiment, measure the outcome, keep/rollback/improve, and standardise.

`python scripts/repoctl.py qce-status --json` derives sector status from the architecture, roadmap capability links, the qualification gate registry, optional GitHub metadata snapshots, and fresh exact-SHA evidence. The existing `roadmap-sync` workflow refreshes the non-authoritative issue/PR relation snapshot. Labels such as `qce:continuous-testing` express relationships only. They never prove an outcome. `PROVEN` cannot be entered manually; a contract is `CONTRACTED`, an existing capability can be `IMPLEMENTED`, and only fresh matching evidence can produce `PROVEN`.

## Security and CVE decisions

`config/contracts/security-scan-policy.yaml` is the only vulnerability/scanner policy authority. It defines accepted CVE, GO, GHSA, and OSV identifiers; alias normalization; multi-scanner observation preservation and deduplication; CVSS normalization; fix and exact Go symbol-reachability handling; KEV/EPSS risk decisions through CVE identifiers or aliases; remediation targets; scan scopes; expiring exact-scope exceptions; and PASS/BLOCK evidence. A non-CVE advisory without a CVE alias records KEV and EPSS as not applicable, but it never receives an automatic PASS: unknown, reachable, or otherwise unresolved release risk remains blocking unless exact symbol-level evidence proves it unreachable.

Policy version 3 corrects a governance inconsistency in the earlier evaluator: the contract selected `govulncheck` as the canonical Go vulnerability scanner while the normalized finding validator accepted only CVE identifiers. Scanner-native advisory identifiers are now modeled generically; no individual advisory is hard-coded or filtered.

KEV and EPSS are refreshed explicitly with `make security-datasets-sync`. The command records official source URLs, snapshot time, checksum, and provenance below `.context/security-datasets/`. Qualification never calls those volatile endpoints. Missing, corrupt, or stale datasets block decisions that need enrichment. An absence of findings records `NOT_REQUIRED_NO_FINDINGS`; it is not represented as a verified dataset.

Exceptions are JSON records below `.context/security-exceptions/`, are bound to the finding and artifact, and expire automatically. Their approval uses the repository's existing exact-SHA owner-authorization syntax. `ignore: true` is not an exception.

## Metrics, SLOs, and product outcomes

`config/contracts/engineering-metrics-policy.yaml` is the sole formula and missing-data authority for DORA, reliability, quality, security, DevEx, cost/value, product-outcome, and AI-effectiveness metrics. Missing runtime data is `MISSING`, `CONTRACTED`, or `PARTIAL`; it is never invented. Individual productivity proxies such as lines of code, commit counts, ticket counts, online hours, or prompt counts are forbidden.

`config/contracts/service-slo.yaml` owns the SLI → SLO → error budget → burn rate → release-risk chain. M1 establishes the contract, M4 implements collection and decisions, and M5 supplies runtime proof. Until telemetry exists, the policy cannot claim healthy budgets or block production based on fabricated measurements.

## Golden Paths and Developer Hub

The Golden Path contract covers new services, APIs, databases, events/topics, secrets, workloads, environments, SLO/dashboard changes, and dependencies. These paths are safe, secure, observable, versioned, reproducible, policy-compliant, and Git/PR governed.

Backstage remains the planned Developer Hub for M4. Its current state is `CONTRACTED`, not deployed or proven. It may expose catalog, ownership, templates, documentation, QCE/SLO/security/deployment state, dependencies, and platform requests. Mutations remain branch → commit → PR → review → qualification → GitOps; the existing Backstage PR contract forbids direct main writes, approval, merge, direct apply, deployment, and promotion.

Kratix OSS is the contracted platform-request orchestrator behind those Golden Paths. Fleet installs its exact-commit, exact-digest Kustomize overlay; Helm is the governed Promise/chart package format. Kratix writes generated desired state to a dedicated Gitea `GitStateStore`, while Rancher Fleet remains the only GitOps/CD authority. Separate Fleet readers map generated paths to RKE2 LAB, PREPROD, and PROD cluster labels; VirtualBox is the LAB example only, and PROD-A/PROD-B remain separate certified sites. OpenBao/ESO supplies separate least-privilege writer and reader identities. The upstream quick-start's Flux and bundled object-store components are never installed.

The initial exact upstream image is recorded for provenance but the Fleet bundle is paused: the current CVE decision blocks `CVE-2026-93990` (`libexpat 2.8.4-r0`, fixed in `2.8.5-r0`). Activation requires an exact replacement digest, a fresh policy PASS, and a reviewed unpause change; no automatic vulnerability exception is permitted.

## AI-native context and experiments

`config/context/router.yaml` bounds agent context by task and authority. Access is read-only and least-privilege by default; secret values, private keys, production credentials, unconstrained environment dumps, unknown contract references, unsafe paths, and budget expansion are rejected or redacted.

AI remains an assistant with required human accountability. It cannot become an authoritative gate, bypass required gates, approve or merge its own change, or deploy directly. Effectiveness is measured by verified outcome changes—cycle time, review/rework, defects, qualification failures, human verification effort, acceptance/rejection, and rollback—not prompt volume.

Experiments use the schema in the engineering metrics policy and the `repoctl experiment` interface. Every experiment binds a baseline, hypothesis, exact change SHA, metric and direction, measurement window, result, decision, and evidence. The output stays below `.context/experiments/`; only a measured decision can be standardised.
