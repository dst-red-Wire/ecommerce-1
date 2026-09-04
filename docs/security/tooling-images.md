# Immutable tooling image inventory

All Tekton Task and legacy Woodpecker helper images are referenced by the
registry-returned manifest-list digest, not by a mutable tag. The readable tags
remain YAML comments only.

The digests for BuildKit `v0.32.2-rootless`, yq `4.53.3`, Alpine Git `2.49.1`,
Go `1.24-alpine`, Gitleaks `v8.30.1`, Trivy `0.74.0`, Syft `v1.51.0`, Cosign
`v3.0.2`, Terraform `1.11` and the disabled legacy ansible-lint image were
resolved on 2026-08-19 from the unauthenticated Docker Hub/GHCR Distribution
API `Docker-Content-Digest` header. No digest was invented.

The Sourcemeta JSON Schema CLI `v15.6.3` manifest-list digest was resolved from
the GHCR Distribution API during this corrective pass. It applies Draft
2020-12 schemas to the frozen PromotionProof and DeliveryEvidence bytes.

Registry resolution proves tag-to-manifest identity at that time; it does not
prove image safety. Vulnerability/signature policy and actual pulls remain
runtime gates. The legacy Woodpecker file is manual-only and cannot issue
`GateEvidence` or `PromotionProof`.
