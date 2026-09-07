# Security policy

## Reporting a vulnerability

Please report vulnerabilities responsibly. Do not publish exploit details, credentials, kubeconfigs, Terraform state, private keys, or other sensitive material in a public Issue.

This repository does not currently publish a private reporting address or channel. Until one is established, open a minimal Issue that asks a maintainer for a private reporting path and includes no sensitive details.

## Sensitive material

Secrets and generated credentials must never be committed. This includes `.env` files, tokens, cloud credentials, Kubernetes configuration, Terraform state, private keys, and scanner artefacts containing sensitive data.

The repository security controls and expected validation are defined by [AGENTS.md](AGENTS.md), [the CI topology contract](config/contracts/ci-topology.yaml), and [the review policy](config/contracts/review-policy.yaml).
