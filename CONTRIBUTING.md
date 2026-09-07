# Contributing

Work repository-first: read the relevant machine-readable contracts and `AGENTS.md` before changing a component. Use a dedicated feature branch and keep each pull request small, focused, and reviewable.

Before requesting review:

- run `make verify-change BASE=origin/main HEAD=WORKTREE` when the supported local toolchain is available;
- add or update focused tests and preserve rollback/evidence expectations;
- never commit secrets, credentials, Terraform state, kubeconfigs, or generated sensitive artefacts;
- do not add repository Shell automation—use Ansible for repeatable state reconciliation and `scripts/repoctl.py` or native tools for stateless work.

Tekton is the CI authority. Rancher Fleet is the GitOps/CD authority, and Argo Rollouts owns progressive delivery. A pull request requires the applicable deterministic evidence and human review; automation never approves, merges, bypasses protection, or mutates infrastructure.

The canonical review and control-plane rules are in [AGENTS.md](AGENTS.md), [ci-topology.yaml](config/contracts/ci-topology.yaml), and [review-policy.yaml](config/contracts/review-policy.yaml).
