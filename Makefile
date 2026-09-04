include versions.mk

SHELL := /bin/sh
ANSIBLE_TOOLING_VENV ?= $(CURDIR)/.venv

.PHONY: help ci lint test security terraform ansible test-api test-integration \
	test-security test-supply-chain test-identity test-fraud test-performance \
	test-load validate-production-readiness test-production-readiness \
	test-tekton-contracts test-tekton-admission test-promotion-proof \
	test-git-promotion test-rendered-images staging-preflight staging-bootstrap \
	staging-status staging-gitops-validate test-management-foundation \
	ansible-lint-management ansible-lint-terraform-state test-terraform-pg-blockers \
	governance install-gitleaks install-trivy install-opa

help: ## Show the available checks
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z_-]+:.*## / {printf "%-16s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

ci: lint test test-api governance security test-supply-chain terraform ansible ## Run every fast PR check

lint: ## Lint repository sources that are present
	@./scripts/ci-lint.sh

test: ## Run test suites that are present
	@./scripts/ci-test.sh

security: ## Scan the working tree for secrets
	@./scripts/ci-security.sh

governance: ## Validate governance, documentation and Policy as Code
	@./scripts/ci-governance.sh

install-gitleaks: ## Install the pinned Gitleaks release in the user environment
	@./scripts/install-gitleaks.sh

install-trivy: ## Install the pinned Trivy release in the user environment
	@./scripts/install-trivy.sh

install-opa: ## Install the pinned OPA release in the user environment
	@./scripts/install-opa.sh

terraform: ## Validate Terraform/OpenTofu sources when present
	@./scripts/ci-terraform.sh

ansible: ## Validate Ansible sources when present
	@ANSIBLE_TOOLING_VENV="$(ANSIBLE_TOOLING_VENV)" ./scripts/ci-ansible.sh

ansible-lint-management: ## Validate management Ansible with pinned project tooling
	@ANSIBLE_TOOLING_VENV="$(ANSIBLE_TOOLING_VENV)" ./scripts/ci-ansible.sh management

ansible-lint-terraform-state: ## Validate independent Terraform state Ansible
	@ANSIBLE_TOOLING_VENV="$(ANSIBLE_TOOLING_VENV)" ./scripts/ci-ansible.sh terraform-state

test-api: ## Validate API contracts and API tests when present
	@./scripts/ci-api.sh

test-integration: ## Run integration test entry points when present
	@./scripts/ci-integration.sh

test-security: security ## Run secret, vulnerability, and IaC security checks

test-supply-chain: ## Reject mutable images and validate supply-chain sources
	@./scripts/ci-supply-chain.sh

test-tekton-contracts: ## Resolve Pipeline, Task, workspace, result, and identity contracts
	@python3 scripts/validate-tekton-contracts.py --self-test

test-tekton-admission: ## Exercise fail-closed PipelineRun admission fixtures
	@python3 scripts/validate-tekton-admission.py --fixture-suite tests/supply-chain/admission-cases.json

test-promotion-proof: ## Exercise PromotionProof schema, time, hash, and TOCTOU rejection cases
	@./scripts/test-promotion-proof.sh

test-git-promotion: ## Exercise optimistic locking and proposal branch ancestry checks
	@./scripts/test-git-promotion.sh

test-rendered-images: ## Exercise rendered workload image digest validation
	@./scripts/test-gitops-image-binding.sh

test-management-foundation: ## Validate management, PostgreSQL backend and archive contracts locally
	@ANSIBLE_TOOLING_VENV="$(ANSIBLE_TOOLING_VENV)" ./scripts/test-management-foundation.sh

test-terraform-pg-blockers: ## Exercise the six PostgreSQL backend blockers offline
	@./scripts/test-terraform-pg-blockers.sh

test-identity: ## Validate synthetic identity and account-abuse scenarios
	@./scripts/ci-identity.sh

test-fraud: ## Validate synthetic e-commerce fraud and API-abuse scenarios
	@./scripts/ci-fraud.sh

test-performance: ## Validate k6 scenarios without generating traffic
	@./scripts/ci-performance.sh

test-load: ## Run authorized k6 load tests (requires RUN_LOAD_TESTS=1)
	@./scripts/ci-load.sh

validate-production-readiness: ## Validate the production gate policy only
	@PRODUCTION_GATE_MODE=validate ./scripts/ci-production-readiness.sh

test-production-readiness: ## Enforce all production promotion artifacts
	@PRODUCTION_GATE_MODE=enforce ./scripts/ci-production-readiness.sh

staging-preflight: ## Validate staging playbooks, Terraform and remote prerequisites without mutation
	@./scripts/staging-preflight.sh

staging-bootstrap: ## Bootstrap the existing Hetzner staging server in ordered phases
	@./scripts/staging-bootstrap.sh

staging-status: ## Collect non-mutating staging health, resource and API measurements
	@./scripts/staging-status.sh

staging-gitops-validate: ## Server-side dry-run Flux, Tekton and Chains sources on staging
	@./scripts/staging-gitops-validate.sh
