include versions.mk

SHELL := /bin/sh

.PHONY: help ci lint test security terraform ansible test-api test-integration \
	test-security test-supply-chain test-identity test-fraud test-performance \
	test-load validate-production-readiness test-production-readiness \
	staging-preflight staging-bootstrap staging-status

help: ## Show the available checks
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z_-]+:.*## / {printf "%-16s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

ci: lint test test-api security test-supply-chain terraform ansible ## Run every fast PR check

lint: ## Lint repository sources that are present
	@./scripts/ci-lint.sh

test: ## Run test suites that are present
	@./scripts/ci-test.sh

security: ## Scan the working tree for secrets
	@./scripts/ci-security.sh

terraform: ## Validate Terraform/OpenTofu sources when present
	@./scripts/ci-terraform.sh

ansible: ## Validate Ansible sources when present
	@./scripts/ci-ansible.sh

test-api: ## Validate API contracts and API tests when present
	@./scripts/ci-api.sh

test-integration: ## Run integration test entry points when present
	@./scripts/ci-integration.sh

test-security: security ## Run secret, vulnerability, and IaC security checks

test-supply-chain: ## Reject mutable images and validate supply-chain sources
	@./scripts/ci-supply-chain.sh

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
