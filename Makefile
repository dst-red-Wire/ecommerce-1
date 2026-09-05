SHELL := /bin/sh

.PHONY: help ci governance automation lint test security terraform ansible doctor bootstrap-check bootstrap hooks-install

help: ## Show the available checks
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z_-]+:.*## / {printf "%-16s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

ci: governance automation lint test security terraform ansible ## Run every portable CI check

governance: ## Validate canonical architecture contracts
	@./scripts/ci-governance.sh

automation: ## Validate deterministic engineering automation contracts
	@./scripts/ci-automation.sh

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

doctor: ## Report the pinned local toolchain state
	@python3 ./scripts/toolchain-doctor.py --scope full --format text

bootstrap-check: ## Check bootstrap prerequisites without changing the workstation
	@./scripts/bootstrap-toolchain.sh --check

bootstrap: ## Install the pinned user-space Python CLIs with pipx
	@./scripts/bootstrap-toolchain.sh --apply

hooks-install: ## Install repository-owned pre-commit hooks into this worktree
	@./scripts/install-git-hooks.sh
