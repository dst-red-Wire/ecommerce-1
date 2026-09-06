SHELL := /bin/sh

.PHONY: help ci governance lint test security terraform ansible

help: ## Show the available checks
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z_-]+:.*## / {printf "%-16s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

ci: governance lint test security terraform ansible ## Run every portable CI check

governance: ## Validate canonical architecture contracts
	@./scripts/ci-governance.sh

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

.PHONY: workstation-doctor workstation-bootstrap git-sync publish

workstation-doctor: ## Audit Windows/WSL/Docker/Git/tooling state
	@./scripts/doctor-workstation.sh

workstation-bootstrap: ## Reconcile the developer workstation automatically
	@./scripts/bootstrap-workstation.sh

git-sync: ## Fetch/prune and fast-forward the current branch
	@./scripts/git-sync.sh

publish: ## Validate, commit and push the current branch (never force; never direct-push main)
	@./scripts/git-publish.sh
.PHONY: context-tools context diff-context failure-context

context-tools: ## Install/verify token-efficient local context tooling
	@./scripts/bootstrap-context-tools.sh

context: ## Build a bounded contract-routed context pack; use TASK="..."
	@./scripts/context-pack.sh "$(TASK)"

diff-context: ## Build a compact diff-only context pack
	@./scripts/diff-context.sh

failure-context: ## Run one gate and retain only actionable failure context; use GATE=lint
	@./scripts/failure-context.sh "$(GATE)"

.PHONY: deliver

deliver: ## Validate, publish the current feature branch and create/update its GitHub PR
	@TITLE="$(TITLE)" MSG="$(MSG)" BASE="$(BASE)" ./scripts/git-deliver.sh
