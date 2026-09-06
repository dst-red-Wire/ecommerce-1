SHELL := /bin/sh

.PHONY: help ci ci-global governance contracts shell lint test security terraform ansible

help: ## Show the available checks
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z_-]+:.*## / {printf "%-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

ci: governance contracts lint test security terraform ansible ## Run every portable repository CI check

ci-global: governance contracts security shell ## Run global gates used by the Tekton global pipeline

governance: ## Validate canonical architecture and CI authority contracts
	@./scripts/ci-governance.sh

contracts: ## Validate registered OpenAPI 3.1 contracts
	@./scripts/ci-contracts.sh

shell: ## ShellCheck repository-owned shell automation
	@./scripts/ci-shell.sh

lint: shell ## Lint Go and frontend sources with their declared toolchains
	@./scripts/ci-lint.sh

test: ## Run repository, Go and frontend test suites
	@./scripts/ci-test.sh

security: ## Scan the working tree for secrets
	@./scripts/ci-security.sh

terraform: ## Validate Terraform/OpenTofu sources when present
	@./scripts/ci-terraform.sh

ansible: ## Validate Ansible sources when present
	@./scripts/ci-ansible.sh

.PHONY: affected frontend-check frontend-storefront frontend-admin service-check

affected: ## Classify affected CI components; use BASE=<sha> [HEAD=<sha>]
	@BASE="$(BASE)" HEAD="$(HEAD)" ./scripts/ci-affected.sh

frontend-check: ## Run the complete Storefront + Admin frontend gate
	@./scripts/ci-frontend.sh check all

frontend-storefront: ## Run the complete Storefront gate
	@./scripts/ci-frontend.sh check storefront

frontend-admin: ## Run the complete Admin gate
	@./scripts/ci-frontend.sh check admin

service-check: ## Run the generic Go service gate; use SERVICE=product
	@SERVICE="$(SERVICE)" ./scripts/ci-service.sh

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

.PHONY: site

site: ## Install pinned frontend dependencies and run Storefront + Admin locally
	@$(MAKE) -C frontend site

.PHONY: product-check product-run

product-check: ## Validate Product through the generic Go service gate
	@SERVICE=product ./scripts/ci-service.sh

product-run: ## Run the local Product REST runtime on PRODUCT_HTTP_ADDR (default :8080)
	@./scripts/ensure-go-toolchain.sh && PATH="$$HOME/.local/bin:$$PATH" go run ./services/product/cmd/product-api
