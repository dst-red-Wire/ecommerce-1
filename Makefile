PYTHON := python3
MANAGED_BIN := $(HOME)/.local/bin
ANSIBLE_CONFIG := $(CURDIR)/platform/ansible/ansible.cfg
ANSIBLE_COLLECTIONS_PATH := $(CURDIR)/.ansible/collections
export ANSIBLE_CONFIG
export ANSIBLE_COLLECTIONS_PATH
ANSIBLE_LOCAL := ansible-playbook -i localhost, -c local platform/ansible/developer.yml -e repo_root=$(CURDIR)

.PHONY: help bootstrap env-check ci ci-full ci-global governance runtime-efficiency contracts automation lint format format-check test security terraform ansible system

bootstrap: ## Reconcile capabilities independently in dependency order
	@$(PYTHON) scripts/capability_bootstrap.py bootstrap

env-check: ## Audit capabilities without changing the workstation
	@$(PYTHON) scripts/capability_bootstrap.py env-check

help: ## Show the available checks
	@$(PYTHON) scripts/repoctl.py --help

ci: ## Run global + affected repository CI and cache promotable worktree evidence
	@$(PYTHON) scripts/repoctl.py verify-change --base "$${BASE:-origin/main}" --head WORKTREE

ci-full: governance contracts automation lint test security terraform ansible ## Run exhaustive portable repository CI checks

ci-global: governance contracts automation security ## Run global gates used by Tekton

governance: runtime-efficiency ## Validate canonical architecture and CI authority contracts
	@$(PYTHON) scripts/repoctl.py governance

runtime-efficiency: ## Validate measured resource, autoscaling, image and runtime efficiency policy
	@$(PYTHON) scripts/repoctl.py runtime-efficiency

contracts: ## Validate OpenAPI and cross-registry contracts; BASE enables compatibility checks
	@$(PYTHON) scripts/repoctl.py contracts $(if $(BASE),--base $(BASE),) $(if $(HEAD),--head $(HEAD),)

automation: ## Enforce Ansible-first and zero repository Shell scripts
	@$(PYTHON) scripts/repoctl.py automation-policy

lint: automation ## Lint Go, Python and frontend sources with declared toolchains
	@$(PYTHON) scripts/repoctl.py lint

format format-check: export PATH := $(MANAGED_BIN):$(PATH)

format: ## Format Python and frontend sources with Ruff/Oxfmt
	@ruff format scripts tests
	@oxfmt --write frontend/apps frontend/packages frontend/e2e

format-check: ## Check Ruff/Oxfmt formatting without mutation
	@ruff format --check scripts tests
	@oxfmt --check frontend/apps frontend/packages frontend/e2e

test: ## Run repository, Go and frontend test suites
	@$(PYTHON) scripts/repoctl.py test

system: ## Run cross-system repository tests without replaying component suites
	@$(PYTHON) scripts/repoctl.py system

security: ## Scan working tree for secrets
	@$(PYTHON) scripts/repoctl.py security

terraform: ## Validate Terraform/OpenTofu sources when present
	@$(PYTHON) scripts/repoctl.py terraform

ansible: ## Validate Ansible sources and local developer playbook syntax
	@$(PYTHON) scripts/repoctl.py ansible

.PHONY: mgmt-runtime-inventory

mgmt-runtime-inventory: ## Build non-secret bootstrap transport overlay from Terraform MGMT outputs
	@$(PYTHON) scripts/mgmt_runtime_inventory.py --output "$${OUTPUT:-.context/runtime/mgmt-ansible-transport.json}"

.PHONY: affected verify-change frontend-check frontend-storefront frontend-admin service-check

affected: ## Classify affected components; use BASE=<ref> [HEAD=<ref|WORKTREE>]
	@$(PYTHON) scripts/repoctl.py affected --base "$${BASE:-origin/main}" --head "$${HEAD:-WORKTREE}"

verify-change: ## Run global + affected component gates and write evidence JSON
	@$(PYTHON) scripts/repoctl.py verify-change --base "$${BASE:-origin/main}" --head "$${HEAD:-WORKTREE}"

frontend-check: ## Run complete Storefront + Admin frontend gate
	@$(PYTHON) scripts/repoctl.py frontend check all

frontend-storefront: ## Run complete Storefront gate
	@$(PYTHON) scripts/repoctl.py frontend check storefront

frontend-admin: ## Run complete Admin gate
	@$(PYTHON) scripts/repoctl.py frontend check admin

service-check: ## Run generic Go service gate; use SERVICE=product
	@$(PYTHON) scripts/repoctl.py service "$(SERVICE)"

.PHONY: tekton-trigger-readiness

tekton-trigger-readiness: ## Read-only live proof of all Gitea -> Tekton trigger runtime prerequisites; set RUNTIME_CONFIG=...
	@$(PYTHON) scripts/repoctl.py tekton-trigger-readiness --runtime-config "$(RUNTIME_CONFIG)" --evidence "$${EVIDENCE:-.context/runtime/tekton-trigger-readiness.json}"

.PHONY: workstation-doctor workstation-bootstrap quality-tools agent-tools context-tools product-bootstrap-persistence git-local-reconcile git-sync publish deliver bundle-deliver evidence-publish evidence-fetch evidence-compare perf-audit

workstation-doctor: ## Audit local developer state without mutating it
	@$(PYTHON) scripts/repoctl.py doctor

workstation-bootstrap: ## Reconcile WSL workstation, pinned collections and developer toolchains with Ansible
	@$(ANSIBLE_LOCAL) --tags workstation,bootstrap,ansible_collections,toolchain,node,agent_tools,context_tools

quality-tools: ## Reconcile pinned Oxlint, Oxfmt and Ruff binaries
	@$(ANSIBLE_LOCAL) --tags quality_tools

agent-tools: ## Reconcile Bazel/Nx/Turbo/OpenAPI/context tooling with Ansible
	@$(ANSIBLE_LOCAL) --tags toolchain,node,agent_tools,context_tools

context-tools: ## Reconcile token-efficient context tooling with Ansible
	@$(ANSIBLE_LOCAL) --tags context_tools

product-bootstrap-persistence: ## Reconcile Product persistence generation/dependencies with Ansible
	@$(ANSIBLE_LOCAL) --tags go,cgo,sqlc,docker,product_persistence

git-local-reconcile: ## Reconcile Git config; TARGET_REPO_ROOT may target another checkout
	@ansible-playbook -i localhost, -c local platform/ansible/developer.yml -e repo_root="$${TARGET_REPO_ROOT:-$(CURDIR)}" --tags git

git-sync: ## Fetch/prune and fast-forward current branch
	@$(PYTHON) scripts/repoctl.py git-sync

publish: ## Commit, exact-SHA verify and push current feature branch
	@$(PYTHON) scripts/repoctl.py publish --base "$${BASE:-origin/main}" --message "$(MSG)"

deliver: ## Exact-SHA validate, publish and create/update GitHub PR
	@$(PYTHON) scripts/repoctl.py deliver --base "$${BASE:-main}" --title "$(TITLE)" --message "$(MSG)"

bundle-deliver: ## Deliver a Git bundle from an isolated checkout; BUNDLE/EXPECTED_HEAD/TITLE required
	@$(PYTHON) scripts/repoctl.py bundle-deliver --bundle "$(BUNDLE)" --expected-head "$(EXPECTED_HEAD)" --title "$(TITLE)" --base "$${BASE:-main}"

evidence-publish: ## Sign and publish exact PASS evidence to the configured OCI evidence repository
	@$(PYTHON) scripts/repoctl.py evidence-publish --path "$(EVIDENCE)"

evidence-fetch: ## Fetch and authenticate exact evidence; SHA=<full-sha>
	@$(PYTHON) scripts/repoctl.py evidence-fetch --sha "$(SHA)"

evidence-compare: ## Compare measured full/incremental evidence; FULL_EVIDENCE/INCREMENTAL_EVIDENCE required
	@$(PYTHON) scripts/repoctl.py evidence-compare --full "$(FULL_EVIDENCE)" --incremental "$(INCREMENTAL_EVIDENCE)"

perf-audit: ## Audit critical path, reuse/cache hit ratio and Amdahl priorities from evidence
	@$(PYTHON) scripts/performance_audit.py $(if $(EVIDENCE),--evidence "$(EVIDENCE)",) $(if $(BASELINE_EVIDENCE),--baseline "$(BASELINE_EVIDENCE)",) $(if $(PERF_OUTPUT),--output "$(PERF_OUTPUT)",)

.PHONY: context diff-context failure-context nx-graph bazel-verify

context: ## Build bounded task-aware context pack; use TASK="..."
	@$(PYTHON) scripts/repoctl.py context "$(TASK)"

diff-context: ## Build compact diff-only context pack
	@$(PYTHON) scripts/repoctl.py diff-context --base "$${BASE:-origin/main}"

failure-context: ## Capture actionable output; use GATE=... or COMPONENT=service:product
	@$(PYTHON) scripts/repoctl.py failure-context --gate "$(GATE)" --component "$(COMPONENT)"

nx-graph: ## Render Nx dependency graph derived from canonical YAML contracts
	@$(PYTHON) scripts/repoctl.py nx-graph

bazel-verify: ## Run affected-only verification through pinned Bazel
	@bazel run //:repoctl -- verify-change --base "$${BASE:-origin/main}" --head "$${HEAD:-WORKTREE}"

.PHONY: api-generate api-mock service-new

api-generate: ## Generate Go and TypeScript bindings from registered OpenAPI contracts
	@$(PYTHON) scripts/repoctl.py api-generate --target all $(if $(SERVICE),--service $(SERVICE),)

api-mock: ## Start Prism mock; use SERVICE=product PORT=4010
	@$(PYTHON) scripts/repoctl.py api-mock --service "$${SERVICE:-product}" --port "$${PORT:-4010}"

service-new: ## Generate canonical service skeleton; set SERVICE=... [DRY_RUN=1]
	@$(PYTHON) scripts/repoctl.py service-new --service "$(SERVICE)" $(if $(DRY_RUN),--dry-run,)

.PHONY: site product-check product-run product-benchmark resource-candidate

site: ## Install pinned frontend dependencies and run Storefront + Admin locally
	@$(MAKE) -C frontend site

product-check: ## Validate Product through generic Go service gate
	@$(PYTHON) scripts/repoctl.py service product

product-run: ## Run local Product REST runtime on PRODUCT_HTTP_ADDR (default :8080)
	@$(ANSIBLE_LOCAL) --tags go
	@$(HOME)/.local/bin/go run ./services/product/cmd/product-api

product-benchmark: ## Benchmark the Product HTTP hot path with allocations; not production sizing evidence
	@$(ANSIBLE_LOCAL) --tags go
	@cd services/product && $(HOME)/.local/bin/go test -run '^$$' -bench '^BenchmarkListProductsEmpty$$' -benchmem ./internal/transport/rest

resource-candidate: ## Derive a deterministic candidate from representative preprod evidence; use EVIDENCE=path.json
	@ruby scripts/resource-sizing.rb "$(EVIDENCE)"

.PHONY: tekton-proof

tekton-proof: ## Reconcile Tekton and run one exact remote proof; RUNTIME_CONFIG/BASE_SHA/PARENT_SHA/HEAD_SHA required
	@ansible-playbook -i localhost, -c local platform/ansible/tekton-proof.yml -e repo_root=$(CURDIR) -e tekton_runtime_config="$(RUNTIME_CONFIG)" -e proof_base_sha="$(BASE_SHA)" -e proof_parent_sha="$(PARENT_SHA)" -e proof_head_sha="$(HEAD_SHA)"
