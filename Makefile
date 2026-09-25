QUALIFICATION_VENV := $(CURDIR)/.venv/qualification
QUALIFICATION_BIN := $(QUALIFICATION_VENV)/bin
QUALIFICATION_PYTHON := $(QUALIFICATION_BIN)/python
PYTHON := $(if $(wildcard $(QUALIFICATION_PYTHON)),$(QUALIFICATION_PYTHON),python3)
ifneq ($(wildcard $(QUALIFICATION_PYTHON)),)
export PATH := $(QUALIFICATION_BIN):$(PATH)
endif
.PHONY: help toolchain-closure seed bootstrap bootstrap-runtime env-check env-check-runtime ci ci-full ci-global governance runtime-efficiency contracts automation lint format format-check test security qualification-tools qualification-tools-smoke opentofu ansible system qce-status qce-check execution-properties execution-properties-matrix capabilities security-datasets-sync engineering-metrics experiment

toolchain-closure: ## Validate the fail-closed central toolchain registry
	@$(PYTHON) scripts/repoctl.py toolchain-closure

seed: toolchain-closure ## Reconcile the hash-locked Python/Ansible seed environment without requiring Ansible
	@$(PYTHON) -I -S scripts/capability_bootstrap.py seed

bootstrap: seed ## Reconcile required static capabilities independently in dependency order
	@PATH="$(QUALIFICATION_BIN):$$PATH" $(QUALIFICATION_PYTHON) scripts/capability_bootstrap.py bootstrap --profile static

bootstrap-runtime: seed ## Reconcile and require optional external runtime capabilities
	@PATH="$(QUALIFICATION_BIN):$$PATH" $(QUALIFICATION_PYTHON) scripts/capability_bootstrap.py bootstrap --profile runtime

env-check: toolchain-closure ## Audit capabilities without changing the workstation
	@test -x "$(QUALIFICATION_PYTHON)" || { printf '%s\n' 'BLOCKED qualification seed missing: run `make seed`'; exit 1; }
	@PATH="$(QUALIFICATION_BIN):$$PATH" $(QUALIFICATION_PYTHON) scripts/capability_bootstrap.py env-check --profile static

env-check-runtime: toolchain-closure ## Audit and require optional external runtime capabilities
	@test -x "$(QUALIFICATION_PYTHON)" || { printf '%s\n' 'BLOCKED qualification seed missing: run `make seed`'; exit 1; }
	@PATH="$(QUALIFICATION_BIN):$$PATH" $(QUALIFICATION_PYTHON) scripts/capability_bootstrap.py env-check --profile runtime

help: ## Show the available checks
	@$(PYTHON) scripts/repoctl.py --help
	@printf '\nAgent efficiency:\n  make review-budget PR=<n> SNAPSHOT=<json> [REVIEW_KIND=combined] [FINAL_CANDIDATE=1]\n'

ci: ## Run the portable non-mutating static profile over global + affected gates
	@$(PYTHON) scripts/repoctl.py verify-change --profile static --base "$${BASE:-origin/main}" --head WORKTREE

ci-full: ## Run merge-authoritative full qualification (WSL2 runtime required when affected)
	@$(PYTHON) scripts/repoctl.py verify-change --profile full --base "$${BASE:-origin/main}" --head WORKTREE

ci-global: ## Run canonical global gates through the central execution planner
	@$(PYTHON) scripts/repoctl.py global-check --base "$${BASE:-origin/main}" --head "$${HEAD:-WORKTREE}"
governance: runtime-efficiency ## Validate canonical architecture and all registered governance contracts
	@$(PYTHON) scripts/repoctl.py governance

runtime-efficiency: ## Validate measured resource, autoscaling, image and runtime efficiency policy
	@$(PYTHON) scripts/repoctl.py runtime-efficiency

contracts: ## Validate OpenAPI and cross-registry contracts; BASE enables compatibility checks
	@$(PYTHON) scripts/repoctl.py contracts $(if $(BASE),--base $(BASE),) $(if $(HEAD),--head $(HEAD),)

automation: ## Enforce Ansible-first and zero repository Shell scripts
	@$(PYTHON) scripts/repoctl.py automation-policy

lint: automation ## Lint Go, Python and frontend sources with declared toolchains
	@$(PYTHON) scripts/repoctl.py lint

format: format-check ## Non-mutating alias; repository quality automation never rewrites source files

format-check: ## Run repository-wide non-mutating format diagnostics from the central quality policy
	@$(PYTHON) scripts/repoctl.py format-check

test: ## Run repository, Go and frontend test suites
	@$(PYTHON) scripts/repoctl.py test

system: ## Run cross-system repository tests without replaying component suites
	@$(PYTHON) scripts/repoctl.py system

security: ## Scan working tree for secrets
	@$(PYTHON) scripts/repoctl.py security

qualification-tools: ## Validate qualification tool contracts and evidence parsers
	@$(PYTHON) scripts/repoctl.py qualification-tools-contract

qualification-tools-smoke: ## Reconcile and run bounded controller-side qualification tool smoke tests
	@$(PYTHON) scripts/repoctl.py reconcile --tags conftest,opa,k6,nuclei,hubble,pint
	@$(PYTHON) scripts/repoctl.py qualification-tools-smoke

qce-status: ## Render the derived nine-sector QCE status projection
	@$(PYTHON) scripts/repoctl.py qce-status $(if $(SECTOR),--sector "$(SECTOR)",) $(if $(JSON),--json,)

qce-check: ## Validate QCE traceability, closed statuses and derived labels
	@$(PYTHON) scripts/repoctl.py qce-check

execution-properties: ## Validate the canonical execution-properties authority and implementation registry
	@$(PYTHON) scripts/repoctl.py execution-properties

execution-properties-matrix: ## Render the execution-properties matrix from the implementation registry
	@$(PYTHON) scripts/repoctl.py execution-properties --matrix

capabilities: ## Resolve scoped effective tool capabilities from exact-SHA evidence
	@$(PYTHON) scripts/repoctl.py capabilities

security-datasets-sync: ## Explicitly refresh verified KEV/EPSS snapshots outside qualification
	@$(PYTHON) scripts/repoctl.py security-datasets-sync --output "$${OUTPUT:-.context/security-datasets}"

engineering-metrics: ## Calculate contract-defined engineering metrics from INPUT=<events.json>
	@$(PYTHON) scripts/repoctl.py engineering-metrics --input "$(INPUT)" $(if $(OUTPUT),--output "$(OUTPUT)",)

experiment: ## Run ACTION=baseline|evaluate|status for INPUT=<experiment.json>
	@$(PYTHON) scripts/repoctl.py experiment "$(ACTION)" --input "$(INPUT)" $(if $(OUTPUT),--output "$(OUTPUT)",)

opentofu: ## Validate OpenTofu-compatible sources with the sole authorized IaC engine
	@$(PYTHON) scripts/repoctl.py opentofu

ansible: ## Validate Ansible sources and local developer playbook syntax
	@$(PYTHON) scripts/repoctl.py ansible

.PHONY: mgmt-runtime-inventory

mgmt-runtime-inventory: ## Build non-secret bootstrap transport overlay from OpenTofu MGMT outputs
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

frontend-admin: ## Run complete Admin frontend gate
	@$(PYTHON) scripts/repoctl.py frontend check admin

service-check: ## Run generic Go service gate; use SERVICE=product
	@$(PYTHON) scripts/repoctl.py service "$(SERVICE)"

.PHONY: tekton-trigger-readiness

tekton-trigger-readiness: ## Read-only live proof of all Gitea -> Tekton trigger runtime prerequisites; set RUNTIME_CONFIG=...
	@$(PYTHON) scripts/repoctl.py tekton-trigger-readiness --runtime-config "$(RUNTIME_CONFIG)" --evidence "$${EVIDENCE:-.context/runtime/tekton-trigger-readiness.json}"

.PHONY: workstation-doctor workstation-bootstrap quality-tools agent-tools context-tools product-bootstrap-persistence git-local-reconcile git-sync branch-cleanup roadmap-check roadmap-sync publish publish-change deliver finish-pr bundle-deliver evidence-publish evidence-fetch evidence-compare perf-audit perf-campaign qualification-proof

workstation-doctor: ## Audit local developer state without mutating it
	@$(PYTHON) scripts/repoctl.py doctor

workstation-bootstrap: ## Reconcile WSL workstation, pinned collections and developer toolchains with Ansible
	@$(PYTHON) scripts/repoctl.py reconcile --tags workstation,bootstrap,ansible_collections,toolchain,node,agent_tools,context_tools

quality-tools: ## Reconcile pinned Oxlint, Oxfmt and Ruff binaries
	@$(PYTHON) scripts/repoctl.py reconcile --tags quality_tools

agent-tools: ## Reconcile Bazel/Nx/Turbo/OpenAPI/context tooling with Ansible
	@$(PYTHON) scripts/repoctl.py reconcile --tags toolchain,node,agent_tools,context_tools

context-tools: ## Reconcile token-efficient context tooling with Ansible
	@$(PYTHON) scripts/repoctl.py reconcile --tags context_tools

product-bootstrap-persistence: ## Reconcile Product persistence generation/dependencies with Ansible
	@$(PYTHON) scripts/repoctl.py reconcile --tags go,cgo,sqlc,docker,product_persistence

git-local-reconcile: ## Reconcile Git config; TARGET_REPO_ROOT may target another checkout
	@$(PYTHON) scripts/repoctl.py reconcile --tags git --target-repo-root "${TARGET_REPO_ROOT:-$(CURDIR)}"

git-sync: ## Fetch/prune and fast-forward current branch
	@$(PYTHON) scripts/repoctl.py git-sync

branch-cleanup: ## Delete safe stale local/remote branches; DRY_RUN=1 only reports candidates
	@$(PYTHON) scripts/repoctl.py branch-cleanup $(if $(DRY_RUN),--dry-run,)

roadmap-check: ## Check GitHub-backed milestone/tracker state against the generated roadmap
	@$(PYTHON) scripts/repoctl.py roadmap-check

roadmap-sync: ## Regenerate roadmap milestone status/tracker projections from GitHub
	@$(PYTHON) scripts/repoctl.py roadmap-sync

publish: ## Commit, exact-SHA verify and push current feature branch
	@$(PYTHON) scripts/repoctl.py publish --base "$${BASE:-origin/main}" --message "$(MSG)"

publish-change: ## Canonical alias: qualify, commit and push the current feature branch
	@$(PYTHON) scripts/repoctl.py publish-change --base "$${BASE:-origin/main}" --message "$(MSG)"

deliver: ## Exact-SHA validate, publish and create/update GitHub PR
	@$(PYTHON) scripts/repoctl.py deliver --base "$${BASE:-main}" --title "$(TITLE)" --message "$(MSG)"

finish-pr: ## Merge exact reviewed PR, clean branches, check roadmap and publish sync PR on drift
	@$(PYTHON) scripts/repoctl.py finish-pr --base "$${BASE:-main}"

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

perf-campaign: ## Run the repository-defined statistical performance campaign
	@$(PYTHON) scripts/repoctl.py perf-campaign --base "$${BASE:-origin/main}" $(if $(PERF_CAMPAIGN_OUTPUT),--output "$(PERF_CAMPAIGN_OUTPUT)",)

qualification-proof: ## Run one exact-SHA qualification plus its performance audit
	@$(PYTHON) scripts/repoctl.py qualification-proof --base "$${BASE:-origin/main}"
.PHONY: context diff-context failure-context review-budget nx-graph bazel-verify pr-monitor

context: ## Build bounded task-aware context pack; use TASK="..."
	@$(PYTHON) scripts/repoctl.py context "$(TASK)"

diff-context: ## Build compact diff-only context pack
	@$(PYTHON) scripts/repoctl.py diff-context --base "$${BASE:-origin/main}"

failure-context: ## Capture actionable output; use GATE=... or COMPONENT=service:product
	@$(PYTHON) scripts/repoctl.py failure-context --gate "$(GATE)" --component "$(COMPONENT)"

pr-monitor: ## Poll one GitHub PR cheaply and emit bounded ChatGPT review handoffs; PR/OWNER/REPO required
	@$(PYTHON) scripts/pr_monitor.py --owner "$(OWNER)" --repo "$(REPO)" --pr "$(PR)" --interval 900 --max-interval 3600

review-budget: ## Decide whether ChatGPT exact-SHA review should run; PR and SNAPSHOT required
	@test -n "$(PR)" || { printf '%s\n' 'ERROR: PR=<number> is required'; exit 2; }
	@test -n "$(SNAPSHOT)" || { printf '%s\n' 'ERROR: SNAPSHOT=<json-path> is required'; exit 2; }
	@$(PYTHON) scripts/review_budget.py decide --pr "$(PR)" --snapshot "$(SNAPSHOT)" --review-kind "$${REVIEW_KIND:-combined}" $(if $(FINAL_CANDIDATE),--final-candidate,)

nx-graph: ## Render Nx dependency graph derived from canonical YAML contracts
	@$(PYTHON) scripts/repoctl.py nx-graph

bazel-verify: ## Run affected-only verification through pinned Bazel
	@$(PYTHON) scripts/repoctl.py bazel-verify --base "${BASE:-origin/main}" --head "${HEAD:-WORKTREE}"

.PHONY: api-generate service-new

api-generate: ## Generate Go bindings from registered OpenAPI contracts
	@$(PYTHON) scripts/repoctl.py api-generate --target go $(if $(SERVICE),--service $(SERVICE),)

service-new: ## Generate canonical service skeleton; set SERVICE=... [DRY_RUN=1]
	@$(PYTHON) scripts/repoctl.py service-new --service "$(SERVICE)" $(if $(DRY_RUN),--dry-run,)

.PHONY: site product-check product-run product-migrate product-benchmark resource-candidate

site: ## Run Storefront and Admin Go frontends locally
	@$(PYTHON) scripts/repoctl.py site

product-check: ## Validate Product through generic Go service gate
	@$(PYTHON) scripts/repoctl.py service product

product-run: ## Run local Product REST runtime through the central tool resolver
	@$(PYTHON) scripts/repoctl.py product-run

product-migrate: ## Apply Product PostgreSQL migrations through the central tool resolver
	@$(PYTHON) scripts/repoctl.py product-migrate

product-benchmark: ## Benchmark Product through the central tool resolver
	@$(PYTHON) scripts/repoctl.py product-benchmark

resource-candidate: ## Derive a deterministic candidate from representative preprod evidence; use EVIDENCE=path.json
	@$(PYTHON) scripts/repoctl.py resource-candidate --evidence "$(EVIDENCE)"

.PHONY: tekton-proof

tekton-proof: ## Reconcile Tekton and run one exact remote proof; RUNTIME_CONFIG/BASE_SHA/PARENT_SHA/HEAD_SHA required
	@$(PYTHON) scripts/repoctl.py tekton-proof --runtime-config "$(RUNTIME_CONFIG)" --base-sha "$(BASE_SHA)" --parent-sha "$(PARENT_SHA)" --head-sha "$(HEAD_SHA)"
