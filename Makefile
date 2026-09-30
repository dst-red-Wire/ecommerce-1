QUALIFICATION_VENV := $(CURDIR)/.venv/qualification
QUALIFICATION_BIN := $(QUALIFICATION_VENV)/bin
QUALIFICATION_PYTHON := $(QUALIFICATION_BIN)/python
PYTHON := $(if $(wildcard $(QUALIFICATION_PYTHON)),$(QUALIFICATION_PYTHON),python3)
ifneq ($(wildcard $(QUALIFICATION_PYTHON)),)
export PATH := $(QUALIFICATION_BIN):$(PATH)
endif
NATIVE_WORKSPACE := $(shell $(PYTHON) scripts/native_workspace.py --quiet >/dev/null 2>&1 && printf PASS)
ifneq ($(NATIVE_WORKSPACE),PASS)
$(error Repository operations require a WSL2 checkout on the native Linux filesystem, such as /home/dev/ecommerce-1)
endif
.PHONY: workspace-check
workspace-check:
	@$(PYTHON) scripts/repoctl.py workspace-check

.PHONY: help toolchain-closure seed bootstrap bootstrap-runtime env-check env-check-runtime ci ci-full ci-global governance runtime-efficiency contracts automation signing-check lint format format-check test security qualification-tools qualification-tools-smoke opentofu ansible system qce-status qce-check execution-properties execution-properties-matrix capabilities security-datasets-sync engineering-metrics experiment

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

ci: workspace-check signing-rotation-check ## Run the portable non-mutating static profile over global + affected gates
	@$(PYTHON) scripts/repoctl.py verify-change --profile static --base "$${BASE:-origin/main}" --head WORKTREE

ci-full: ## Run merge-authoritative full qualification (WSL2 runtime required when affected)
	@$(PYTHON) scripts/repoctl.py verify-change --profile full --base "$${BASE:-origin/main}" --head WORKTREE

ci-global: ## Run canonical global gates through the central execution planner
	@$(PYTHON) scripts/repoctl.py global-check --base "$${BASE:-origin/main}" --head "$${HEAD:-WORKTREE}"
governance: workspace-check runtime-efficiency ## Validate canonical architecture and all registered governance contracts
	@$(PYTHON) scripts/repoctl.py governance

runtime-efficiency: ## Validate measured resource, autoscaling, image and runtime efficiency policy
	@$(PYTHON) scripts/repoctl.py runtime-efficiency

contracts: workspace-check ## Validate OpenAPI and cross-registry contracts; BASE enables compatibility checks
	@$(PYTHON) scripts/repoctl.py contracts $(if $(BASE),--base $(BASE),) $(if $(HEAD),--head $(HEAD),)

automation: ## Enforce Ansible-first and zero repository Shell scripts
	@$(PYTHON) scripts/repoctl.py automation-policy

signing-check: signing-rotation-check ## Verify local automation signing isolation, validity and rotation window
	@$(PYTHON) scripts/check_automation_signing.py

.PHONY: signing-rotation-check signing-rotation-status signing-rotate signing-rotation-verify-remote signing-rotation-activate signing-rotation-retire-old
signing-rotation-check: ## Read-only rotation status and delivery gate
	@$(PYTHON) scripts/signing_rotation.py rotation-check

signing-rotation-status: ## Show read-only rotation status
	@$(PYTHON) scripts/signing_rotation.py rotation-status

signing-rotate: ## Prepare the replacement key without activating it
	@$(PYTHON) scripts/signing_rotation.py rotate

signing-rotation-verify-remote: ## Verify public registration on GitHub and Gitea
	@$(PYTHON) scripts/signing_rotation.py verify-remote

signing-rotation-activate: ## Activate only after both forge registrations are proven
	@$(PYTHON) scripts/signing_rotation.py activate

signing-rotation-retire-old: ## Retire old registration after exact replacement proofs
	@$(PYTHON) scripts/signing_rotation.py retire-old

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

.PHONY: mgmt-runtime-inventory image-rocky-preflight image-rocky-build image-rocky-qualify image-rocky-release image-rocky-windows-preflight image-rocky-windows-build image-rocky-windows-qualify image-rocky-windows-release image-rocky-windows-native-prepare image-rocky-windows-native-reboot image-rocky-windows-native-import image-rocky-windows-native-recover image-rocky-windows-native-reset-failed image-rocky-windows-native-self-test image-rocky-linux-static-validate image-rocky-linux-preflight image-rocky-linux-build image-rocky-linux-qualify image-rocky-linux-release image-rocky-oras-push image-rocky-oras-pull local-services-assets local-services-capabilities local-services-qualify local-services-recover lab-ssh-key packer-box lab-network-smoke lab-network-resume lab-network-import lab-network-native-prepare lab-network-native-boot-prepare lab-network-native-boot-reboot lab-network-native-boot-recover lab-network-native-boot-self-test lab-network-status lab-clean
.PHONY: local-services-up local-services-provision local-services-proof local-gpg-register

local-services-up: workspace-check ## Start pinned local Gitea/Harbor on native WSL storage
	@$(PYTHON) platform/local-services/manage.py up

local-services-provision: workspace-check ## Create dedicated local Gitea/Harbor identities
	@$(PYTHON) platform/local-services/manage.py gitea-users
	@$(PYTHON) platform/local-services/manage.py harbor-robot

local-gpg-register: workspace-check ## Register public automation key on Gitea only after reboot proof
	@$(PYTHON) platform/local-services/manage.py register-gpg

local-services-proof: workspace-check ## Verify TLS, DNS, identities, GPG and Harbor robot login
	@$(PYTHON) platform/local-services/manage.py proof


mgmt-runtime-inventory: ## Build non-secret bootstrap transport overlay from OpenTofu MGMT outputs
	@$(PYTHON) scripts/mgmt_runtime_inventory.py --output "$${OUTPUT:-.context/runtime/mgmt-ansible-transport.json}"

image-rocky-preflight: image-rocky-windows-preflight ## Default profile: verify the native Windows image toolchain

image-rocky-build: image-rocky-windows-build ## Default profile: build the Windows/VirtualBox artifact

image-rocky-qualify: image-rocky-windows-qualify ## Default profile: qualify the Windows/VirtualBox artifact

image-rocky-release: image-rocky-windows-release ## Default profile: release-check the Windows artifact

image-rocky-windows-preflight: ## Verify exact native Windows Packer, VirtualBox and Vagrant versions without starting a VM
	@$(PYTHON) scripts/repoctl.py image-rocky-windows-preflight

image-rocky-windows-build: ## Build the checksum-locked Rocky Linux 10.2 VirtualBox box with native Windows Packer
	@$(PYTHON) scripts/repoctl.py image-rocky-windows-build $(if $(OFFLINE),--offline,)

image-rocky-windows-qualify: ## Boot and smoke-test the exact Rocky box through isolated native Windows Vagrant state
	@$(PYTHON) scripts/repoctl.py image-rocky-windows-qualify

image-rocky-windows-release: ## Verify exact Windows build and qualification evidence without remote publication
	@$(PYTHON) scripts/repoctl.py image-rocky-windows-release

image-rocky-windows-native-prepare: ## Prepare exact-SHA Windows staging, guarded BCD entry and one-shot task; does not reboot
	@$(PYTHON) scripts/repoctl.py image-rocky-windows-native-prepare $(if $(OFFLINE),--offline,)

image-rocky-windows-native-reboot: ## Explicitly authorize the one-shot native VT-x boot and automatic return
	@$(PYTHON) scripts/repoctl.py image-rocky-windows-native-reboot

image-rocky-windows-native-import: ## Import exact-SHA native VT-x build and smoke evidence after WSL2 returns
	@$(PYTHON) scripts/repoctl.py image-rocky-windows-native-import

image-rocky-windows-native-recover: ## Arm the normal Windows boot and remove the temporary task while preserving the native entry
	@$(PYTHON) scripts/repoctl.py image-rocky-windows-native-recover

image-rocky-windows-native-reset-failed: ## Archive a failed native cycle's stale stage after normal-boot recovery
	@$(PYTHON) scripts/repoctl.py image-rocky-windows-native-reset-failed

image-rocky-windows-native-self-test: ## Test BCD parsing, backend classification, integrity and stale-evidence rejection without reboot
	@$(PYTHON) scripts/repoctl.py image-rocky-windows-native-self-test

lab-ssh-key: ## Explicitly create or verify the persistent Windows-native Rocky smoke SSH identity
	@$(PYTHON) scripts/repoctl.py lab-ssh-key

packer-box: ## Verify and reuse the local immutable Rocky box matching current Packer inputs
	@$(PYTHON) scripts/repoctl.py packer-box $(if $(BOX_PATH),--box "$(BOX_PATH)",)

lab-network-smoke: ## Stage exact-SHA native network smoke from a verified box without running Packer
	@$(PYTHON) scripts/repoctl.py lab-network-smoke $(if $(BOX_PATH),--box "$(BOX_PATH)",) $(if $(BOX_SHA256),--box-sha256 "$(BOX_SHA256)",) $(if $(filter 1,$(KEEP_FAILED_VM)),--keep-failed-vm,) $(if $(filter 1,$(RETAIN_VM)),--retain-vm,) $(if $(filter 1,$(DIAGNOSTIC_NEM)),--diagnostic-nem,) $(if $(GLOBAL_DEADLINE),--global-deadline $(GLOBAL_DEADLINE),)

lab-network-resume: ## Resume SSH and Rocky probes on the retained VM for CAMPAIGN_ID
	@$(PYTHON) scripts/repoctl.py lab-network-resume --campaign-id "$(CAMPAIGN_ID)"

lab-network-import: ## Import a PASS native-boot network result after WSL is restored
	@$(PYTHON) scripts/repoctl.py lab-network-import --campaign-id "$(CAMPAIGN_ID)"

lab-network-native-prepare: ## Stage exact-head Windows runner for a native-boot Resume
	@$(PYTHON) scripts/repoctl.py lab-network-native-prepare --campaign-id "$(CAMPAIGN_ID)"

lab-network-native-boot-prepare: ## Prepare the retained campaign's guarded one-shot native Windows entry; no reboot
	@echo "BLOCKED: invoke trusted-native-uac from the exact-base checkout; see docs/engineering/ROCKY_BOX_REUSE.md" >&2; exit 1

lab-network-native-boot-reboot: ## Explicitly start the one-shot native boot for the retained campaign
	@echo "BLOCKED: invoke trusted-native-uac from the exact-base checkout; see docs/engineering/ROCKY_BOX_REUSE.md" >&2; exit 1

lab-network-native-boot-recover: ## Restore normal boot and remove the owned network-smoke entry
	@echo "BLOCKED: invoke trusted-native-uac from the exact-base checkout; see docs/engineering/ROCKY_BOX_REUSE.md" >&2; exit 1

lab-network-native-boot-self-test: ## Check network native-boot BCD parsing and state guards without mutation
	@echo "BLOCKED: invoke trusted-native-uac from the exact-base checkout; see docs/engineering/ROCKY_BOX_REUSE.md" >&2; exit 1

lab-network-status: ## Read the latest network checkpoint and current VirtualBox VM state
	@$(PYTHON) scripts/repoctl.py lab-network-status --campaign-id "$(CAMPAIGN_ID)"

lab-clean: ## Destroy the explicitly preserved network-smoke VM for CAMPAIGN_ID
	@$(PYTHON) scripts/repoctl.py lab-clean --campaign-id "$(CAMPAIGN_ID)"

image-rocky-linux-preflight: ## Verify exact Packer/QEMU versions and KVM access on a native Linux host
	@$(PYTHON) scripts/repoctl.py image-rocky-linux-preflight

image-rocky-linux-static-validate: ## Validate QEMU Packer source/plugins through Windows without claiming KVM runtime
	@$(PYTHON) scripts/repoctl.py image-rocky-linux-static-validate

image-rocky-linux-build: ## Build the checksum-locked Rocky Linux 10.2 qcow2 with native Linux Packer/QEMU
	@$(PYTHON) scripts/repoctl.py image-rocky-linux-build $(if $(OFFLINE),--offline,)

image-rocky-linux-qualify: ## Boot and smoke-test the exact qcow2 through bounded native QEMU/KVM
	@$(PYTHON) scripts/repoctl.py image-rocky-linux-qualify

image-rocky-linux-release: ## Verify exact Linux build and qualification evidence without remote publication
	@$(PYTHON) scripts/repoctl.py image-rocky-linux-release

image-rocky-oras-push: ## Push PROFILE=windows|linux release to ORAS_REPOSITORY and report its immutable digest
	@$(PYTHON) scripts/repoctl.py image-rocky-oras-push --profile "$${PROFILE:-windows}" --repository "$${ORAS_REPOSITORY:-}"

image-rocky-oras-pull: ## Pull PROFILE=windows|linux from immutable ORAS_REF=repository@sha256:digest
	@$(PYTHON) scripts/repoctl.py image-rocky-oras-pull --profile "$${PROFILE:-windows}" --reference "$${ORAS_REF:-}"

local-services-assets: ## Materialize exact Gitea, Harbor and Docker offline inputs
	@$(PYTHON) scripts/repoctl.py local-services-assets $(if $(OFFLINE),--offline,)

local-services-capabilities: ## Observe WSL2, Ansible, SSH and Windows VirtualBox runtime prerequisites
	@$(PYTHON) scripts/repoctl.py local-services-capabilities

local-services-qualify: ## Qualify Gitea, Harbor and ORAS on the exact released Rocky box
	@$(PYTHON) scripts/repoctl.py local-services-qualify $(if $(OFFLINE),--offline,)

local-services-recover: ## Stop only owned local service VMs while preserving their disks
	@$(PYTHON) scripts/repoctl.py local-services-recover

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

.PHONY: workstation-doctor workstation-bootstrap quality-tools agent-tools context-tools product-bootstrap-persistence git-local-reconcile git-sync branch-cleanup roadmap-check roadmap-sync deliver pr-loop finish-pr bundle-deliver evidence-publish evidence-fetch evidence-compare perf-audit perf-campaign qualification-proof

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

deliver: signing-rotation-check ## Canonical publication: qualify, sign/commit, push and create/update exact-SHA GitHub PR
	@$(PYTHON) scripts/repoctl.py deliver --base "$${BASE:-main}" --title "$(TITLE)" --message "$(MSG)"

pr-loop: ## Run trusted-pr-transition from TRUSTED_ROOT at the PR BASE_SHA, then dispatch external review; PR required
	@test -n "$(TRUSTED_ROOT)" || { echo "BLOCKED TRUSTED_ROOT exact-base checkout is required" >&2; exit 1; }
	@test -n "$(PR)" || { echo "BLOCKED PR number is required" >&2; exit 1; }
	@$(PYTHON) scripts/pr_review_dispatch_transition.py --trusted-root "$(TRUSTED_ROOT)" --target-root "$(CURDIR)" --pr "$(PR)" $(if $(DRY_RUN),--dry-run,) $(if $(JSON),--json,) $(if $(LEGACY_BOOTSTRAP_BINDING),--legacy-bootstrap-binding "$(LEGACY_BOOTSTRAP_BINDING)",)

.PHONY: review-dispatch-status
review-dispatch-status: ## Read non-authoritative ChatGPT outbox status for exact PR and KIND=CODE|SECURITY
	@test -n "$(PR)" || { echo "BLOCKED PR number is required" >&2; exit 1; }
	@test -n "$(KIND)" || { echo "BLOCKED KIND=CODE|SECURITY is required" >&2; exit 1; }
	@$(PYTHON) scripts/pr_review_dispatch_transition.py --target-root "$(CURDIR)" --pr "$(PR)" --status --kind "$(KIND)" --json

finish-pr: ## Internal only: trusted-pr-transition delegates to exact-base repoctl.py
	@echo "BLOCKED finish-pr is internal to exact-base trusted-pr-transition" >&2
	@exit 1

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

.PHONY: qualification
qualification: qualification-proof ## Run exact-SHA qualification from the canonical workspace

qualification-proof: workspace-check ## Run one exact-SHA qualification plus its performance audit
	@$(PYTHON) scripts/repoctl.py qualification-proof --base "$${BASE:-origin/main}"
.PHONY: context diff-context failure-context review-budget codex-run codex-budget codex-budget-mark nx-graph bazel-verify pr-monitor

context: ## Build task-delta context pack; optional SINCE/PATHS/STAGED/WORKING_TREE/PRINT
	@test -n "$(TASK)" || { printf '%s\n' 'ERROR: TASK=<bounded task> is required'; exit 2; }
	@$(PYTHON) scripts/context-pack.py --task "$(TASK)" $(if $(SINCE),--since "$(SINCE)",) $(if $(PATHS),--paths $(PATHS),) $(if $(STAGED),--staged,) $(if $(WORKING_TREE),--working-tree,) $(if $(PRINT),--print,)

diff-context: ## Build compact diff-only context pack (hard-capped by codex-token-budget)
	@$(PYTHON) scripts/repoctl.py diff-context --base "$${BASE:-origin/main}"

failure-context: ## Capture causal output; use GATE=... or COMPONENT=service:product
	@$(PYTHON) scripts/repoctl.py failure-context --gate "$(GATE)" --component "$(COMPONENT)" $(if $(RERUN),--rerun,)

pr-monitor: ## Poll one GitHub PR cheaply and emit bounded ChatGPT review handoffs; PR/OWNER/REPO required
	@$(PYTHON) scripts/pr_monitor.py --owner "$(OWNER)" --repo "$(REPO)" --pr "$(PR)" --interval 900 --max-interval 3600

review-budget: ## Decide whether ChatGPT exact-SHA review should run; PR and SNAPSHOT required
	@test -n "$(PR)" || { printf '%s\n' 'ERROR: PR=<number> is required'; exit 2; }
	@test -n "$(SNAPSHOT)" || { printf '%s\n' 'ERROR: SNAPSHOT=<json-path> is required'; exit 2; }
	@$(PYTHON) scripts/review_budget.py decide --pr "$(PR)" --snapshot "$(SNAPSHOT)" --review-kind "$${REVIEW_KIND:-combined}" $(if $(FINAL_CANDIDATE),--final-candidate,)

codex-run: ## Governed CLI invocation; CACHEABLE=1 EXPECT=<literal success criterion> for static read-only reuse
	@test -n "$(TASK)" || { printf '%s\n' 'ERROR: TASK=<bounded task> is required'; exit 2; }
	@$(PYTHON) scripts/codex_budget.py run --task "$(TASK)" --profile "$${PROFILE:-ecommerce-minimal}" $(if $(PATHS),--paths $(PATHS),) $(if $(SINCE),--since "$(SINCE)",) $(if $(STAGED),--staged,) $(if $(CACHEABLE),--cacheable,) $(if $(EXPECT),--expect "$(EXPECT)",)

codex-budget: ## Decide whether the exact current context can reuse a marked Codex result
	@$(PYTHON) scripts/codex_budget.py decide --manifest "$${MANIFEST:-.context/codex-context.json}"

codex-budget-mark: ## Mark RESULT=.context/... reusable only for the exact current context key
	@test -n "$(RESULT)" || { printf '%s\n' 'ERROR: RESULT=.context/<result> is required'; exit 2; }
	@$(PYTHON) scripts/codex_budget.py mark --manifest "$${MANIFEST:-.context/codex-context.json}" --result "$(RESULT)" $(if $(VALIDATED),--validated,) $(if $(READ_ONLY),--read-only,)

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
