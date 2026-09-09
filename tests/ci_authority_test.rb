# frozen_string_literal: true

require "fileutils"
require "json"
require "minitest/autorun"
require "tmpdir"
require "yaml"
require_relative "../scripts/validate-contract-authority"

class CIAuthorityTest < Minitest::Test
  ROOT = File.expand_path("..", __dir__)
  REQUIRED_TEKTON = %w[
    platform/tekton/kustomization.yaml
    platform/tekton/tasks/source-checkout.yaml
    platform/tekton/tasks/global-gates.yaml
    platform/tekton/tasks/affected-components.yaml
    platform/tekton/tasks/component-gates.yaml
    platform/tekton/tasks/finalize-evidence.yaml
    platform/tekton/tasks/frontend-gates.yaml
    platform/tekton/tasks/go-service-gates.yaml
    platform/tekton/tasks/platform-gates.yaml
    platform/tekton/pipelines/global.yaml
    platform/tekton/pipelines/frontend.yaml
    platform/tekton/pipelines/go-service.yaml
    platform/tekton/pipelines/platform.yaml
    platform/tekton/pipelines/affected.yaml
    platform/tekton/triggers/README.md
  ].freeze

  def read(relative) = File.read(File.join(ROOT, relative))
  def yaml(relative) = YAML.safe_load(read(relative))
  def machine_contract_path(key)
    ContractAuthorityValidator.machine_path(yaml("architecture.lock.yaml"), ROOT, key)
  end

  def test_single_control_plane_authorities
    lock = yaml("architecture.lock.yaml")
    topology = yaml(machine_contract_path("ci_topology"))
    assert_equal "tekton", lock.dig("platform", "ci")
    assert_equal "tekton", lock.dig("management_plane", "ci")
    assert_equal "rancher-fleet", lock.dig("platform", "gitops")
    assert_equal "gitea", topology.dig("authorities", "forge")
    assert_equal "tekton", topology.dig("authorities", "ci")
    assert_equal "rancher-fleet", topology.dig("authorities", "gitops_cd")
    assert_equal true, topology.dig("repository", "affected_only")
    assert_equal false, topology.dig("gitea_actions", "ci_authority")
    assert_equal false, topology.dig("gitea_actions", "cd_authority")
  end

  def test_developer_accelerators_are_not_control_planes
    accelerators = yaml(machine_contract_path("ci_topology")).fetch("developer_accelerators")
    assert_equal %w[bazel nx turborepo], accelerators.keys.sort
    accelerators.each do |name, contract|
      assert_equal false, contract["source_of_truth"], name
      assert_equal false, contract["ci_authority"], name
      assert_equal false, contract["may_deploy"], name
    end
  end

  def test_ansible_first_developer_automation_contract
    automation = yaml(machine_contract_path("ci_topology")).fetch("developer_automation")
    assert_equal "ansible", automation.fetch("state_reconciliation")
    assert_equal "python", automation.fetch("stateless_controller")
    assert_equal "forbidden", automation.fetch("shell_policy")
    assert_equal true, automation.fetch("shell_state_mutation_forbidden")
    assert_equal true, automation.fetch("tekton_remains_ci_authority")
  end

  def test_repository_has_no_shell_automation
    candidates = `git -C #{ROOT} ls-files --cached --others --exclude-standard -- '*.sh'`.split("\n").reject(&:empty?)
    worktree_shell = candidates.select { |relative| File.file?(File.join(ROOT, relative)) }
    assert_empty worktree_shell
    refute_includes read("BUILD.bazel"), "sh_binary("
    REQUIRED_TEKTON.grep(/\.yaml\z/).each do |relative|
      content = read(relative)
      refute_match(%r{scripts/[^\s'\"]+\.sh\b}, content, relative)
      refute_includes content, "#!/bin/sh", relative
      refute_includes content, "#!/usr/bin/env bash", relative
    end
  end

  def test_parallel_ci_configuration_is_absent
    %w[.woodpecker/ci.yaml .gitlab-ci.yml Jenkinsfile .drone.yml].each do |relative|
      refute File.exist?(File.join(ROOT, relative)), relative
    end
    assert_empty Dir[File.join(ROOT, ".github/workflows/*.{yml,yaml}")]
  end

  def test_tekton_pipeline_classes_are_present_and_do_not_use_latest
    REQUIRED_TEKTON.each { |relative| assert File.file?(File.join(ROOT, relative)), relative }
    manifests = REQUIRED_TEKTON.grep(/\.yaml\z/).map { |relative| read(relative) }.join("\n")
    refute_match(/image:\s*\S+:latest\b/, manifests)
  end

  def test_tekton_trigger_runtime_prerequisites_are_fail_closed
    topology = yaml(machine_contract_path("ci_topology"))
    runtime_path = topology.dig("trigger_flow", "runtime_prerequisites_contract")
    assert_equal "config/contracts/tekton-trigger-runtime.yaml", runtime_path
    runtime = yaml(runtime_path)
    assert_equal "exact-prerequisites", runtime.fetch("status")
    assert_equal "tekton.dev/v1", runtime.dig("api_contract", "pipelines")
    assert_equal "triggers.tekton.dev/v1beta1", runtime.dig("api_contract", "triggers")
    assert_equal true, runtime.dig("api_contract", "crds_must_be_proven_before_activation")
    assert_equal "harbor", runtime.dig("runner_image", "registry_authority")
    assert_equal true, runtime.dig("runner_image", "immutable_digest_required")
    assert_equal true, runtime.dig("runner_image", "default_forbidden")
    assert_equal true, runtime.dig("identity", "event_listener_service_account", "least_privilege")
    assert_equal true, runtime.dig("identity", "event_listener_service_account", "wildcard_rbac_forbidden")
    assert_equal "openbao-via-eso", runtime.dig("webhook_authentication", "secret", "source")
    assert_equal true, runtime.dig("webhook_authentication", "secret", "plaintext_in_git_forbidden")
    assert_equal true, runtime.dig("network", "default_deny_required")
    assert_equal "blocked-until-prerequisites-proven", runtime.dig("activation", "trigger_manifests")
    assert_equal false, runtime.dig("activation", "static_contract_is_runtime_proof")
  end

  def test_frontend_ci_uses_declared_pnpm_workspace
    package = JSON.parse(read("frontend/package.json"))
    assert_match(/\Apnpm@\d/, package.fetch("packageManager"))
    assert File.file?(File.join(ROOT, "frontend/pnpm-lock.yaml"))
    assert File.file?(File.join(ROOT, "frontend/pnpm-workspace.yaml"))
    refute File.exist?(File.join(ROOT, "frontend/package-lock.json"))
    controller = read("scripts/repoctl.py")
    refute_match(/\bnpm ci\b/, controller)
    refute_includes controller, "package-lock.json"
  end

  def test_governance_documentation_regressions_run_in_governance
    assert system("python3", File.join(ROOT, "tests/test_governance_documentation.py"))
  end
end

class StoragePlanGovernanceTest < Minitest::Test
  ROOT = File.expand_path("..", __dir__)
  REQUIRED_MLOPS_METADATA_FIELDS = %w[
    engine deployment_mode storage topology retention backup network data_scope encryption
    operational_authority dependencies failure_behavior environments
  ].freeze

  def test_dedicated_mlops_metadata_storage_contracts_are_complete
    lock = YAML.safe_load(File.read(File.join(ROOT, "architecture.lock.yaml")), aliases: false)
    storage_path = ContractAuthorityValidator.machine_path(lock, ROOT, "storage_plan")
    resilience_path = ContractAuthorityValidator.machine_path(lock, ROOT, "resilience_governance")
    storage = YAML.safe_load(File.read(File.join(ROOT, storage_path)), aliases: false)
    resilience = YAML.safe_load(File.read(File.join(ROOT, resilience_path)), aliases: false)
    profile = resilience.dig("profiles", "mlops-metadata-cnpg")
    assert_equal 5, storage.fetch("version")
    assert_equal "exact", storage.fetch("status")
    assert_equal "exact", resilience.fetch("status")
    refute_nil profile
    engines = storage.fetch("engines")

    {"lakefs-metadata-cnpg" => "lakefs", "mlflow-metadata-cnpg" => "mlflow"}.each do |component, consumer|
      spec = engines.fetch(component)
      assert_empty REQUIRED_MLOPS_METADATA_FIELDS - spec.keys, component
      assert_equal "cloudnativepg-postgresql", spec.fetch("engine"), component
      assert_equal "cloudnativepg", spec.fetch("deployment_mode"), component
      assert_equal "localpv", spec.dig("storage", "class"), component
      assert_equal "ReadWriteOnce", spec.dig("storage", "access_mode"), component
      assert_equal({"preprod" => 3, "prod_per_site" => 3}, spec.dig("topology", "instances"), component)
      assert_equal "strict", spec.dig("topology", "anti_affinity"), component
      assert_equal "single-writer-home-site", spec.dig("topology", "prod_write_authority"), component
      assert_equal "barman-pitr-compatible", spec.dig("backup", "method"), component
      assert_equal "seaweedfs-s3", spec.dig("backup", "target"), component
      assert_equal "independent-from-source-site", spec.dig("backup", "target_failure_domain"), component
      assert_equal profile.fetch("schedule"), spec.dig("backup", "schedule"), component
      assert_equal profile.fetch("retention"), spec.dig("backup", "retention"), component
      assert_equal({"machine_contract" => "resilience_governance", "profile" => "mlops-metadata-cnpg"},
                   spec.dig("backup", "objectives_authority"), component)
      assert_equal "forbidden", spec.dig("backup", "local_objective_override"), component
      %w[rpo rto].each do |objective|
        assert_equal profile.fetch(objective), spec.dig("backup", objective), "#{component} #{objective}"
      end
      assert_equal profile.fetch("restore_validation"), spec.dig("backup", "restore_validation"), component
      assert_equal [consumer], spec.dig("network", "writers"), component
      assert_equal [consumer], spec.dig("network", "readers"), component
      assert_equal "forbidden", spec.dig("network", "public_access"), component
      assert_equal "forbidden", spec.dig("data_scope", "business_data"), component
      assert_equal "required", spec.dig("encryption", "in_transit"), component
      assert_equal "rancher-fleet", spec.dig("operational_authority", "desired_state"), component
      assert_equal "cloudnativepg", spec.dig("operational_authority", "database_operator"), component
      assert_includes spec.fetch("dependencies"), "cloudnativepg", component
      assert_includes spec.fetch("dependencies"), "seaweedfs", component
      assert_equal "fail-closed", spec.dig("failure_behavior", "quorum_loss"), component
      assert_equal "forbidden", spec.dig("failure_behavior", "empty_reinitialization"), component
      assert_equal({"mgmt" => "deferred", "preprod" => "required", "prod" => "required"},
                   spec.fetch("environments"), component)
    end
  end
end

class DeploymentWaveAuthorityTest < Minitest::Test
  def base_contract
    {
      "status" => "exact",
      "graph_policy" => {
        "root_wave" => "root",
        "unique_wave_ids_required" => true,
        "requires_must_resolve" => true,
        "cycles_forbidden" => true,
        "unreachable_waves_forbidden" => true
      },
      "execution_policy" => {"default" => ContractAuthorityValidator::REQUIRED_EXECUTION_POLICY.dup},
      "waves" => [
        {"id" => "root", "requires" => [], "components" => ["foundation"]},
        {"id" => "a", "requires" => ["root"], "components" => ["store-a"]},
        {"id" => "b", "requires" => ["a"], "components" => ["consumer-b"]}
      ]
    }
  end

  def validate(contract)
    errors = []
    ContractAuthorityValidator.validate_dag(errors, contract)
    errors
  end

  def test_rejects_unknown_wave_dependency
    contract = base_contract
    contract["waves"].last["requires"] = ["missing"]
    assert validate(contract).any? { |error| error.include?("unknown dependency missing") }
  end

  def test_rejects_wave_cycle
    contract = base_contract
    contract["waves"].first["requires"] = ["b"]
    assert validate(contract).any? { |error| error.include?("cycle detected") }
  end

  def test_rejects_duplicate_wave_ids_and_components
    contract = base_contract
    contract["waves"] << {"id" => "a", "requires" => ["root"], "components" => ["store-a"]}
    errors = validate(contract)
    assert errors.any? { |error| error.include?("ids must be unique") }
    assert errors.any? { |error| error.include?("appears in multiple waves") }
  end

  def test_rejects_unreachable_wave
    contract = base_contract
    contract["waves"] << {"id" => "orphan", "requires" => [], "components" => ["orphan-component"]}
    assert validate(contract).any? { |error| error.include?("unreachable from root") }
  end
end

class MilestoneAuthorityTest < Minitest::Test
  def canonical_lock
    YAML.safe_load(File.read(File.join(File.expand_path("..", __dir__), "architecture.lock.yaml")), aliases: false)
  end

  def validate(lock)
    errors = []
    ContractAuthorityValidator.validate_milestone_dependencies(errors, lock)
    errors
  end

  def test_m3_depends_on_m25_but_not_m2
    lock = canonical_lock
    assert_equal ["M2-5-persistent-mgmt-bootstrap"],
                 lock.fetch("milestone_dependencies").fetch("M3-preprod-infrastructure")
    assert_empty validate(lock)
  end

  def test_rejects_m2_as_m3_prerequisite
    lock = canonical_lock
    lock["milestone_dependencies"]["M3-preprod-infrastructure"] << "M2-golden-service-product"
    assert_includes validate(lock), "milestone M3-preprod-infrastructure dependency drift"
  end
end

class MachineContractExactStatusTest < Minitest::Test
  def test_rejects_draft_locked_machine_contract
    Dir.mktmpdir("machine-contract-status") do |root|
      relative = "config/contracts/example.yaml"
      absolute = File.join(root, relative)
      FileUtils.mkdir_p(File.dirname(absolute))
      File.write(absolute, "version: 1\nstatus: draft\n")
      lock = {"machine_contracts" => {"example" => relative}}
      errors = []
      ContractAuthorityValidator.validate_exact_contracts(errors, lock, root)
      assert_includes errors, "machine contract example must have status exact"
    end
  end
end
