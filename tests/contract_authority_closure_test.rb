# frozen_string_literal: true

require "minitest/autorun"
require "fileutils"
require "tmpdir"
require "yaml"
require_relative "../scripts/validate-contract-authority"

class ContractAuthorityClosureTest < Minitest::Test
  ROOT = File.expand_path("..", __dir__)

  def load_yaml(path)
    YAML.safe_load(File.read(File.join(ROOT, path)), aliases: false)
  end

  def test_exact_m0_to_m9_graph_passes
    errors = []
    ContractAuthorityValidator.validate_milestone_dependencies(errors, load_yaml("architecture.lock.yaml"))
    assert_empty errors
  end

  def test_m9_dependency_drift_is_rejected
    lock = load_yaml("architecture.lock.yaml")
    lock["milestone_dependencies"]["M9-prod-ab"] = []
    errors = []
    ContractAuthorityValidator.validate_milestone_dependencies(errors, lock)
    assert errors.any? { |error| error.include?("M9-prod-ab dependency drift") }
  end

  def test_every_wave_component_has_exactly_one_execution_binding
    waves = load_yaml("config/infrastructure/deployment-waves.yaml")
    errors = []
    ContractAuthorityValidator.validate_dag(errors, waves)
    assert_empty errors

    component = waves.fetch("component_execution_bindings").keys.first
    waves["component_execution_bindings"].delete(component)
    errors = []
    ContractAuthorityValidator.validate_dag(errors, waves)
    assert errors.any? { |error| error.include?("bindings must cover every wave component exactly") }
  end

  def test_unknown_execution_profile_is_rejected
    waves = load_yaml("config/infrastructure/deployment-waves.yaml")
    waves["component_execution_bindings"]["product"] = "missing-profile"
    errors = []
    ContractAuthorityValidator.validate_dag(errors, waves)
    assert errors.any? { |error| error.include?("unknown profile missing-profile") }
  end

  def test_each_deployment_safety_rule_mutation_fails_closed
    ContractAuthorityValidator::REQUIRED_DEPLOYMENT_RULES.each_key do |rule|
      waves = load_yaml("config/infrastructure/deployment-waves.yaml")
      waves.fetch("rules")[rule] = false
      errors = []
      ContractAuthorityValidator.validate_dag(errors, waves)
      assert errors.any? { |error| error.include?(rule) }, rule
    end
  end

  def test_unknown_storage_dependency_is_rejected
    storage = load_yaml("config/infrastructure/storage-plan.yaml")
    waves = load_yaml("config/infrastructure/deployment-waves.yaml")
    storage["engines"]["victoriametrics"]["dependencies"] << "unknown-store"
    errors = []
    ContractAuthorityValidator.validate_storage_dependency_edges(errors, storage, waves)
    assert errors.any? { |error| error.include?("unknown-store") && error.include?("not located") }
  end

  def test_storage_classes_and_active_stateful_contracts_are_complete
    storage = load_yaml("config/infrastructure/storage-plan.yaml")
    errors = []
    ContractAuthorityValidator.validate_storage_classes(errors, storage)
    ContractAuthorityValidator.validate_stateful_contracts(errors, storage)
    assert_empty errors
  end

  def test_superseded_component_is_rejected_generically
    lock = load_yaml("architecture.lock.yaml")
    waves = load_yaml("config/infrastructure/deployment-waves.yaml")
    waves["waves"].first["components"] << "fluxcd"
    errors = []
    ContractAuthorityValidator.validate_superseded_components(errors, lock, waves)
    assert errors.any? { |error| error.include?("fluxcd") }
  end

  def test_trust_zone_contract_covers_all_active_components
    lock = load_yaml("architecture.lock.yaml")
    waves = load_yaml("config/infrastructure/deployment-waves.yaml")
    errors = []
    ContractAuthorityValidator.validate_trust_zones(errors, lock, ROOT, waves)
    assert_empty errors
  end

  def test_each_trust_zone_safety_rule_mutation_fails_closed
    lock = load_yaml("architecture.lock.yaml")
    waves = load_yaml("config/infrastructure/deployment-waves.yaml")
    ContractAuthorityValidator::REQUIRED_TRUST_ZONE_RULES.each_key do |rule|
      Dir.mktmpdir do |root|
        FileUtils.cp_r(Dir.glob(File.join(ROOT, "*")), root)
        path = File.join(root, "config/contracts/security-trust-zones.yaml")
        contract = YAML.safe_load(File.read(path), aliases: false)
        contract.fetch("rules")[rule] = false
        File.write(path, YAML.dump(contract))
        errors = []
        ContractAuthorityValidator.validate_trust_zones(errors, lock, root, waves)
        assert errors.any? { |error| error.include?(rule) }, rule
      end
    end
  end
  def test_keycloak_database_and_strimzi_operator_mutations_fail_closed
    storage = load_yaml("config/infrastructure/storage-plan.yaml")
    waves = load_yaml("config/infrastructure/deployment-waves.yaml")
    storage["engines"].delete("keycloak-database")
    errors = []
    ContractAuthorityValidator.validate_stateful_contracts(errors, storage)
    assert errors.any? { |error| error.include?("keycloak-database lacks complete storage contract") }

    waves["component_execution_bindings"]["strimzi-operator"] = "stateful"
    errors = []
    ContractAuthorityValidator.validate_dag(errors, waves)
    assert errors.any? { |error| error.include?("Strimzi operator execution binding") }
  end

  def test_strimzi_operator_dependency_must_be_in_an_earlier_wave
    storage = load_yaml("config/infrastructure/storage-plan.yaml")
    waves = load_yaml("config/infrastructure/deployment-waves.yaml")
    operator_wave = waves["waves"].find { |wave| wave["id"] == "59-messaging-operators" }
    stateful_wave = waves["waves"].find { |wave| wave["id"] == "60-stateful" }
    operator_wave["components"].delete("strimzi-operator")
    stateful_wave["parallel_groups"].first << "strimzi-operator"
    errors = []
    ContractAuthorityValidator.validate_storage_dependency_edges(errors, storage, waves)
    assert errors.any? { |error| error.include?("strimzi-operator must be ready in an earlier wave") }
  end

  def test_keycloak_backup_must_survive_preprod_jit_destroy
    lock = load_yaml("architecture.lock.yaml")
    storage = load_yaml("config/infrastructure/storage-plan.yaml")
    storage.dig("engines", "keycloak-database", "backup")["targets"]["prod"] = "preprod-jit-external-archive"
    errors = []
    ContractAuthorityValidator.validate_resilience_binding(errors, lock, ROOT, storage)
    assert errors.any? { |error| error.include?("keycloak-database backup targets must distinguish") }
  end

  def test_environment_aware_database_backup_mutations_fail_closed
    lock = load_yaml("architecture.lock.yaml")
    %w[keycloak-database lakefs-metadata-cnpg mlflow-metadata-cnpg].each do |component|
      {
        "prod targets PREPROD" => ["targets", {"preprod" => "preprod-jit-external-archive", "prod" => "preprod-jit-external-archive"}],
        "PREPROD stays in JIT" => ["target_failure_domains", {"preprod" => "preprod-jit", "prod" => "opposite-prod-site"}],
        "failure domains swapped" => ["target_failure_domains", {"preprod" => "opposite-prod-site", "prod" => "external-to-preprod-jit"}],
        "ambiguous target" => ["targets", "preprod-jit-external-archive"]
      }.each do |label, (field, value)|
        storage = load_yaml("config/infrastructure/storage-plan.yaml")
        storage.dig("engines", component, "backup")[field] = value
        errors = []
        ContractAuthorityValidator.validate_resilience_binding(errors, lock, ROOT, storage)
        assert errors.any? { |error| error.include?(component) && error.include?(field.start_with?("target_failure") ? "failure" : "target") }, "#{component}: #{label}"
      end
    end
  end

  def test_seaweedfs_preprod_backup_target_and_teardown_gate_mutations_fail_closed
    lock = load_yaml("architecture.lock.yaml")
    {
      "targets" => {"preprod" => "opposite-prod-site", "prod" => "opposite-prod-site"},
      "destroy_without_verified_archive" => "allowed"
    }.each do |field, value|
      storage = load_yaml("config/infrastructure/storage-plan.yaml")
      storage.dig("engines", "seaweedfs", "backup")[field] = value
      errors = []
      ContractAuthorityValidator.validate_resilience_binding(errors, lock, ROOT, storage)
      assert errors.any? { |error| error.include?("SeaweedFS") && error.include?(field.split('_').first) }, field
    end
  end

end
