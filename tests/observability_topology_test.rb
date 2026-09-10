# frozen_string_literal: true

require "fileutils"
require "minitest/autorun"
require "tmpdir"
require "yaml"
require_relative "../scripts/validate-observability"

class ObservabilityTopologyTest < Minitest::Test
  ROOT = File.expand_path("..", __dir__)
  LOCK = YAML.safe_load(File.read(File.join(ROOT, "architecture.lock.yaml")), aliases: false)
  OBSERVABILITY_PATH = LOCK.fetch("machine_contracts").fetch("observability_topology")
  STORAGE_PATH = LOCK.fetch("machine_contracts").fetch("storage_plan")
  WAVES_PATH = LOCK.fetch("machine_contracts").fetch("deployment_waves")

  def test_repository_contract_is_exact
    assert_empty ObservabilityTopologyValidator.validate(ROOT)
  end

  def test_rejects_prometheus_as_primary_tsdb
    with_contract_copy do |root|
      mutate_yaml(root, "architecture.lock.yaml") do |data|
        data["observability"]["metrics"] = "prometheus"
      end
      assert_includes ObservabilityTopologyValidator.validate(root),
                      "architecture.lock.yaml observability summary drift"
    end
  end

  def test_rejects_data_prepper_as_general_log_pipeline
    with_contract_copy do |root|
      mutate_yaml(root, OBSERVABILITY_PATH) do |data|
        data["security_telemetry"]["forbidden_purposes"].delete("general-application-logs")
      end
      assert_includes ObservabilityTopologyValidator.validate(root), "Data Prepper must remain security-only"
    end
  end

  def test_rejects_overlapping_application_gateway
    with_contract_copy do |root|
      mutate_yaml(root, OBSERVABILITY_PATH) do |data|
        data["authorities"]["application_telemetry_gateway"] = "opentelemetry-collector"
      end
      assert_includes ObservabilityTopologyValidator.validate(root), "observability authority map drift"
    end
  end

  def test_rejects_active_stateful_store_without_storage_contract
    with_contract_copy do |root|
      mutate_yaml(root, STORAGE_PATH) { |data| data["engines"].delete("victoriametrics") }
      assert_includes ObservabilityTopologyValidator.validate(root),
                      "active stateful component victoriametrics lacks complete storage contract"
    end
  end

  def test_rejects_incomplete_rpo
    with_contract_copy do |root|
      mutate_yaml(root, STORAGE_PATH) do |data|
        data["engines"]["clickhouse"]["backup"]["rpo"].delete("prod")
      end
      assert_includes ObservabilityTopologyValidator.validate(root), "clickhouse backup RPO is incomplete"
    end
  end

  def test_rejects_minio_as_backup_authority
    with_contract_copy do |root|
      mutate_yaml(root, STORAGE_PATH) do |data|
        data["engines"]["victorialogs"]["backup"]["target"] = "minio-community"
      end
      assert_includes ObservabilityTopologyValidator.validate(root),
                      "victorialogs backup target must be seaweedfs-s3"
    end
  end

  def test_rejects_business_data_in_hyperdx_mongodb
    with_contract_copy do |root|
      mutate_yaml(root, STORAGE_PATH) do |data|
        data["engines"]["mongodb-oss-self-hosted"]["data_scope"]["business_data"] = "allowed"
      end
      assert_includes ObservabilityTopologyValidator.validate(root),
                      "HyperDX MongoDB storage scope must forbid business data"
    end
  end

  def test_rejects_general_logs_in_opensearch_security
    with_contract_copy do |root|
      mutate_yaml(root, STORAGE_PATH) do |data|
        data["engines"]["opensearch-security"]["data_scope"]["forbidden"].delete("general-infrastructure-logs")
      end
      assert_includes ObservabilityTopologyValidator.validate(root),
                      "OpenSearch Security storage scope must remain SIEM-only"
    end
  end

  def test_rejects_missing_active_store_from_deployment_waves
    with_contract_copy do |root|
      mutate_yaml(root, WAVES_PATH) do |data|
        data["waves"].find { |wave| wave["id"] == "50-observability-stateful" }["components"].delete("clickhouse")
      end
      assert_includes ObservabilityTopologyValidator.validate(root),
                      "deployment waves must include active stateful component clickhouse"
    end
  end

  def test_rejects_store_without_seaweedfs_dependency_path
    with_contract_copy do |root|
      mutate_yaml(root, WAVES_PATH) do |data|
        data["waves"].find { |wave| wave["id"] == "48-observability-operators" }["requires"].delete("45-object-storage")
      end
      assert_includes ObservabilityTopologyValidator.validate(root),
                      "SeaweedFS must be healthy before victoriametrics"
    end
  end

  def test_accepts_declaration_reorder_when_requires_graph_is_unchanged
    with_contract_copy do |root|
      mutate_yaml(root, WAVES_PATH) do |data|
        waves = data["waves"]
        object_storage = waves.delete_at(waves.index { |wave| wave["id"] == "45-object-storage" })
        services = waves.index { |wave| wave["id"] == "55-observability-services" }
        waves.insert(services + 1, object_storage)
      end
      assert_empty ObservabilityTopologyValidator.validate(root)
    end
  end

  def test_rejects_observability_consumer_without_stateful_dependency_edge
    with_contract_copy do |root|
      mutate_yaml(root, WAVES_PATH) do |data|
        data["waves"].find { |wave| wave["id"] == "55-observability-services" }["requires"].delete("50-observability-stateful")
      end
      errors = ObservabilityTopologyValidator.validate(root)
      assert_includes errors, "HyperDX must start after ClickHouse"
      assert_includes errors, "Data Prepper Security must start after OpenSearch Security"
      assert_includes errors, "Wazuh must start after OpenSearch Security"
    end
  end

  def test_rejects_new_stateful_store_without_complete_contract
    with_contract_copy do |root|
      mutate_yaml(root, OBSERVABILITY_PATH) do |data|
        data["stateful_storage"]["stores"]["accidental"] = {"component" => "accidental-store", "purpose" => "none"}
      end
      errors = ObservabilityTopologyValidator.validate(root)
      assert_includes errors, "active observability stateful store set drift"
      assert_includes errors, "active stateful component accidental-store lacks complete storage contract"
    end
  end

  def test_rejects_disabled_observability_encryption
    with_contract_copy do |root|
      mutate_yaml(root, STORAGE_PATH) do |data|
        data["engines"]["opensearch-security"]["encryption"] = {"at_rest" => "none", "in_transit" => "none"}
      end
      errors = ObservabilityTopologyValidator.validate(root)
      assert_includes errors, "opensearch-security at-rest encryption must be luks2"
      assert_includes errors, "opensearch-security transport encryption must be tls or tls-mtls"
    end
  end

  def test_rejects_disabled_transport_encryption_default
    with_contract_copy do |root|
      mutate_yaml(root, STORAGE_PATH) do |data|
        data["observability_defaults"]["transport_encryption"] = "optional"
      end
      assert_includes ObservabilityTopologyValidator.validate(root), "observability storage defaults drift"
    end
  end

  def test_rejects_disabled_replica_anti_affinity_default
    with_contract_copy do |root|
      mutate_yaml(root, STORAGE_PATH) do |data|
        data["observability_defaults"]["strict_replica_anti_affinity"] = false
      end
      assert_includes ObservabilityTopologyValidator.validate(root), "observability storage defaults drift"
    end
  end

  def test_rejects_disabled_engine_replica_anti_affinity
    with_contract_copy do |root|
      mutate_yaml(root, STORAGE_PATH) do |data|
        data["engines"]["clickhouse"]["topology"]["anti_affinity"] = "disabled"
      end
      assert_includes ObservabilityTopologyValidator.validate(root),
                      "clickhouse replica anti-affinity must be strict"
    end
  end

  def test_rejects_forbidden_component_in_deployment_waves
    with_contract_copy do |root|
      mutate_yaml(root, WAVES_PATH) do |data|
        data["waves"].find { |wave| wave["id"] == "55-observability-services" }["components"] << "opensearch-general-log-store"
      end
      assert_includes ObservabilityTopologyValidator.validate(root),
                      "forbidden observability components active in deployment waves: opensearch-general-log-store"
    end
  end

  def test_rejects_deployment_wave_cycle
    with_contract_copy do |root|
      mutate_yaml(root, WAVES_PATH) do |data|
        data["waves"].find { |wave| wave["id"] == "45-object-storage" }["requires"] << "55-observability-services"
      end
      assert ObservabilityTopologyValidator.validate(root).any? { |error| error.include?("deployment wave cycle detected") }
    end
  end

  def test_rejects_draft_storage_plan
    with_contract_copy do |root|
      mutate_yaml(root, STORAGE_PATH) { |data| data["status"] = "draft" }
      assert_includes ObservabilityTopologyValidator.validate(root), "storage plan status must be exact"
    end
  end

  def test_rejects_clickhouse_writer_drift
    with_contract_copy do |root|
      mutate_yaml(root, STORAGE_PATH) do |data|
        data["engines"]["clickhouse"]["network"]["writers"] = ["vmagent"]
      end
      assert ObservabilityTopologyValidator.validate(root).any? do |error|
        error.include?("clickhouse network writers drift") && error.include?("rotel")
      end
    end
  end

  def test_rejects_business_data_for_every_observability_store
    %w[victoriametrics victorialogs clickhouse].each do |component|
      with_contract_copy do |root|
        mutate_yaml(root, STORAGE_PATH) do |data|
          data["engines"][component]["data_scope"]["business_data"] = "allowed"
        end
        assert_includes ObservabilityTopologyValidator.validate(root),
                        "#{component} data scope must forbid business data"
      end
    end
  end

  def test_rejects_empty_retention_and_backup_schedule
    with_contract_copy do |root|
      mutate_yaml(root, STORAGE_PATH) do |data|
        data["engines"]["victoriametrics"]["retention"] = {}
        data["engines"]["victoriametrics"]["backup"]["schedule"] = {}
      end
      errors = ObservabilityTopologyValidator.validate(root)
      assert_includes errors, "victoriametrics retention contract is incomplete"
      assert_includes errors, "victoriametrics backup schedule is incomplete"
    end
  end

  def test_rejects_null_backup_objective_value
    with_contract_copy do |root|
      mutate_yaml(root, STORAGE_PATH) do |data|
        data["engines"]["clickhouse"]["backup"]["rpo"]["prod"] = nil
      end
      assert_includes ObservabilityTopologyValidator.validate(root), "clickhouse backup RPO is incomplete"
    end
  end

  def test_rejects_minio_policy_guard_contradiction
    with_contract_copy do |root|
      mutate_yaml(root, STORAGE_PATH) do |data|
        data["policies"]["no_minio_ce"] = false
      end
      errors = ObservabilityTopologyValidator.validate(root)
      assert_includes errors, "storage policy must forbid MinIO CE"
      assert_includes errors, "storage MinIO policy and validation guard must agree"
    end
  end

  def test_rejects_ceph_policy_guard_contradiction
    with_contract_copy do |root|
      mutate_yaml(root, STORAGE_PATH) do |data|
        data["policies"]["no_default_ceph"] = false
      end
      errors = ObservabilityTopologyValidator.validate(root)
      assert_includes errors, "storage policy must reject default Ceph"
      assert_includes errors, "storage Ceph policy and validation guard must agree"
    end
  end

  def test_consumes_observability_contract_path_from_lock
    with_contract_copy do |root|
      alternate = "config/contracts/alternate-observability-topology.yaml"
      FileUtils.cp(File.join(root, OBSERVABILITY_PATH), File.join(root, alternate))
      mutate_yaml(root, alternate) { |data| data["sre_metrics"]["storage"] = "prometheus" }
      mutate_yaml(root, "architecture.lock.yaml") do |data|
        data["machine_contracts"]["observability_topology"] = alternate
      end
      assert_includes ObservabilityTopologyValidator.validate(root), "VictoriaMetrics must own metric storage"
    end
  end

  private

  def with_contract_copy
    Dir.mktmpdir("observability-topology") do |root|
      [
        "architecture.lock.yaml",
        OBSERVABILITY_PATH,
        STORAGE_PATH,
        WAVES_PATH
      ].each do |relative|
        target = File.join(root, relative)
        FileUtils.mkdir_p(File.dirname(target))
        FileUtils.cp(File.join(ROOT, relative), target)
      end
      yield root
    end
  end

  def mutate_yaml(root, relative)
    path = File.join(root, relative)
    data = YAML.safe_load(File.read(path), aliases: false)
    yield data
    File.write(path, YAML.dump(data))
  end
end
