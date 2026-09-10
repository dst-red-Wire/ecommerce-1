#!/usr/bin/env ruby
# frozen_string_literal: true

require "yaml"
require_relative "validate-contract-authority"

module ObservabilityTopologyValidator
  module_function

  EXPECTED_SUMMARY = {
    "telemetry" => "opentelemetry",
    "application_gateway" => "rotel",
    "infrastructure_collector" => "opentelemetry-collector",
    "metrics_protocol" => "prometheus",
    "metrics_scraper" => "vmagent",
    "metrics" => "victoriametrics",
    "infrastructure_logs" => "victorialogs",
    "application_observability_storage" => "clickhouse",
    "application_observability_ui" => "hyperdx",
    "hyperdx_metadata_store" => "mongodb-oss-self-hosted",
    "alerts" => "vmalert",
    "notifications" => "alertmanager",
    "dashboards" => "grafana",
    "security_pipeline" => "data-prepper",
    "security_logs" => "opensearch",
    "security" => "wazuh"
  }.freeze

  EXPECTED_AUTHORITIES = {
    "application_telemetry_gateway" => "rotel",
    "infrastructure_telemetry_collector" => "opentelemetry-collector",
    "metrics_scraper" => "vmagent",
    "metrics_storage" => "victoriametrics",
    "infrastructure_log_storage" => "victorialogs",
    "application_observability_storage" => "clickhouse",
    "application_observability_ui" => "hyperdx",
    "sre_dashboards" => "grafana",
    "rule_evaluation" => "vmalert",
    "notification_routing" => "alertmanager",
    "security_ingest_pipeline" => "data-prepper",
    "security_analytics" => "wazuh",
    "security_search_storage" => "opensearch"
  }.freeze

  EXPECTED_PIPELINES = {
    "traces" => %w[rotel clickhouse hyperdx],
    "logs" => %w[rotel clickhouse hyperdx],
    "metrics" => %w[rotel vmagent victoriametrics]
  }.freeze

  EXPECTED_STATEFUL_STORES = %w[
    victoriametrics
    victorialogs
    clickhouse
    mongodb-oss-self-hosted
    opensearch-security
  ].freeze

  REQUIRED_STORAGE_FIELDS = %w[
    engine deployment_mode storage topology retention backup encryption network data_scope
    operational_authority dependencies failure_behavior environments
  ].freeze

  FORBIDDEN_GENERAL_LOG_COMPONENTS = %w[
    prometheus-server-tsdb
    fluent-bit-general-log-shipper
    opensearch-general-log-store
    data-prepper-general-log-pipeline
  ].freeze

  BACKUP_RESTORE_IDENTITY = "platform-backup-jobs"
  DURATION = /\A[1-9]\d*[hd]\z/
  PERSISTENT_RETENTION = "persistent-until-explicit-deletion"

  def duration?(value)
    value.is_a?(String) && value.match?(DURATION)
  end

  def duration_map?(value, keys = %w[preprod prod])
    value.is_a?(Hash) && value.keys.sort == keys.sort && keys.all? { |key| duration?(value[key]) }
  end

  def retention_contract?(value, keys = %w[preprod prod])
    return value == PERSISTENT_RETENTION if value.is_a?(String)
    return false unless value.is_a?(Hash) && value.keys.sort == keys.sort

    value.values.all? { |entry| duration?(entry) || entry == PERSISTENT_RETENTION }
  end

  def load_yaml(path)
    YAML.safe_load(File.read(path), aliases: false) || {}
  rescue Psych::Exception, SystemCallError => e
    raise ArgumentError, "#{path}: #{e.message}"
  end

  def machine_contract(lock, root, key)
    relative = ContractAuthorityValidator.machine_path(lock, root, key)
    [load_yaml(File.join(root, relative)), relative]
  end

  def wave_components(wave)
    Array(wave["components"]) + Array(wave["parallel_groups"]).flatten + Array(wave["serial_after_parallel"])
  end

  def component_wave_ids(waves)
    wave_ids = {}
    waves.each do |wave|
      wave_components(wave).each { |component| wave_ids[component] = wave["id"] }
    end
    wave_ids
  end

  def wave_dependency_reachable?(waves_by_id, prerequisite_wave_id, consumer_wave_id, visited = {})
    return false if prerequisite_wave_id.nil? || consumer_wave_id.nil? || prerequisite_wave_id == consumer_wave_id
    return false if visited[consumer_wave_id]

    consumer_wave = waves_by_id[consumer_wave_id]
    return false unless consumer_wave

    requirements = Array(consumer_wave["requires"])
    return true if requirements.include?(prerequisite_wave_id)

    next_visited = visited.merge(consumer_wave_id => true)
    requirements.any? do |required_wave_id|
      wave_dependency_reachable?(waves_by_id, prerequisite_wave_id, required_wave_id, next_visited)
    end
  end

  def dependency_ready_before?(waves_by_id, component_waves, prerequisite, consumer)
    wave_dependency_reachable?(waves_by_id, component_waves[prerequisite], component_waves[consumer])
  end

  def validate_stateful_storage(errors, lock, root, contract)
    storage, = machine_contract(lock, root, "storage_plan")
    waves, = machine_contract(lock, root, "deployment_waves")
    stateful = contract["stateful_storage"] || {}

    errors << "observability stateful storage profile drift" unless stateful["profile"] == "observability-stateful-v1"
    errors << "observability stateful storage contract authority drift" unless stateful["contract_authority"] == {"machine_contract" => "storage_plan"}
    errors << "storage plan status must be exact" unless storage["status"] == "exact"
    errors << "SeaweedFS S3 must remain observability backup object authority" unless stateful["backup_object_authority"] == "seaweedfs-s3"
    errors << "PROD observability clusters must be independent per site" unless stateful["prod_placement"] == "per-site-independent" &&
      stateful["stretched_quorum_between_prod_sites"] == "forbidden"
    errors << "observability environment activation drift" unless stateful["environments"] == {
      "mgmt" => "deferred", "preprod" => "required", "prod" => "required"
    }

    stores = (stateful["stores"] || {}).values.map { |entry| entry["component"] }.compact
    errors << "active observability stateful store set drift" unless stores.sort == EXPECTED_STATEFUL_STORES.sort

    storage_class = storage.dig("storage_classes", "localpv-observability") || {}
    errors << "localpv-observability storage class is incomplete" unless storage_class["provisioner"] == "kubernetes.io/no-provisioner" &&
      storage_class["backing_pools"] == %w[localpv-a localpv-b] && storage_class["filesystem"] == "xfs" &&
      storage_class["access_mode"] == "ReadWriteOnce" && storage_class["volume_binding_mode"] == "WaitForFirstConsumer" &&
      storage_class["reclaim_policy"] == "Retain" && storage_class["encryption_at_rest"] == "luks2" &&
      storage_class["xfs_project_quota"] == "required" && storage_class["failure_domain"] == "host-and-site"

    defaults = storage["observability_defaults"] || {}
    errors << "observability storage defaults drift" unless defaults["storage_class"] == "localpv-observability" &&
      defaults["secrets_authority"] == "openbao" && defaults["secret_delivery"] == "external-secrets" &&
      defaults["secrets_in_git"] == "forbidden" && defaults["transport_encryption"] == "required" &&
      defaults["strict_replica_anti_affinity"] == true && defaults["backup_object_authority"] == "seaweedfs-s3" &&
      defaults["backup_execution_authority"] == "rancher-fleet-kubernetes-cronjob" &&
      defaults["prod_backup_failure_domain"] == "opposite-prod-site" && defaults["prod_cluster_scope"] == "per-site" &&
      defaults["stretched_quorum_between_prod_sites"] == "forbidden"

    engines = storage["engines"] || {}
    stores.uniq.each do |component|
      spec = engines[component]
      unless spec.is_a?(Hash)
        errors << "active stateful component #{component} lacks complete storage contract"
        next
      end

      missing = REQUIRED_STORAGE_FIELDS.reject { |field| spec.key?(field) && !spec[field].nil? }
      errors << "active stateful component #{component} missing storage fields: #{missing.join(', ')}" unless missing.empty?
      next unless missing.empty?

      errors << "#{component} must use localpv-observability" unless spec.dig("storage", "class") == "localpv-observability"
      errors << "#{component} environment activation drift" unless spec["environments"] == {
        "mgmt" => "deferred", "preprod" => "required", "prod" => "required"
      }
      errors << "#{component} replica anti-affinity must be strict" unless spec.dig("topology", "anti_affinity") == "strict"
      encryption = spec["encryption"].is_a?(Hash) ? spec["encryption"] : {}
      errors << "#{component} at-rest encryption must be luks2" unless encryption["at_rest"] == "luks2"
      errors << "#{component} transport encryption must be tls or tls-mtls" unless %w[tls tls-mtls].include?(encryption["in_transit"])
      retention_keys = component == "opensearch-security" ? %w[preprod_hot prod_hot prod_snapshots] : %w[preprod prod]
      errors << "#{component} retention contract is incomplete" unless retention_contract?(spec["retention"], retention_keys)
      backup = spec["backup"] || {}
      errors << "#{component} backup target must be seaweedfs-s3" unless backup["target"] == "seaweedfs-s3"
      %w[schedule retention rpo rto].each do |field|
        label = %w[rpo rto].include?(field) ? field.upcase : field
        errors << "#{component} backup #{label} is incomplete" unless duration_map?(backup[field])
      end
      errors << "#{component} restore validation is required" unless backup["restore_validation"] == "required"
      errors << "#{component} public storage access is forbidden" unless spec.dig("network", "public_access") == "forbidden"
      errors << "#{component} backup jobs require read access" unless Array(spec.dig("network", "readers")).include?(BACKUP_RESTORE_IDENTITY)
      errors << "#{component} restore jobs require write access" unless Array(spec.dig("network", "writers")).include?(BACKUP_RESTORE_IDENTITY)
      errors << "#{component} desired-state authority must remain Rancher Fleet" unless spec.dig("operational_authority", "desired_state") == "rancher-fleet"
      unless component == "opensearch-security" || spec.dig("data_scope", "business_data") == "forbidden"
        errors << "#{component} data scope must forbid business data"
      end
    end

    vm = engines["victoriametrics"] || {}
    errors << "VictoriaMetrics HA topology drift" unless vm.dig("topology", "vmstorage") == 3 && vm.dig("topology", "replication_factor") == 2

    vl = engines["victorialogs"] || {}
    errors << "VictoriaLogs must declare sharding without hidden replication" unless vl.dig("topology", "vlstorage") == 3 &&
      vl.dig("topology", "replication") == "none-sharded" && vl.dig("failure_behavior", "missing_vlstorage_query") == "fail-closed"

    ch = engines["clickhouse"] || {}
    errors << "ClickHouse topology drift" unless ch.dig("topology", "shards") == 1 &&
      ch.dig("topology", "replicas_per_shard") == 3 && ch.dig("topology", "keeper_nodes") == 3

    mongo = engines["mongodb-oss-self-hosted"] || {}
    errors << "HyperDX MongoDB storage scope must forbid business data" unless mongo.dig("topology", "replica_set_members") == 3 &&
      mongo.dig("data_scope", "hyperdx_internal_only") == true && mongo.dig("data_scope", "business_data") == "forbidden" &&
      mongo.dig("network", "ecommerce_services") == "forbidden"

    security = engines["opensearch-security"] || {}
    forbidden_purposes = Array(security.dig("data_scope", "forbidden"))
    errors << "OpenSearch Security storage scope must remain SIEM-only" unless security.dig("topology", "cluster_manager_data_nodes") == 3 &&
      security.dig("topology", "index_replicas") == 1 &&
      %w[general-application-logs general-infrastructure-logs business-data].all? { |purpose| forbidden_purposes.include?(purpose) }

    authorities = contract["authorities"] || {}
    metrics = contract["sre_metrics"] || {}
    logs = contract["infrastructure_logs"] || {}
    security_telemetry = contract["security_telemetry"] || {}
    expected_network = {
      "victoriametrics" => {
        "writers" => [metrics["scraper"], BACKUP_RESTORE_IDENTITY],
        "readers" => [metrics["dashboard_consumer"], metrics["rule_evaluator"], BACKUP_RESTORE_IDENTITY]
      },
      "victorialogs" => {
        "writers" => [logs["collector"], BACKUP_RESTORE_IDENTITY],
        "readers" => [logs["dashboard_consumer"], logs["rule_evaluator"], BACKUP_RESTORE_IDENTITY]
      },
      "clickhouse" => {
        "writers" => [authorities["application_telemetry_gateway"], BACKUP_RESTORE_IDENTITY],
        "readers" => [authorities["application_observability_ui"], BACKUP_RESTORE_IDENTITY]
      },
      "mongodb-oss-self-hosted" => {
        "writers" => [authorities["application_observability_ui"], BACKUP_RESTORE_IDENTITY],
        "readers" => [authorities["application_observability_ui"], BACKUP_RESTORE_IDENTITY]
      },
      "opensearch-security" => {
        "writers" => [security_telemetry["deployment_component"], BACKUP_RESTORE_IDENTITY],
        "readers" => [security_telemetry["analytics"], BACKUP_RESTORE_IDENTITY]
      }
    }
    expected_network.each do |component, expected|
      network = engines.dig(component, "network") || {}
      %w[writers readers].each do |direction|
        expected_identities = Array(expected[direction]).compact.sort
        actual_identities = Array(network[direction]).compact.sort
        unless actual_identities == expected_identities
          errors << "#{component} network #{direction} drift: expected #{expected_identities.inspect}, got #{actual_identities.inspect}"
        end
      end
    end

    ContractAuthorityValidator.validate_dag(errors, waves)
    wave_list = Array(waves["waves"])
    waves_by_id = wave_list.to_h { |wave| [wave["id"], wave] }
    component_waves = component_wave_ids(wave_list)
    stores.uniq.each do |component|
      errors << "deployment waves must include active stateful component #{component}" unless component_waves.key?(component)
      errors << "SeaweedFS must be healthy before #{component}" unless dependency_ready_before?(waves_by_id, component_waves, "seaweedfs", component)
    end
    errors << "MongoDB Community Operator must precede HyperDX MongoDB" unless dependency_ready_before?(waves_by_id, component_waves, "mongodb-community-operator", "mongodb-oss-self-hosted")
    errors << "OpenSearch Operator must precede OpenSearch Security" unless dependency_ready_before?(waves_by_id, component_waves, "opensearch-operator", "opensearch-security")
    errors << "HyperDX must start after ClickHouse" unless dependency_ready_before?(waves_by_id, component_waves, "clickhouse", "hyperdx")
    errors << "HyperDX must start after MongoDB" unless dependency_ready_before?(waves_by_id, component_waves, "mongodb-oss-self-hosted", "hyperdx")
    errors << "Data Prepper Security must start after OpenSearch Security" unless dependency_ready_before?(waves_by_id, component_waves, "opensearch-security", "data-prepper-security")
    errors << "Wazuh must start after OpenSearch Security" unless dependency_ready_before?(waves_by_id, component_waves, "opensearch-security", "wazuh")

    active_wave_components = wave_list.flat_map { |wave| wave_components(wave) }
    forbidden_active = Array(contract.dig("anti_duplication", "forbidden_active_components"))
    present_forbidden = forbidden_active & active_wave_components
    errors << "forbidden observability components active in deployment waves: #{present_forbidden.sort.join(', ')}" unless present_forbidden.empty?

    policies = storage["policies"] || {}
    validation = storage["validation"] || {}
    errors << "storage policy must forbid MinIO CE" unless policies["no_minio_ce"] == true
    errors << "storage MinIO policy and validation guard must agree" unless policies["no_minio_ce"] == validation["reject_minio_ce"]
    errors << "storage policy must reject default Ceph" unless policies["no_default_ceph"] == true
    errors << "storage Ceph policy and validation guard must agree" unless policies["no_default_ceph"] == validation["reject_default_ceph"]
    errors << "observability LocalPV isolation validation drift" unless validation["reject_static_pv_reuse"] == true &&
      validation["reject_localpv_path_reuse"] == true && validation["require_xfs_project_quota"] == true &&
      validation["allow_distinct_pvs_on_same_backing_nvme"] == true &&
      validation["require_same_engine_replica_failure_domain_separation"] == true &&
      validation["reject_default_ceph"] == true && validation["reject_minio_ce"] == true
  end

  def validate(root)
    errors = []
    lock_path = File.join(root, "architecture.lock.yaml")
    lock = load_yaml(lock_path)
    contract, = machine_contract(lock, root, "observability_topology")
    errors << "observability topology status must be exact" unless contract["status"] == "exact"

    summary = lock["observability"] || {}
    errors << "architecture.lock.yaml observability summary drift" unless summary == EXPECTED_SUMMARY

    authorities = contract["authorities"] || {}
    errors << "observability authority map drift" unless authorities == EXPECTED_AUTHORITIES

    application = contract["application_telemetry"] || {}
    errors << "application instrumentation must be opentelemetry" unless application["instrumentation"] == "opentelemetry"
    errors << "application telemetry transport must be otlp" unless application["transport"] == "otlp"
    errors << "application telemetry gateway must be rotel" unless application["gateway"] == "rotel"
    errors << "application telemetry pipelines drift" unless application["pipelines"] == EXPECTED_PIPELINES

    metrics = contract["sre_metrics"] || {}
    errors << "vmagent must scrape SRE metrics" unless metrics["scraper"] == "vmagent"
    errors << "VictoriaMetrics must own metric storage" unless metrics["storage"] == "victoriametrics"
    errors << "Prometheus must remain exposition protocol only" unless metrics["exposition_protocol"] == "prometheus"
    errors << "vmalert must evaluate SRE metric rules" unless metrics["rule_evaluator"] == "vmalert"
    errors << "Alertmanager must route metric notifications" unless metrics["notification_router"] == "alertmanager"

    logs = contract["infrastructure_logs"] || {}
    errors << "OpenTelemetry Collector must collect infrastructure logs" unless logs["collector"] == "opentelemetry-collector"
    errors << "VictoriaLogs must own infrastructure log storage" unless logs["storage"] == "victorialogs"

    security = contract["security_telemetry"] || {}
    errors << "Data Prepper must remain security-only" unless security["pipeline"] == "data-prepper" &&
      security["deployment_component"] == "data-prepper-security" &&
      Array(security["forbidden_purposes"]).sort == %w[general-application-logs general-infrastructure-logs].sort

    hyperdx = contract["hyperdx"] || {}
    errors << "HyperDX telemetry must use ClickHouse" unless hyperdx["telemetry_storage"] == "clickhouse"
    errors << "HyperDX metadata MongoDB must be internal-only" unless hyperdx["metadata_store"] == "mongodb" &&
      hyperdx["metadata_deployment"] == "mongodb-oss-self-hosted" &&
      hyperdx["metadata_scope"] == "hyperdx-internal-only" && hyperdx["business_data_forbidden"] == true

    forbidden = Array(contract.dig("anti_duplication", "forbidden_active_components"))
    errors << "observability anti-duplication guard drift" unless forbidden.sort == FORBIDDEN_GENERAL_LOG_COMPONENTS.sort

    validate_stateful_storage(errors, lock, root, contract)
    errors
  rescue ArgumentError, TypeError, NoMethodError => e
    ["observability topology structure is invalid: #{e.message}"]
  end
end

if $PROGRAM_NAME == __FILE__
  root = ARGV.fetch(0, File.expand_path("..", __dir__))
  errors = ContractAuthorityValidator.validate(root) + ObservabilityTopologyValidator.validate(root)
  if errors.empty?
    puts "[governance] observability topology: PASS"
  else
    warn errors.map { |error| "[governance] #{error}" }.join("\n")
    exit 1
  end
end
