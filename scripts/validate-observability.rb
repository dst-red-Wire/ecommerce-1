#!/usr/bin/env ruby
# frozen_string_literal: true

require "yaml"

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

  FORBIDDEN_GENERAL_LOG_COMPONENTS = %w[
    prometheus-server-tsdb
    fluent-bit-general-log-shipper
    opensearch-general-log-store
    data-prepper-general-log-pipeline
  ].freeze

  DEPLOYMENT_COMPONENT_FIELDS = %w[
    infrastructure_collector application_gateway metrics_scraper metrics infrastructure_logs
    application_observability_storage application_observability_ui hyperdx_metadata_store alerts
    notifications dashboards security_pipeline security
  ].freeze

  def load_yaml(path)
    YAML.safe_load(File.read(path), aliases: false) || {}
  rescue Psych::Exception, SystemCallError => e
    raise ArgumentError, "#{path}: #{e.message}"
  end

  def validate(root)
    errors = []
    lock_path = File.join(root, "architecture.lock.yaml")
    lock = load_yaml(lock_path)
    relative_contract = lock.dig("machine_contracts", "observability_topology")
    unless relative_contract == "config/contracts/observability-topology.yaml"
      errors << "architecture.lock.yaml machine_contracts.observability_topology must point to config/contracts/observability-topology.yaml"
      return errors
    end

    contract_path = File.join(root, relative_contract)
    contract = load_yaml(contract_path)
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
      Array(security["forbidden_purposes"]).sort == %w[general-application-logs general-infrastructure-logs].sort

    hyperdx = contract["hyperdx"] || {}
    errors << "HyperDX telemetry must use ClickHouse" unless hyperdx["telemetry_storage"] == "clickhouse"
    errors << "HyperDX metadata MongoDB must be internal-only" unless hyperdx["metadata_store"] == "mongodb-oss-self-hosted" &&
      hyperdx["metadata_scope"] == "hyperdx-internal-only" && hyperdx["business_data_forbidden"] == true

    waves_path = lock.dig("machine_contracts", "deployment_waves")
    waves = load_yaml(File.join(root, waves_path.to_s))
    matching_waves = Array(waves["waves"]).select { |entry| entry["id"] == "50-observability" }
    unless matching_waves.length == 1
      errors << "deployment wave 50-observability must occur exactly once"
      return errors
    end
    wave = matching_waves.first
    components = Array(wave && wave["components"])
    required = DEPLOYMENT_COMPONENT_FIELDS.reject { |field| field == "security" }.map { |field| summary[field] }
    required << "#{summary['security_logs']}-security"
    required << summary["security"]
    missing = required.compact.uniq - components
    errors << "deployment wave 50 missing canonical observability components: #{missing.join(', ')}" unless missing.empty?
    expected_components = required.compact.uniq
    errors << "deployment wave 50 must exactly match canonical observability components" unless components == expected_components
    forbidden_wave = %w[prometheus prometheus-server fluent-bit opensearch-logs]
    active_forbidden = components & forbidden_wave
    errors << "deployment wave 50 activates superseded general observability roles: #{active_forbidden.join(', ')}" unless active_forbidden.empty?

    forbidden = Array(contract.dig("anti_duplication", "forbidden_active_components"))
    errors << "observability anti-duplication guard drift" unless forbidden.sort == FORBIDDEN_GENERAL_LOG_COMPONENTS.sort
    errors
  rescue ArgumentError, TypeError, NoMethodError => e
    ["observability topology structure is invalid: #{e.message}"]
  end
end

if $PROGRAM_NAME == __FILE__
  root = ARGV.fetch(0, File.expand_path("..", __dir__))
  errors = ObservabilityTopologyValidator.validate(root)
  if errors.empty?
    puts "[governance] observability topology: PASS"
  else
    warn errors.map { |error| "[governance] #{error}" }.join("\n")
    exit 1
  end
end
