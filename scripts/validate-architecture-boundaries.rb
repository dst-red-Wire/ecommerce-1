#!/usr/bin/env ruby
# frozen_string_literal: true

require "yaml"

ROOT_DEFAULT = File.expand_path("..", __dir__)

module ArchitectureBoundariesValidator
  CONTRACT_ROLES = {
    identity: "identity_boundary_policy",
    edge: "edge_policy_authority",
    cert: "certificate_authority_policy",
    secret: "secret_delivery_policy",
    dns: "dns_authority_policy",
    time: "time_authority_policy",
    rollout: "progressive_delivery_policy",
    telemetry: "telemetry_data_policy",
    rate: "rate_limit_policy",
    commerce: "commerce_transaction_policy",
    egress: "egress_policy",
    egress_runtime: "egress_runtime_policy",
    resilience: "service_resilience_policy",
    mesh: "service_mesh_policy"
  }.freeze

  module_function

  def load_yaml(root, relative)
    YAML.safe_load(File.read(File.join(root, relative)), aliases: false) || {}
  rescue Psych::Exception => e
    raise "#{relative} invalid YAML: #{e.message}"
  rescue SystemCallError => e
    raise "#{relative} cannot be loaded: #{e.message}"
  end

  def validate(root)
    errors = []
    lock = load_yaml(root, "architecture.lock.yaml")
    registry = lock.fetch("machine_contracts", {})
    paths = CONTRACT_ROLES.transform_values do |role|
      path = registry[role]
      raise "architecture.lock.yaml machine_contracts.#{role} must be declared" unless path.is_a?(String) && !path.strip.empty?
      path
    end
    data = paths.transform_values { |contract_path| load_yaml(root, contract_path) }
    identity = data[:identity]
    edge = data[:edge]
    cert = data[:cert]
    secret = data[:secret]
    dns = data[:dns]
    time = data[:time]
    rollout = data[:rollout]
    telemetry = data[:telemetry]
    rate = data[:rate]
    commerce = data[:commerce]
    egress = data[:egress]
    egress_runtime = data[:egress_runtime]
    resilience = data[:resilience]
    mesh = data[:mesh]

    errors << "human identity authority must be keycloak" unless identity.dig("authorities", "human_identity", "authority") == "keycloak"
    errors << "workload identity authority must be spire" unless identity.dig("authorities", "workload_identity", "authority") == "spire"
    errors << "edge JWT validation authority must be kong" unless identity.dig("authorities", "edge_token_validation", "authority") == "kong"

    expected_edge = %w[haproxy caddy-coraza kong istio-gateway]
    errors << "edge chain must remain #{expected_edge.inspect}" unless Array(edge["chain"]) == expected_edge
    errors << "public TLS must be owned by caddy-coraza" unless Array(edge.dig("responsibilities", "caddy-coraza", "owns")).include?("public-tls")
    errors << "public API authentication must be owned by kong" unless Array(edge.dig("responsibilities", "kong", "owns")).include?("api-authentication")

    errors << "public certificates must be consumed by caddy" unless cert.dig("certificates", "public_edge", "consumer") == "caddy"
    errors << "public certificate renewal must be automatic" unless cert.dig("certificates", "public_edge", "renewal") == "caddy"
    errors << "mesh workload certificate identity must be SPIRE" unless cert.dig("certificates", "mesh_workload", "identity_authority") == "spire"

    errors << "OpenBao must remain secret authority" unless secret.dig("authorities", "secret_source") == "openbao"
    errors << "ESO must remain Kubernetes secret sync authority" unless secret.dig("authorities", "kubernetes_sync") == "external-secrets-operator"
    errors << "SPIRE must remain workload identity authority in secret policy" unless secret.dig("authorities", "workload_identity") == "spire"

    errors << "public DNS model must be hidden-primary-with-public-secondaries" unless dns.dig("public_dns_model", "mode") == "hidden-primary-with-public-secondaries"
    errors << "PowerDNS must remain public zone source of truth" unless dns.dig("authorities", "public_zone_source", "authority") == "powerdns-authoritative"
    errors << "PowerDNS public role must remain hidden-primary" unless dns.dig("authorities", "public_zone_source", "role") == "hidden-primary"
    errors << "PowerDNS hidden primary must not be publicly delegated" unless dns.dig("authorities", "public_zone_source", "publicly-delegated") == false
    errors << "ClouDNS must remain public authoritative secondary" unless dns.dig("authorities", "public_authoritative_secondaries", "authority") == "cloudns"
    errors << "ClouDNS role must remain public-secondary" unless dns.dig("authorities", "public_authoritative_secondaries", "role") == "public-secondary"
    errors << "ClouDNS secondaries must source zones from PowerDNS hidden primary" unless dns.dig("authorities", "public_authoritative_secondaries", "source") == "powerdns-hidden-primary"
    errors << "public DNS transfer must support AXFR/IXFR" unless Array(dns.dig("public_dns_model", "transfer_protocols")).sort == %w[axfr ixfr]
    errors << "ExternalDNS must remain controlled DNS writer" unless dns.dig("authorities", "kubernetes_record_writer", "authority") == "externaldns"
    errors << "ExternalDNS must write PowerDNS hidden primary, not ClouDNS" unless dns.dig("authorities", "kubernetes_record_writer", "target_authority") == "powerdns-hidden-primary" && dns.dig("authorities", "kubernetes_record_writer", "writes_public-secondary-directly") == false
    errors << "CoreDNS must remain Kubernetes service discovery authority" unless dns.dig("authorities", "kubernetes_service_discovery", "authority") == "coredns"
    errors << "Unbound must remain recursive DNS authority" unless dns.dig("authorities", "recursive_resolution", "authority") == "unbound"
    errors << "exact ClouDNS nameserver set must be required before registrar delegation" unless dns.dig("public_dns_model", "public_nameservers", "exact_assigned_set_required_before-delegation") == true
    errors << "DNS zone transfer must be monitored" unless dns.dig("rules", "zone-transfer-must-be-monitored") == true
    errors << "direct ClouDNS primary editing must remain forbidden" unless dns.dig("rules", "cloudns-direct-primary-editing-forbidden") == true

    errors << "public NTP fallback must remain forbidden" unless time.dig("runtime", "public_ntp_fallback") == "forbidden"
    errors << "time policy must fail closed when internal source is missing" unless time.dig("runtime", "fail_closed_when_missing") == true

    errors << "Argo Rollouts must remain rollout authority" unless rollout.dig("authorities", "rollout_decision") == "argo-rollouts"
    errors << "Istio must remain canary traffic shift authority" unless rollout.dig("authorities", "traffic_shift_execution") == "istio"
    errors << "Kong canary weighting must remain forbidden" unless rollout.dig("rules", "kong-canary-weighting") == "forbidden"

    forbidden_fields = Array(telemetry.dig("classification", "forbidden_fields"))
    %w[authorization cookie access_token refresh_token api_key card_pan card_cvc].each do |field|
      errors << "telemetry forbidden field missing: #{field}" unless forbidden_fields.include?(field)
    end
    errors << "raw request body logging must remain forbidden by default" unless telemetry.dig("rules", "raw-request-body-logging") == "forbidden-by-default"

    errors << "public API rate-limit authority must be kong" unless rate.dig("layers", "public_api", "authority") == "kong"
    errors << "internal L7 rate-limit authority must be istio-waypoint" unless rate.dig("layers", "internal_l7", "authority") == "istio-waypoint"
    errors << "business rate-limit authority must be application" unless rate.dig("layers", "business_rules", "authority") == "application"

    errors << "checkout must remain transaction orchestration authority" unless commerce.dig("orchestration", "authority") == "checkout"
    errors << "order must remain durable order authority" unless commerce.dig("orchestration", "durable_order_authority") == "order"
    errors << "payment must remain payment authority" unless commerce.dig("orchestration", "payment_authority") == "payment"
    errors << "cross-database transaction must remain forbidden" unless commerce.dig("rules", "cross-database-transaction") == "forbidden"
    errors << "distributed 2PC must remain forbidden" unless commerce.dig("rules", "distributed-2pc") == "forbidden"
    errors << "payment retry without idempotency must remain forbidden" unless commerce.dig("rules", "payment-retry-without-idempotency") == "forbidden"

    logical = egress.fetch("services", {})
    runtime = egress_runtime.fetch("services", {})
    logical.each do |service, entry|
      expected_ids = Array(entry["external_destinations"]).filter_map { |d| d.is_a?(Hash) ? d["id"] : nil }.map(&:to_s).sort
      actual_ids = runtime.fetch(service, {}).keys.map(&:to_s).sort
      errors << "#{service}: egress runtime destinations must match logical egress: expected #{expected_ids.inspect}, got #{actual_ids.inspect}" unless expected_ids == actual_ids
      runtime.fetch(service, {}).each do |destination, cfg|
        errors << "#{service}/#{destination}: external egress port must be 443" unless cfg["port"] == 443
        errors << "#{service}/#{destination}: external egress protocol must be https" unless cfg["protocol"] == "https"
        errors << "#{service}/#{destination}: TLS SNI must be required" unless cfg["tls_sni"] == "required"
      end
    end

    if mesh.dig("services", "payment", "l7", "traffic_policy") == true
      errors << "payment resilience source contract must exist" unless resilience.dig("services", "payment", "source_contract") == "contracts/payment-runtime.yaml"
      errors << "payment retry must require idempotency" unless resilience.dig("services", "payment", "retry_requires_idempotency") == true
    end

    errors.uniq
  end
end

if $PROGRAM_NAME == __FILE__
  root = ENV.fetch("ARCHITECTURE_BOUNDARIES_ROOT", ROOT_DEFAULT)
  begin
    errors = ArchitectureBoundariesValidator.validate(root)
  rescue StandardError => e
    warn "FAIL architecture boundaries governance"
    warn "  - #{e.message}"
    exit 1
  end
  if errors.empty?
    puts "PASS architecture boundaries governance"
    exit 0
  end
  warn "FAIL architecture boundaries governance"
  errors.each { |error| warn "  - #{error}" }
  exit 1
end
