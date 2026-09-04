#!/usr/bin/env ruby
# frozen_string_literal: true

require "ipaddr"
require "pathname"
require "yaml"

module ArchitectureValidator
  class ContractLoadError < StandardError; end

  module_function

  def load_yaml(root, path)
    YAML.safe_load_file(File.join(root, path), aliases: false)
  rescue Psych::Exception => e
    raise ContractLoadError, "#{path} is not valid YAML: #{e.message}"
  rescue SystemCallError => e
    raise ContractLoadError, "#{path} cannot be loaded: #{e.message}"
  end

  def machine_contract_path(root, lock, key)
    path = lock.fetch("machine_contracts", {}).fetch(key, nil)
    label = "architecture.lock.yaml machine_contracts.#{key}"
    unless path.is_a?(String) && !path.empty?
      raise ContractLoadError, "#{label} must declare a non-empty relative path"
    end
    if Pathname.new(path).absolute?
      raise ContractLoadError, "#{label} must declare a relative path: #{path.inspect}"
    end

    repository_root = File.expand_path(root)
    resolved_path = File.expand_path(path, repository_root)
    unless resolved_path.start_with?("#{repository_root}#{File::SEPARATOR}")
      raise ContractLoadError, "#{label} must stay within the repository: #{path.inspect}"
    end
    unless File.file?(resolved_path)
      raise ContractLoadError, "#{label} declared file does not exist: #{path}"
    end

    real_repository_root = File.realpath(repository_root)
    real_path = File.realpath(resolved_path)
    unless real_path.start_with?("#{real_repository_root}#{File::SEPARATOR}")
      raise ContractLoadError, "#{label} resolves outside the repository: #{path.inspect}"
    end

    path
  end

  def load_machine_contract(root, lock, key)
    path = machine_contract_path(root, lock, key)
    [load_yaml(root, path), path]
  end

  def markdown_rows(root, path, header)
    lines = File.readlines(File.join(root, path), chomp: true)
    first = lines.index { |line| line.start_with?(header) }
    raise "#{path}: table #{header.inspect} not found" unless first

    lines[(first + 2)..].take_while { |line| line.start_with?("|") }.map do |line|
      line.split("|", -1)[1...-1].map(&:strip)
    end
  end

  def list(cell)
    return [] if ["none", ""].include?(cell)

    cell.split(",").map(&:strip)
  end

  def check_equal(errors, label, expected, actual)
    return if expected == actual

    errors << "#{label}: expected #{expected.inspect}, got #{actual.inspect}"
  end

  def validate(root)
    errors = []
    begin
      lock = load_yaml(root, "architecture.lock.yaml")
      ownership, ownership_path = load_machine_contract(root, lock, "service_ownership")
      events, events_path = load_machine_contract(root, lock, "event_contracts")
      dependencies, dependencies_path = load_machine_contract(root, lock, "dependency_map")
      network, = load_machine_contract(root, lock, "network_plan")
      prod, = load_machine_contract(root, lock, "prod_inventory")
    rescue ContractLoadError => e
      return [e.message]
    end

    service_rows = markdown_rows(root, "docs/architecture/SERVICE_OWNERSHIP_MATRIX.md", "| Service |")
    service_sets = {
      "architecture.lock.yaml" => lock.dig("business", "services"),
      File.basename(ownership_path) => ownership.fetch("services").keys,
      File.basename(dependencies_path) => dependencies.fetch("services").keys,
      "SERVICE_OWNERSHIP_MATRIX.md" => service_rows.map(&:first)
    }
    canonical_services = service_sets.values.first.sort
    service_sets.each { |name, names| check_equal(errors, "17 services in #{name}", canonical_services, names.sort) }
    errors << "architecture must contain exactly 17 services" unless canonical_services.length == 17
    service_sets.each do |name, names|
      errors << "checkout service is forbidden in #{name}" if names.include?("checkout")
    end

    markdown_sync = service_rows.to_h { |row| [row[0], list(row[3]).map { |value| value.split(";").first.strip }] }
    ownership.fetch("services").each do |service, contract|
      check_equal(errors, "sync dependencies for #{service}", contract.fetch("sync_dependencies"), markdown_sync.fetch(service))
      map = dependencies.fetch("services")[service]
      next unless map

      expected_dependencies = contract.fetch("sync_dependencies")
      expected_internal = expected_dependencies.select { |dependency| canonical_services.include?(dependency) }
      expected_external = expected_dependencies.reject { |dependency| canonical_services.include?(dependency) }
      check_equal(errors, "dependency map internal sync for #{service}", expected_internal, map.fetch("sync", []))
      check_equal(errors, "dependency map external sync for #{service}", expected_external, map.fetch("sync_external", []))
    end

    check_equal(errors, "#{File.basename(ownership_path)} forbidden.cross_database_reads", true,
                ownership.dig("forbidden", "cross_database_reads"))
    check_equal(errors, "#{File.basename(dependencies_path)} rules.no_cross_database_reads", true,
                dependencies.dig("rules", "no_cross_database_reads"))

    errors << "#{File.basename(events_path)} status must be exact" unless events["status"] == "exact"
    {
      "delivery" => "at-least-once",
      "producer_pattern" => "transactional-outbox",
      "consumer_idempotent" => true,
      "global_ordering" => false,
      "aggregate_key_ordering" => true,
      "secrets_in_events" => "forbidden",
      "unnecessary_pii_in_events" => "forbidden"
    }.each do |field, expected|
      check_equal(errors, "#{File.basename(events_path)} semantics.#{field}", expected, events.dig("semantics", field))
    end
    event_rows = markdown_rows(root, "docs/architecture/EVENT_CONTRACT_MATRIX.md", "| Producer |")
    markdown_events = event_rows.to_h { |row| ["#{row[0]}.#{row[1]}", list(row[2])] }
    machine_events = events.fetch("events").transform_values { |entry| entry.fetch("consumers") }
    check_equal(errors, "active event catalogue", machine_events, markdown_events)

    emitted = service_rows.flat_map { |row| list(row[5]).map { |event| "#{row[0]}.#{event}.v1" } }.sort
    check_equal(errors, "all emitted events covered by exact event contract", emitted, machine_events.keys.sort)
    machine_events.each do |key, consumers|
      producer = key.split(".", 2).first
      errors << "unknown producer #{producer} for #{key}" unless canonical_services.include?(producer)
      consumers.each { |consumer| errors << "unknown consumer #{consumer} for #{key}" unless canonical_services.include?(consumer) }
      errors << "duplicate consumers for #{key}" unless consumers.uniq == consumers
    end
    canonical_services.each do |service|
      expected_inputs = machine_events.filter_map do |key, consumers|
        key.split(".", 2).last if consumers.include?(service)
      end
      map = dependencies.fetch("services")[service]
      next unless map

      actual_inputs = map.fetch("events_in")
      check_equal(errors, "event inputs for #{service}", expected_inputs.sort, actual_inputs.sort)
    end

    networks = []
    network.fetch("address_domains").each { |site, cidr| networks << ["domain #{site}", IPAddr.new(cidr)] }
    network.fetch("vlans").each do |site, vlans|
      domain = IPAddr.new(network.fetch("address_domains").fetch(site))
      vlans.each do |vlan, spec|
        subnet = IPAddr.new(spec.fetch("cidr"))
        errors << "#{site} VLAN #{vlan} is outside its address domain" unless domain.include?(subnet)
        networks << ["#{site} VLAN #{vlan}", subnet]
      end
    end
    network.fetch("kubernetes").each do |site, cidrs|
      cidrs.each { |kind, cidr| networks << ["#{site} #{kind}", IPAddr.new(cidr)] }
    end
    networks.combination(2) do |(left_name, left), (right_name, right)|
      next if left_name.start_with?("domain ") && right_name.start_with?("#{left_name.delete_prefix('domain ')} VLAN ")
      next if right_name.start_with?("domain ") && left_name.start_with?("#{right_name.delete_prefix('domain ')} VLAN ")

      errors << "CIDR overlap: #{left_name} and #{right_name}" if left.include?(right) || right.include?(left)
    end

    seen_ips = {}
    network.fetch("static_allocations").each do |site, vlans|
      vlans.each do |vlan, allocations|
        subnet = IPAddr.new(network.fetch("vlans").fetch(site).fetch(vlan).fetch("cidr"))
        allocations.each do |node, value|
          ip = IPAddr.new(value)
          errors << "#{site}/#{vlan}/#{node} is outside #{subnet}" unless subnet.include?(ip)
          if subnet.ipv4? && ip == subnet.to_range.first
            errors << "#{site}/#{vlan}/#{node} uses network address #{value}"
          elsif subnet.ipv4? && ip == subnet.to_range.last
            errors << "#{site}/#{vlan}/#{node} uses broadcast address #{value}"
          end
          %w[gateway_and_vips future_reserved].each do |policy|
            range = network.fetch("allocation_policy").fetch(policy)
            first, last = range.scan(/\d+/).map(&:to_i)
            next unless first && last && (first..last).cover?(ip.to_i - subnet.to_range.first.to_i)

            errors << "#{site}/#{vlan}/#{node} uses #{policy} reserved address #{value}"
          end
          errors << "duplicate static IP #{value}" if seen_ips.key?(value)
          seen_ips[value] = "#{site}/#{vlan}/#{node}"
        end
      end
    end
    network.fetch("dynamic_pools").each do |site, vlans|
      vlans.each do |vlan, pools|
        subnet = IPAddr.new(network.fetch("vlans").fetch(site).fetch(vlan).fetch("cidr"))
        parsed_pools = pools.map do |name, value|
          pool = IPAddr.new(value)
          errors << "#{site}/#{vlan}/#{name} pool is outside #{subnet}" unless subnet.include?(pool)
          seen_ips.each_key { |ip| errors << "static IP #{ip} overlaps #{name} pool" if pool.include?(IPAddr.new(ip)) }
          [name, pool]
        end
        parsed_pools.combination(2) do |(left_name, left), (right_name, right)|
          if left.include?(right) || right.include?(left)
            errors << "dynamic pool overlap in #{site}/#{vlan}: #{left_name} and #{right_name}"
          end
        end
      end
    end

    topology = lock.fetch("prod_certified_topology")
    expected_prod_sites = network.fetch("address_domains").keys.grep(/^prod-/).sort
    actual_prod_sites = prod.fetch("sites").keys.sort
    check_equal(errors, "exact PROD sites", expected_prod_sites, actual_prod_sites)
    expected_site_count = topology.fetch("physical_hosts_total") / topology.fetch("physical_hosts_per_site")
    check_equal(errors, "exact PROD site count", expected_site_count, expected_prod_sites.length)

    prod.fetch("sites").each do |site, spec|
      next unless network.fetch("address_domains").key?(site)

      check_equal(errors, "#{site} private block", network.fetch("address_domains").fetch(site), spec.fetch("private_block"))
      check_equal(errors, "#{site} physical hosts", topology.fetch("physical_hosts_per_site"), spec.fetch("physical_hosts").length)
      check_equal(errors, "#{site} control planes", topology.fetch("control_planes_per_site"), spec.fetch("control_planes").length)
      check_equal(errors, "#{site} data workers", topology.fetch("data_workers_per_site"), spec.fetch("data_workers").length)
      check_equal(errors, "#{site} general workers", topology.fetch("general_workers_per_site"), spec.fetch("general_workers").length)
      check_equal(errors, "#{site} workers", topology.fetch("workers_per_site"),
                  spec.fetch("data_workers").length + spec.fetch("general_workers").length)
    end
    total_physical_hosts = expected_prod_sites.sum do |site|
      prod.fetch("sites").fetch(site, {}).fetch("physical_hosts", {}).length
    end
    check_equal(errors, "PROD total physical hosts", topology.fetch("physical_hosts_total"), total_physical_hosts)
    {
      "physical_hosts_total" => 6,
      "physical_hosts_per_site" => 3,
      "control_planes_per_site" => 3,
      "workers_per_site" => 5,
      "data_workers_per_site" => 3,
      "general_workers_per_site" => 2
    }.each do |field, expected|
      check_equal(errors, "prod_certified_topology.#{field}", expected, topology.fetch(field))
    end

    active_contracts = {
      "platform" => {
        "kubernetes" => "rke2", "node_os" => "rocky-linux-9", "cni" => "cilium", "mesh" => "istio",
        "gitops" => "rancher-fleet", "ci" => "tekton", "progressive_delivery" => "argo-rollouts",
        "registry" => "harbor", "secrets" => "openbao", "external_secrets" => "eso",
        "workload_identity" => "spire", "iam" => "keycloak"
      },
      "stateful" => {
        "database" => "cloudnativepg-postgresql", "events" => "strimzi-kafka-kraft",
        "jobs" => "rabbitmq-quorum-queues", "cache" => "redis-cluster", "search" => "opensearch",
        "object_storage" => "seaweedfs-s3"
      },
      "observability" => {
        "telemetry" => "opentelemetry", "metrics" => "prometheus", "alerts" => "alertmanager",
        "dashboards" => "grafana", "log_shipper" => "fluent-bit", "log_pipeline" => "data-prepper",
        "logs" => "opensearch-logs", "security" => "wazuh"
      },
      "supply_chain" => {
        "scanner" => "trivy", "sbom" => "syft", "signing" => "cosign",
        "immutable_images" => true, "forbid_latest" => true
      }
    }
    active_contracts.each do |section, expected_contract|
      actual_contract = lock.fetch(section)
      check_equal(errors, "#{section} active contract keys", expected_contract.keys.sort, actual_contract.keys.sort)
      expected_contract.each do |field, expected|
        check_equal(errors, "#{section}.#{field}", expected, actual_contract[field])
      end
    end

    network_policy = network.fetch("validation")
    %w[
      require_unique_ips
      require_non_overlapping_cidrs
      require_site_isolation
      require_underlay_pod_service_separation
      public_ips_runtime_injected_only
    ].each do |field|
      check_equal(errors, "network-plan.validation.#{field}", true, network_policy.fetch(field))
    end
    errors
  end
end

if $PROGRAM_NAME == __FILE__
  root = ARGV.fetch(0, File.expand_path("..", __dir__))
  errors = ArchitectureValidator.validate(root)
  if errors.empty?
    puts "[governance] architecture contracts: PASS"
  else
    warn errors.map { |error| "[governance] #{error}" }.join("\n")
    exit 1
  end
end
