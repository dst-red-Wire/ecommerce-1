#!/usr/bin/env ruby
# frozen_string_literal: true

require "ipaddr"
require "yaml"

module ArchitectureValidator
  module_function

  def load_yaml(root, path)
    YAML.safe_load_file(File.join(root, path), aliases: false)
  rescue Psych::Exception => e
    raise "#{path} is not valid YAML: #{e.message}"
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
    lock = load_yaml(root, "architecture.lock.yaml")
    ownership = load_yaml(root, "config/contracts/service-ownership.yaml")
    events = load_yaml(root, "config/contracts/event-contracts.yaml")
    dependencies = load_yaml(root, "config/contracts/dependency-map.yaml")
    network = load_yaml(root, "config/infrastructure/network-plan.yaml")
    prod = load_yaml(root, "config/infrastructure/prod-inventory.yaml")

    service_rows = markdown_rows(root, "docs/architecture/SERVICE_OWNERSHIP_MATRIX.md", "| Service |")
    service_sets = {
      "architecture.lock.yaml" => lock.dig("business", "services"),
      "service-ownership.yaml" => ownership.fetch("services").keys,
      "dependency-map.yaml" => dependencies.fetch("services").keys,
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

      mapped = map.fetch("sync", []) + map.fetch("sync_external", [])
      check_equal(errors, "dependency map sync for #{service}", contract.fetch("sync_dependencies"), mapped)
    end

    errors << "event-contracts.yaml status must be exact" unless events["status"] == "exact"
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

    prod.fetch("sites").each do |site, spec|
      check_equal(errors, "#{site} private block", network.fetch("address_domains").fetch(site), spec.fetch("private_block"))
      errors << "#{site} must have 3 physical hosts" unless spec.fetch("physical_hosts").length == 3
      errors << "#{site} must have 3 control planes" unless spec.fetch("control_planes").length == 3
      errors << "#{site} must have 3 data workers" unless spec.fetch("data_workers").length == 3
      errors << "#{site} must have 2 general workers" unless spec.fetch("general_workers").length == 2
    end
    topology = lock.fetch("prod_certified_topology")
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

    active_contract_checks = [
      ["platform.gitops", lock.dig("platform", "gitops"), "rancher-fleet"],
      ["platform.progressive_delivery", lock.dig("platform", "progressive_delivery"), "argo-rollouts"],
      ["stateful.object_storage", lock.dig("stateful", "object_storage"), "seaweedfs-s3"],
      ["observability.logs", lock.dig("observability", "logs"), "opensearch-logs"],
      ["observability.security", lock.dig("observability", "security"), "wazuh"],
      ["supply_chain.immutable_images", lock.dig("supply_chain", "immutable_images"), true],
      ["supply_chain.forbid_latest", lock.dig("supply_chain", "forbid_latest"), true]
    ]
    active_contract_checks.each do |path, actual, expected|
      check_equal(errors, path, expected, actual)
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
