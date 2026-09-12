#!/usr/bin/env ruby
# frozen_string_literal: true

require "ipaddr"
require "pathname"
require "yaml"

module ArchitectureValidator
  LOCK_STATUS = "locked-for-build"
  V5_FRONTENDS = %w[storefront admin].freeze
  DEPLOYABLE_MLOPS = %w[lakefs mlflow kserve-vllm evidently-tekton-batch].freeze
  V5_MLOPS = {
    "dataset_versioner" => "lakefs", "object_storage" => "seaweedfs-s3",
    "metadata_database" => "cloudnativepg-postgresql", "experiments_lineage" => "mlflow",
    "artifact_registry" => "harbor", "promotion_authority" => "gitea-gitops",
    "orchestration" => "tekton", "desired_state" => "rancher-fleet",
    "progressive_delivery" => "argo-rollouts", "runtime" => "kserve-vllm",
    "drift" => "evidently-tekton-batch"
  }.freeze
  V5_TOPOLOGY_CONTRACTS = {
    "exact_index" => "docs/architecture/EXACT_TOPOLOGY_V5.md", "preprod" => "docs/architecture/PREPROD_TOPOLOGY_V2.md",
    "prod" => "docs/architecture/PROD_TOPOLOGY_V2.md", "network_ipam" => "docs/architecture/NETWORK_IPAM_CONTRACT.md",
    "mgmt_wireguard_access" => "docs/architecture/MGMT_WIREGUARD_ACCESS.md", "storage" => "docs/architecture/STORAGE_TOPOLOGY_V2.md",
    "service_ownership" => "docs/architecture/SERVICE_OWNERSHIP_MATRIX.md", "data_ownership" => "docs/architecture/DATA_OWNERSHIP_MATRIX.md",
    "events" => "docs/architecture/EVENT_CONTRACT_MATRIX.md", "security_zones" => "docs/architecture/SECURITY_TRUST_ZONES.md",
    "deployment_dag" => "docs/architecture/DEPLOYMENT_DAG.md", "aiops" => "docs/architecture/AIOPS_TOPOLOGY_V1.md",
    "mlops" => "docs/architecture/MLOPS_TOPOLOGY_V1.md", "observability" => "docs/architecture/OBSERVABILITY_TOPOLOGY_V1.md"
  }.freeze
  V5_MACHINE_CONTRACTS = {
    "resilience_governance" => "config/contracts/resilience-governance.yaml", "security_trust_zones" => "config/contracts/security-trust-zones.yaml",
    "review_policy" => "config/contracts/review-policy.yaml", "mgmt_inventory" => "config/infrastructure/mgmt-inventory.yaml",
    "preprod_inventory" => "config/infrastructure/preprod-inventory.yaml", "prod_inventory" => "config/infrastructure/prod-inventory.yaml",
    "network_plan" => "config/infrastructure/network-plan.yaml", "mgmt_wireguard_access" => "config/contracts/mgmt-wireguard-access.yaml",
    "mgmt_access_gateways" => "config/infrastructure/mgmt-access-gateways.yaml", "storage_plan" => "config/infrastructure/storage-plan.yaml",
    "deployment_waves" => "config/infrastructure/deployment-waves.yaml", "service_ownership" => "config/contracts/service-ownership.yaml",
    "event_contracts" => "config/contracts/event-contracts.yaml", "dependency_map" => "config/contracts/dependency-map.yaml",
    "public_api_contracts" => "config/contracts/public-api-contracts.yaml", "ci_topology" => "config/contracts/ci-topology.yaml",
    "runtime_efficiency" => "config/contracts/runtime-efficiency.yaml", "observability_topology" => "config/contracts/observability-topology.yaml"
  }.freeze

  class ContractLoadError < StandardError; end

  module_function

  def load_yaml(root, path)
    contents = File.read(File.join(root, path))
    document = Psych.parse_stream(contents, filename: path)
    # Match safe_load's restricted scalar construction, including tags and quoting.
    class_loader = Psych::ClassLoader::Restricted.new([], [])
    scanner = Psych::ScalarScanner.new(class_loader)
    visitor = Psych::Visitors::NoAliasRuby.new(scanner, class_loader)
    reject_duplicate_yaml_keys(document, path, visitor)
    YAML.safe_load(contents, aliases: false, filename: path)
  rescue Psych::Exception => e
    raise ContractLoadError, "#{path} is not valid YAML: #{e.message}"
  rescue SystemCallError => e
    raise ContractLoadError, "#{path} cannot be loaded: #{e.message}"
  end

  def reject_duplicate_yaml_keys(node, path, visitor, context = [])
    case node
    when Psych::Nodes::Mapping
      seen = {}
      node.children.each_slice(2) do |key_node, value_node|
        key = yaml_key_identity(key_node, visitor, path, context)
        key_name = key.is_a?(String) ? key : key.inspect
        key_context = context + [key_name]
        if seen.key?(key)
          raise ContractLoadError,
                "#{path} contains duplicate YAML key #{key_context.join('.').inspect} " \
                "at line #{key_node.start_line + 1}"
        end

        seen[key] = true
        reject_duplicate_yaml_keys(value_node, path, visitor, key_context)
      end
    when Psych::Nodes::Sequence
      node.children.each_with_index do |child, index|
        reject_duplicate_yaml_keys(child, path, visitor, context + ["[#{index}]"])
      end
    when Psych::Nodes::Stream, Psych::Nodes::Document
      node.children.each { |child| reject_duplicate_yaml_keys(child, path, visitor, context) }
    end
  end

  # Custom tags may silently fall back to scalar scanning in Psych. Reject them
  # explicitly; only standard scalar tags are supported by governance contracts.
  YAML_KEY_TAGS = %w[
    tag:yaml.org,2002:str tag:yaml.org,2002:bool tag:yaml.org,2002:null
    tag:yaml.org,2002:int tag:yaml.org,2002:float tag:yaml.org,2002:binary
  ].freeze

  def yaml_key_identity(node, visitor, path, context)
    location = "#{path} mapping #{context.join('.').inspect} at line #{node.start_line + 1}"
    unless node.is_a?(Psych::Nodes::Scalar)
      raise ContractLoadError, "#{location}: unsupported YAML key type #{node.class.name}"
    end
    if node.tag && !YAML_KEY_TAGS.include?(node.tag)
      raise ContractLoadError, "#{location}: unsupported YAML key type (non-standard scalar tag)"
    end

    # Store the constructed object directly in seen: Hash uses hash/eql?, so
    # equivalent spellings collide without conflating Integer, Float and String.
    visitor.accept(node)
  rescue Psych::Exception, ArgumentError, TypeError => e
    raise ContractLoadError, "#{location}: unsupported YAML key type (#{e.class})"
  end

  def expect_mapping(value, label)
    return value if value.is_a?(Hash)

    raise ContractLoadError, "#{label} must be a mapping"
  end

  def expect_array(value, label)
    return value if value.is_a?(Array)

    raise ContractLoadError, "#{label} must be an array"
  end

  def machine_contract_path(root, key, path)
    label = "architecture.lock.yaml machine_contracts.#{key}"
    unless path.is_a?(String) && !path.strip.empty?
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

  def load_machine_contracts(root, lock)
    declared = expect_mapping(lock["machine_contracts"], "architecture.lock.yaml machine_contracts")
    contracts = declared.each_with_object({}) do |(key, path), loaded|
      unless key.is_a?(String) && !key.strip.empty?
        raise ContractLoadError, "architecture.lock.yaml machine_contracts keys must be non-empty strings"
      end

      validated_path = machine_contract_path(root, key, path)
      contract = load_yaml(root, validated_path)
      loaded[key] = [expect_mapping(contract, validated_path), validated_path]
    end
    unless declared == V5_MACHINE_CONTRACTS
      raise ContractLoadError, "architecture.lock.yaml machine_contracts must match the complete approved V5 role/path registry"
    end
    contracts
  end

  def validate_topology_contracts(root, lock)
    declared = expect_mapping(lock["topology_contracts"], "architecture.lock.yaml topology_contracts")
    unless declared == V5_TOPOLOGY_CONTRACTS
      raise ContractLoadError, "architecture.lock.yaml topology_contracts must match the complete approved V5 role/path registry"
    end
    declared.each do |key, path|
      label = "architecture.lock.yaml topology_contracts.#{key}"
      unless key.is_a?(String) && !key.strip.empty?
        raise ContractLoadError, "architecture.lock.yaml topology_contracts keys must be non-empty strings"
      end
      unless path.is_a?(String) && !path.strip.empty? && !Pathname.new(path).absolute?
        raise ContractLoadError, "#{label} must declare a non-empty relative path"
      end
      repository_root = File.expand_path(root)
      resolved = File.expand_path(path, repository_root)
      unless resolved.start_with?("#{repository_root}#{File::SEPARATOR}") && File.file?(resolved)
        raise ContractLoadError, "#{label} declared file does not exist: #{path}"
      end
      real_root = File.realpath(repository_root)
      real_path = File.realpath(resolved)
      unless real_path.start_with?("#{real_root}#{File::SEPARATOR}")
        raise ContractLoadError, "#{label} resolves outside the repository: #{path.inspect}"
      end
      contents = File.read(real_path)
      status = contents.match(/^Status:\s*`([^`]*)`\s*$/i)
      status_value = status && status[1].strip
      unless status_value&.casecmp?("EXACT")
        raise ContractLoadError, "#{label} must reference a readable EXACT topology contract: #{path}"
      end
    end
  end

  def required_machine_contract(contracts, key)
    contracts.fetch(key) do
      raise ContractLoadError, "architecture.lock.yaml machine_contracts.#{key} must be declared"
    end
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
    lock = expect_mapping(load_yaml(root, "architecture.lock.yaml"), "architecture.lock.yaml")
    check_equal(errors, "architecture.lock.yaml status", LOCK_STATUS, lock["status"])
    validate_topology_contracts(root, lock)
    contracts = load_machine_contracts(root, lock)
    ownership, ownership_path = required_machine_contract(contracts, "service_ownership")
    events, events_path = required_machine_contract(contracts, "event_contracts")
    dependencies, dependencies_path = required_machine_contract(contracts, "dependency_map")
    network, = required_machine_contract(contracts, "network_plan")
    mgmt, = required_machine_contract(contracts, "mgmt_inventory")
    mgmt_gateways, = required_machine_contract(contracts, "mgmt_access_gateways")
    mgmt_wireguard, = required_machine_contract(contracts, "mgmt_wireguard_access")
    prod, = required_machine_contract(contracts, "prod_inventory")
    resilience, resilience_path = required_machine_contract(contracts, "resilience_governance")
    trust_zones, trust_zones_path = required_machine_contract(contracts, "security_trust_zones")
    deployment_waves, deployment_waves_path = required_machine_contract(contracts, "deployment_waves")
    check_equal(errors, "#{deployment_waves_path} status", "exact", deployment_waves["status"])

    mlops_path = lock.dig("topology_contracts", "mlops")
    mlops_section = File.read(File.join(root, mlops_path)).split("## Locked role mapping", 2).last.to_s.split("\n## ", 2).first
    mlops_rows = mlops_section.scan(/^- `([a-z_]+)`: `([a-z0-9-]+)`\s*$/)
    seen_mlops = {}
    mlops_rows.each do |role, _value|
      errors << "duplicate subordinate MLOps assignment: #{role}" if seen_mlops.key?(role)
      seen_mlops[role] = true
    end
    subordinate_mlops = mlops_rows.to_h
    check_equal(errors, "architecture.lock.yaml mlops", V5_MLOPS, lock["mlops"])
    check_equal(errors, "#{mlops_path} locked role mapping", V5_MLOPS, subordinate_mlops)

    [resilience, trust_zones].zip([resilience_path, trust_zones_path]).each do |contract, path|
      check_equal(errors, "#{path} status", "exact", contract["status"])
      check_equal(errors, "#{path} architecture authority", "architecture.lock.yaml", contract["architecture_authority"])
    end
    management = expect_mapping(lock["management_plane"], "architecture.lock.yaml management_plane")
    check_equal(errors, "MGMT inventory provider", management["provider"], mgmt["provider"])
    check_equal(errors, "MGMT gateway provider", management["provider"], mgmt_gateways["provider"])
    check_equal(errors, "MGMT WireGuard provider", management["provider"], mgmt_wireguard.dig("gateway", "provider"))
    check_equal(errors, "MGMT inventory lifecycle", management["lifecycle"], mgmt.dig("lifecycle", "mode"))
    check_equal(errors, "MGMT gateway lifecycle", management["lifecycle"], mgmt_gateways.dig("lifecycle", "mode"))
    check_equal(errors, "MGMT WireGuard lifecycle", management["lifecycle"], mgmt_wireguard.dig("gateway", "lifecycle"))
    check_equal(errors, "MGMT private block", management["private_block"], mgmt["private_block"])
    %w[forge ci registry gitops].each do |role|
      check_equal(errors, "MGMT #{role}", management[role], mgmt.dig("platform_services", role))
    end
    profile_prefixes = expect_mapping(mgmt["vm_profiles"], "mgmt-inventory.yaml vm_profiles").keys.map { |name| name.split("-", 2).first }.uniq
    check_equal(errors, "MGMT Kubernetes", [management["kubernetes"]], profile_prefixes)
    check_equal(errors, "MGMT Terraform/OpenTofu bootstrap", true, management.dig("bootstrap", "terraform_opentofu"))
    check_equal(errors, "MGMT inventory Terraform/OpenTofu bootstrap", "terraform-opentofu", mgmt.dig("bootstrap", "infrastructure"))
    check_equal(errors, "MGMT Ansible bootstrap", true, management.dig("bootstrap", "ansible"))
    check_equal(errors, "MGMT inventory Ansible bootstrap", "ansible", mgmt.dig("bootstrap", "configuration"))
    check_equal(errors, "MGMT human apply gate", true, management.dig("bootstrap", "requires_human_apply_gate"))
    check_equal(errors, "MGMT inventory human apply gate", true, mgmt.dig("bootstrap", "human_apply_gate"))
    check_equal(errors, "MGMT gateway human apply gate", true, mgmt_gateways.dig("implementation", "human_apply_gate"))
    check_equal(errors, "MGMT WireGuard provider apply gate", "required", mgmt_wireguard.dig("human_gates", "provider_apply"))
    check_equal(errors, "security trust zones", {
      "Z0" => "internet-untrusted", "Z1" => "public-edge-dmz", "Z2" => "kubernetes-ingress-service-mesh",
      "Z3" => "application-workloads", "Z4" => "stateful-data", "Z5" => "permanent-mgmt",
      "Z6" => "backup-evidence-dfir"
    }, trust_zones["zones"])
    check_equal(errors, "security secret handling", {
      "flow" => "openbao-eso-kubernetes-secret-runtime-mount-where-applicable",
      "forbidden" => %w[git image-layers ci-logs bootstrap-credentials-after-preprod-destroy application-access-to-openbao-admin-credentials]
    }, trust_zones["secrets"])
    check_equal(errors, "security egress", {
      "default" => "deny", "application_path" => "approved-istio-egress-squid",
      "logging" => "required", "exceptions" => "documented"
    }, trust_zones["egress"])
    check_equal(errors, "compromise containment", %w[isolate acquire-evidence destroy rebuild-via-gitops-iac],
                resilience.dig("compromise", "sequence"))
    check_equal(errors, "forensic evidence preservation", "forbidden",
                resilience.dig("evidence", "destroy_required_forensic_evidence"))
    check_equal(errors, "site recovery sequence",
                %w[health-evidence quorum-fencing write-authority-decision stateful-promotion-recovery application-routing dns-gslb-change],
                resilience.dig("site_recovery", "sequence"))

    service_rows = markdown_rows(root, "docs/architecture/SERVICE_OWNERSHIP_MATRIX.md", "| Service |")
    service_sets = {
      "architecture.lock.yaml" => lock.dig("business", "services"),
      File.basename(ownership_path) => ownership.fetch("services").keys,
      File.basename(dependencies_path) => dependencies.fetch("services").keys,
      "SERVICE_OWNERSHIP_MATRIX.md" => service_rows.map(&:first)
    }
    canonical_services = service_sets.values.first.sort
    expected_service_count = 19
    service_sets.each { |name, names| check_equal(errors, "19 services in #{name}", canonical_services, names.sort) }
    errors << "architecture must contain exactly 19 services" unless canonical_services.length == expected_service_count
    deployed_services = deployment_waves.fetch("waves").flat_map do |wave|
      wave.fetch("components", []) + wave.fetch("parallel_groups", []).flatten + wave.fetch("serial_after_parallel", [])
    end.select { |component| canonical_services.include?(component) }
    check_equal(errors, "business services scheduled exactly once in #{File.basename(deployment_waves_path)}",
                canonical_services, deployed_services.sort)
    check_equal(errors, "architecture.lock.yaml canonical frontends", V5_FRONTENDS,
                expect_array(lock.dig("business", "frontends"), "architecture.lock.yaml business.frontends"))
    scheduled_components = []
    deployment_positions = {}
    deployment_waves.fetch("waves").each_with_index do |wave, wave_index|
      wave.fetch("components", []).each do |component|
        scheduled_components << component
        deployment_positions[component] ||= [wave_index, 0]
      end
      groups = wave.fetch("parallel_groups", [])
      groups.each_with_index do |group, group_index|
        group.each do |component|
          scheduled_components << component
          deployment_positions[component] ||= [wave_index, group_index + 1]
        end
      end
      wave.fetch("serial_after_parallel", []).each_with_index do |component, serial_index|
        scheduled_components << component
        deployment_positions[component] ||= [wave_index, groups.length + serial_index + 1]
      end
    end
    frontend_waves = deployment_waves.fetch("waves").select { |wave| wave["id"] == "100-frontends" }
    deployed_frontends = frontend_waves.length == 1 ? frontend_waves.first.fetch("components", []) : []
    check_equal(errors, "canonical frontends scheduled in 100-frontends in #{File.basename(deployment_waves_path)}",
                V5_FRONTENDS, deployed_frontends)
    check_equal(errors, "canonical frontends scheduled exactly once in #{File.basename(deployment_waves_path)}",
                V5_FRONTENDS, scheduled_components.select { |component| V5_FRONTENDS.include?(component) })
    dependencies.fetch("services").each do |service, contract|
      contract.fetch("sync", []).each do |dependency|
        next unless deployment_positions.key?(service) && deployment_positions.key?(dependency)
        next if (deployment_positions[service] <=> deployment_positions[dependency]).positive?

        errors << "deployment ordering requires #{service} after synchronous dependency #{dependency}"
      end
    end
    deployed_mlops = scheduled_components.select { |component| DEPLOYABLE_MLOPS.include?(component) }
    check_equal(errors, "canonical deployable MLOps components scheduled exactly once", DEPLOYABLE_MLOPS, deployed_mlops)
    {
      "lakefs" => %w[seaweedfs], "mlflow" => %w[lakefs cloudnativepg],
      "kserve-vllm" => %w[mlflow harbor tekton rancher-fleet argo-rollouts],
      "evidently-tekton-batch" => %w[kserve-vllm tekton]
    }.each do |component, required|
      required.each do |dependency|
        ordered = deployment_positions.key?(component) && deployment_positions.key?(dependency) &&
                  (deployment_positions[component] <=> deployment_positions[dependency]).positive?
        errors << "deployment ordering requires #{component} after MLOps dependency #{dependency}" unless ordered
      end
    end
    %w[checkout fulfillment].each do |required_service|
      service_sets.each do |name, names|
        errors << "#{required_service} service is required in #{name}" unless names.include?(required_service)
      end
    end
    lock_forbidden = expect_array(lock.dig("business", "forbidden_services"), "architecture.lock.yaml business.forbidden_services")
    ownership_forbidden = expect_array(ownership.dig("forbidden", "services"), "#{ownership_path} forbidden.services")
    %w[checkout fulfillment].each do |required_service|
      errors << "#{required_service} must not be forbidden in architecture.lock.yaml" if lock_forbidden.include?(required_service)
      errors << "#{required_service} must not be forbidden in #{File.basename(ownership_path)}" if ownership_forbidden.include?(required_service)
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
    semantics = expect_mapping(events["semantics"], "#{events_path} semantics")
    {
      "delivery" => "at-least-once",
      "producer_pattern" => "transactional-outbox",
      "consumer_idempotent" => true,
      "global_ordering" => false,
      "aggregate_key_ordering" => true,
      "secrets_in_events" => "forbidden",
      "unnecessary_pii_in_events" => "forbidden"
    }.each do |field, expected|
      check_equal(errors, "#{File.basename(events_path)} semantics.#{field}", expected, semantics[field])
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
    static_allocations = expect_mapping(network["static_allocations"], "network-plan.yaml static_allocations")
    static_allocations.each do |site, vlans|
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

    topology = expect_mapping(lock["prod_certified_topology"], "architecture.lock.yaml prod_certified_topology")
    topology_sites = expect_mapping(topology["sites"], "architecture.lock.yaml prod_certified_topology.sites")
    address_domains = expect_mapping(network["address_domains"], "network-plan.yaml address_domains")
    prod_sites = expect_mapping(prod["sites"], "prod-inventory.yaml sites")
    expected_prod_sites = topology_sites.keys.sort
    network_prod_sites = address_domains.keys.grep(/^prod-/).sort
    actual_prod_sites = prod_sites.keys.sort
    check_equal(errors, "exact PROD network sites", expected_prod_sites, network_prod_sites)
    check_equal(errors, "exact PROD sites", expected_prod_sites, actual_prod_sites)
    expected_site_count = topology.fetch("physical_hosts_total") / topology.fetch("physical_hosts_per_site")
    check_equal(errors, "exact PROD site count", expected_site_count, expected_prod_sites.length)

    topology_sites.each do |site, canonical_spec|
      canonical_spec = expect_mapping(canonical_spec, "prod_certified_topology.sites.#{site}")
      canonical_hosts = expect_array(canonical_spec["physical_hosts"],
                                     "prod_certified_topology.sites.#{site}.physical_hosts")
      check_equal(errors, "#{site} network private block", canonical_spec.fetch("private_block"), address_domains[site])
      spec = prod_sites[site]
      next unless spec.is_a?(Hash)

      check_equal(errors, "#{site} private block", canonical_spec.fetch("private_block"), spec.fetch("private_block"))
      check_equal(errors, "#{site} exact physical hosts", canonical_hosts.sort, spec.fetch("physical_hosts").keys.sort)
      check_equal(errors, "#{site} physical hosts", topology.fetch("physical_hosts_per_site"), spec.fetch("physical_hosts").length)
      check_equal(errors, "#{site} control planes", topology.fetch("control_planes_per_site"), spec.fetch("control_planes").length)
      check_equal(errors, "#{site} data workers", topology.fetch("data_workers_per_site"), spec.fetch("data_workers").length)
      check_equal(errors, "#{site} general workers", topology.fetch("general_workers_per_site"), spec.fetch("general_workers").length)
      check_equal(errors, "#{site} workers", topology.fetch("workers_per_site"),
                  spec.fetch("data_workers").length + spec.fetch("general_workers").length)
    end
    total_physical_hosts = expected_prod_sites.sum do |site|
      prod_sites.fetch(site, {}).fetch("physical_hosts", {}).length
    end
    check_equal(errors, "PROD total physical hosts", topology.fetch("physical_hosts_total"), total_physical_hosts)
    canonical_prod_hosts = topology_sites.values.flat_map { |site| site.fetch("physical_hosts") }
    inventory_prod_hosts = prod_sites.values.flat_map { |site| site.fetch("physical_hosts", {}).keys }
    errors << "canonical PROD physical hosts must be globally unique across sites" unless canonical_prod_hosts.uniq.length == canonical_prod_hosts.length
    errors << "inventory PROD physical hosts must be globally unique across sites" unless inventory_prod_hosts.uniq.length == inventory_prod_hosts.length
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
        "workload_identity" => "spire", "iam" => "keycloak", "runtime_security" => "tetragon",
        "autoscaling" => {
          "synchronous_pods" => "kubernetes-hpa", "event_driven_pods" => "keda",
          "certified_nodes" => "fixed", "preprod_perf_burst" => "gate-only"
        }
      },
      "stateful" => {
        "database" => "cloudnativepg-postgresql", "events" => "strimzi-kafka-kraft",
        "jobs" => "rabbitmq-quorum-queues", "cache" => "redis-cluster", "search" => "opensearch",
        "object_storage" => "seaweedfs-s3"
      },
      "observability" => {
        "telemetry" => "opentelemetry", "application_gateway" => "rotel",
        "infrastructure_collector" => "opentelemetry-collector", "metrics_protocol" => "prometheus",
        "metrics_scraper" => "vmagent", "metrics" => "victoriametrics", "infrastructure_logs" => "victorialogs",
        "application_observability_storage" => "clickhouse", "application_observability_ui" => "hyperdx",
        "hyperdx_metadata_store" => "mongodb-oss-self-hosted",
        "alerts" => "vmalert", "notifications" => "alertmanager", "dashboards" => "grafana",
        "security_pipeline" => "data-prepper", "security_logs" => "opensearch", "security" => "wazuh"
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

    mgmt_control_planes = expect_mapping(mgmt["control_planes"], "mgmt-inventory.yaml control_planes")
    mgmt_workers = expect_mapping(mgmt["workers"], "mgmt-inventory.yaml workers")
    mgmt_profiles = expect_mapping(mgmt["vm_profiles"], "mgmt-inventory.yaml vm_profiles")

    expected_mgmt_control_planes = %w[cp-01 cp-02 cp-03]
    expected_mgmt_workers = %w[worker-01 worker-02 worker-03]

    check_equal(errors, "MGMT exact control planes", expected_mgmt_control_planes, mgmt_control_planes.keys.sort)
    check_equal(errors, "MGMT exact workers", expected_mgmt_workers, mgmt_workers.keys.sort)

    mgmt_nodes = mgmt_control_planes.merge(mgmt_workers)

    mgmt_inventory_ips = []
    mgmt_nodes.each_value do |node|
      mgmt_inventory_ips << node.fetch("mgmt_ip")
      mgmt_inventory_ips << node.fetch("k8s_ip")
    end
    mgmt_workers.each_value do |node|
      mgmt_inventory_ips << node.fetch("storage_ip")
      mgmt_inventory_ips << node.fetch("backup_ip")
    end

    duplicates = mgmt_inventory_ips.group_by(&:itself).select { |_ip, values| values.length > 1 }.keys
    duplicates.each { |ip| errors << "duplicate static IP #{ip} in mgmt-inventory.yaml" }

    mgmt_mgmt_subnet = IPAddr.new(network.dig("vlans", "mgmt", 401, "cidr"))
    mgmt_k8s_subnet = IPAddr.new(network.dig("vlans", "mgmt", 402, "cidr"))
    mgmt_storage_subnet = IPAddr.new(network.dig("vlans", "mgmt", 403, "cidr"))
    mgmt_backup_subnet = IPAddr.new(network.dig("vlans", "mgmt", 405, "cidr"))

    mgmt_nodes.each do |name, node|
      mgmt_ip = IPAddr.new(node.fetch("mgmt_ip"))
      k8s_ip = IPAddr.new(node.fetch("k8s_ip"))

      errors << "outside MGMT mgmt subnet for #{name}" unless mgmt_mgmt_subnet.include?(mgmt_ip)
      errors << "outside MGMT k8s subnet for #{name}" unless mgmt_k8s_subnet.include?(k8s_ip)

      profile = node.fetch("profile")
      errors << "MGMT unknown profile #{profile} for #{name}" unless mgmt_profiles.key?(profile)

      expected_mgmt_ip = network.dig("static_allocations", "mgmt", 401, name)
      expected_k8s_ip = network.dig("static_allocations", "mgmt", 402, name)

      check_equal(errors, "MGMT #{name} mgmt_ip", expected_mgmt_ip, node.fetch("mgmt_ip"))
      check_equal(errors, "MGMT #{name} k8s_ip", expected_k8s_ip, node.fetch("k8s_ip"))
    end

    mgmt_workers.each do |name, node|
      storage_ip = IPAddr.new(node.fetch("storage_ip"))
      backup_ip = IPAddr.new(node.fetch("backup_ip"))

      errors << "outside MGMT storage subnet for #{name}" unless mgmt_storage_subnet.include?(storage_ip)
      errors << "outside MGMT backup subnet for #{name}" unless mgmt_backup_subnet.include?(backup_ip)

      expected_storage_ip = network.dig("static_allocations", "mgmt", 403, name)
      expected_backup_ip = network.dig("static_allocations", "mgmt", 405, name)

      check_equal(errors, "MGMT #{name} storage_ip", expected_storage_ip, node.fetch("storage_ip"))
      check_equal(errors, "MGMT #{name} backup_ip", expected_backup_ip, node.fetch("backup_ip"))
    end

    check_equal(errors, "MGMT private block", network.dig("address_domains", "mgmt"), mgmt.fetch("private_block"))

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
  rescue ContractLoadError => e
    [e.message]
  rescue KeyError, TypeError, NoMethodError, ArgumentError => e
    ["architecture contract structure is invalid: #{e.message}"]
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
