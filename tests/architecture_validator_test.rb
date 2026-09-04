# frozen_string_literal: true

require "fileutils"
require "minitest/autorun"
require "tmpdir"
require "yaml"
require_relative "../scripts/validate-architecture"

class ArchitectureValidatorTest < Minitest::Test
  ROOT = File.expand_path("..", __dir__)
  CONTRACT_FILES = %w[
    architecture.lock.yaml
    config/contracts/dependency-map.yaml
    config/contracts/event-contracts.yaml
    config/contracts/service-ownership.yaml
    config/infrastructure/network-plan.yaml
    config/infrastructure/prod-inventory.yaml
    docs/architecture/EVENT_CONTRACT_MATRIX.md
    docs/architecture/SERVICE_OWNERSHIP_MATRIX.md
  ].freeze

  def test_repository_contracts_are_consistent
    assert_empty ArchitectureValidator.validate(ROOT)
  end

  SERVICE_MUTATIONS = {
    "checkout in dependency map" => lambda { |root|
      mutate_yaml(root, "config/contracts/dependency-map.yaml") do |data|
        data["services"]["checkout"] = {"sync" => [], "events_in" => []}
      end
    },
    "arbitrary service in dependency map" => lambda { |root|
      mutate_yaml(root, "config/contracts/dependency-map.yaml") do |data|
        data["services"]["warehouse"] = {"sync" => [], "events_in" => []}
      end
    },
    "missing canonical service" => lambda { |root|
      mutate_yaml(root, "config/contracts/dependency-map.yaml") { |data| data["services"].delete("catalog") }
    }
  }.freeze

  SERVICE_MUTATIONS.each do |label, mutation|
    define_method("test_rejects_#{label.tr(' ', '_')}") do
      with_contract_copy do |root|
        mutation.call(root)
        errors = ArchitectureValidator.validate(root)
        refute_empty errors
        assert errors.any? { |error| error.include?("17 services in dependency-map.yaml") }
      end
    end
  end

  def test_checkout_error_identifies_the_active_machine_contract
    with_contract_copy do |root|
      SERVICE_MUTATIONS.fetch("checkout in dependency map").call(root)
      assert_includes ArchitectureValidator.validate(root), "checkout service is forbidden in dependency-map.yaml"
    end
  end

  def test_event_contract_failures
    mutations = {
      "active event catalogue" => lambda { |data| data["events"].delete("notification.NotificationFailed.v1") },
      "unknown producer warehouse" => lambda { |data| data["events"]["warehouse.InventoryMoved.v1"] = {"consumers" => []} },
      "unknown consumer warehouse" => lambda { |data| data["events"]["cart.CartUpdated.v1"]["consumers"] = ["warehouse"] }
    }
    mutations.each do |message, mutation|
      with_contract_copy do |root|
        mutate_yaml(root, "config/contracts/event-contracts.yaml", &mutation)
        errors = ArchitectureValidator.validate(root)
        refute_empty errors, message
        assert errors.any? { |error| error.include?(message) }, message
      end
    end
  end

  def test_dependency_contract_failures
    mutations = {
      "event inputs" => lambda { |data| data["services"]["notification"]["events_in"].delete("OrderFailed.v1") },
      "dependency map internal sync" => lambda { |data| data["services"]["inventory"]["sync"] = ["order"] }
    }
    mutations.each do |message, mutation|
      with_contract_copy do |root|
        mutate_yaml(root, "config/contracts/dependency-map.yaml", &mutation)
        assert ArchitectureValidator.validate(root).any? { |error| error.include?(message) }
      end
    end
  end

  def test_ipam_failures
    mutations = {
      "duplicate static IP" => lambda { |data| data["static_allocations"]["preprod"][401]["pve-02"] = "10.240.1.11" },
      "outside" => lambda { |data| data["static_allocations"]["preprod"][401]["pve-01"] = "10.240.2.11" },
      "overlaps perf-workers pool" => lambda { |data| data["static_allocations"]["preprod"][402]["worker-01"] = "10.240.2.201" },
      "dynamic pool overlap" => lambda { |data| data["dynamic_pools"]["preprod"][402]["perf-workers-2"] = "10.240.2.204/30" },
      "pool is outside" => lambda { |data| data["dynamic_pools"]["preprod"][402]["perf-workers"] = "10.240.3.200/29" },
      "CIDR overlap" => lambda { |data| data["kubernetes"]["preprod"]["pod_cidr"] = "10.240.0.0/16" }
    }
    mutations.each do |message, mutation|
      with_contract_copy do |root|
        mutate_yaml(root, "config/infrastructure/network-plan.yaml", &mutation)
        assert ArchitectureValidator.validate(root).any? { |error| error.include?(message) }, message
      end
    end
  end

  def test_rejects_network_and_broadcast_static_addresses
    {
      "network address 10.240.1.0" => "10.240.1.0",
      "broadcast address 10.240.1.255" => "10.240.1.255"
    }.each do |message, address|
      with_contract_copy do |root|
        mutate_yaml(root, "config/infrastructure/network-plan.yaml") do |data|
          data["static_allocations"]["preprod"][401]["pve-01"] = address
        end
        assert ArchitectureValidator.validate(root).any? { |error| error.include?(message) }, message
      end
    end
  end

  def test_rejects_reserved_static_address_ranges
    {
      "gateway_and_vips reserved address" => "10.240.1.1",
      "future_reserved reserved address" => "10.240.1.240"
    }.each do |message, address|
      with_contract_copy do |root|
        mutate_yaml(root, "config/infrastructure/network-plan.yaml") do |data|
          data["static_allocations"]["preprod"][401]["pve-01"] = address
        end
        assert ArchitectureValidator.validate(root).any? { |error| error.include?(message) }, message
      end
    end
  end

  def test_rejects_missing_and_additional_prod_sites
    {
      "missing prod-b" => lambda { |sites| sites.delete("prod-b") },
      "additional prod-c" => lambda { |sites| sites["prod-c"] = {} }
    }.each do |message, mutation|
      with_contract_copy do |root|
        mutate_yaml(root, "config/infrastructure/prod-inventory.yaml") { |data| mutation.call(data["sites"]) }
        errors = ArchitectureValidator.validate(root)
        assert errors.any? { |error| error.include?("exact PROD sites") }, message
      end
    end
  end

  def test_rejects_prod_inventory_inconsistent_with_certified_totals
    with_contract_copy do |root|
      mutate_yaml(root, "config/infrastructure/prod-inventory.yaml") do |data|
        data["sites"]["prod-b"]["physical_hosts"].delete("b-host-03")
      end
      errors = ArchitectureValidator.validate(root)
      assert errors.any? { |error| error.include?("prod-b physical hosts") }
      assert errors.any? { |error| error.include?("PROD total physical hosts") }
    end
  end

  def test_rejects_cross_database_read_policy_corruption
    {
      "service-ownership.yaml" => ["config/contracts/service-ownership.yaml", %w[forbidden cross_database_reads]],
      "dependency-map.yaml" => ["config/contracts/dependency-map.yaml", %w[rules no_cross_database_reads]]
    }.each do |contract, (path, keys)|
      with_contract_copy do |root|
        mutate_yaml(root, path) { |data| data.dig(*keys[0...-1])[keys.last] = false }
        label = "#{contract} #{keys.join('.')}"
        assert ArchitectureValidator.validate(root).any? { |error| error.include?(label) }, label
      end
    end
  end

  def test_rejects_event_safety_semantics_corruption
    mutations = {
      "delivery" => "at-most-once",
      "producer_pattern" => "direct-publish",
      "consumer_idempotent" => false,
      "global_ordering" => true,
      "aggregate_key_ordering" => false,
      "secrets_in_events" => "allowed",
      "unnecessary_pii_in_events" => "allowed"
    }
    mutations.each do |field, value|
      with_contract_copy do |root|
        mutate_yaml(root, "config/contracts/event-contracts.yaml") { |data| data["semantics"][field] = value }
        label = "event-contracts.yaml semantics.#{field}"
        assert ArchitectureValidator.validate(root).any? { |error| error.include?(label) }, label
      end
    end
  end

  def test_machine_contract_path_must_exist
    with_contract_copy do |root|
      mutate_yaml(root, "architecture.lock.yaml") do |data|
        data["machine_contracts"]["network_plan"] = "config/infrastructure/missing-network-plan.yaml"
      end
      assert_includes ArchitectureValidator.validate(root),
                      "architecture.lock.yaml machine_contracts.network_plan declared file does not exist: " \
                      "config/infrastructure/missing-network-plan.yaml"
    end
  end

  def test_validator_consumes_declared_machine_contract_path
    with_contract_copy do |root|
      alternate = "config/infrastructure/alternate-network-plan.yaml"
      FileUtils.cp(File.join(root, "config/infrastructure/network-plan.yaml"), File.join(root, alternate))
      mutate_yaml(root, alternate) { |data| data["validation"]["require_unique_ips"] = false }
      mutate_yaml(root, "architecture.lock.yaml") { |data| data["machine_contracts"]["network_plan"] = alternate }

      assert ArchitectureValidator.validate(root).any? do |error|
        error.include?("network-plan.validation.require_unique_ips")
      end
    end
  end

  def test_rejects_machine_contract_path_outside_repository
    with_contract_copy do |root|
      mutate_yaml(root, "architecture.lock.yaml") do |data|
        data["machine_contracts"]["network_plan"] = "../network-plan.yaml"
      end
      assert ArchitectureValidator.validate(root).any? { |error| error.include?("must stay within the repository") }
    end
  end

  def test_rejects_external_dependency_reclassified_as_internal
    with_contract_copy do |root|
      mutate_yaml(root, "config/contracts/dependency-map.yaml") do |data|
        payment = data["services"]["payment"]
        payment["sync_external"].delete("stripe")
        payment["sync"] << "stripe"
      end
      errors = ArchitectureValidator.validate(root)
      assert errors.any? { |error| error.include?("dependency map internal sync for payment") }
      assert errors.any? { |error| error.include?("dependency map external sync for payment") }
    end
  end

  def test_lock_invariants_independently
    mutations = {
      %w[prod_certified_topology physical_hosts_total] => 5,
      %w[prod_certified_topology physical_hosts_per_site] => 4,
      %w[prod_certified_topology control_planes_per_site] => 2,
      %w[prod_certified_topology workers_per_site] => 4,
      %w[prod_certified_topology data_workers_per_site] => 2,
      %w[prod_certified_topology general_workers_per_site] => 1,
      %w[supply_chain immutable_images] => false,
      %w[supply_chain forbid_latest] => false,
      %w[platform gitops] => "argo-rollouts",
      %w[platform ci] => "github-actions",
      %w[platform progressive_delivery] => "flagger",
      %w[platform registry] => "docker-hub",
      %w[stateful object_storage] => "minio-community",
      %w[observability log_shipper] => "vector",
      %w[observability log_pipeline] => "logstash",
      %w[observability logs] => "loki",
      %w[observability security] => "splunk"
    }
    mutations.each do |path, value|
      with_contract_copy do |root|
        mutate_yaml(root, "architecture.lock.yaml") { |data| data.dig(*path[0...-1])[path.last] = value }
        assert ArchitectureValidator.validate(root).any? { |error| error.include?(path.join(".")) }, path.join(".")
      end
    end
  end

  def test_network_policy_invariants_independently
    %w[require_unique_ips require_non_overlapping_cidrs require_site_isolation require_underlay_pod_service_separation public_ips_runtime_injected_only].each do |field|
      with_contract_copy do |root|
        mutate_yaml(root, "config/infrastructure/network-plan.yaml") { |data| data["validation"][field] = false }
        assert ArchitectureValidator.validate(root).any? { |error| error.include?("validation.#{field}") }, field
      end
    end
  end

  private

  def self.mutate_yaml(root, relative)
    path = File.join(root, relative)
    data = YAML.safe_load_file(path, aliases: false)
    yield data
    File.write(path, YAML.dump(data))
  end

  def mutate_yaml(root, relative, &block)
    self.class.mutate_yaml(root, relative, &block)
  end

  def with_contract_copy
    Dir.mktmpdir do |root|
      CONTRACT_FILES.each do |relative|
        target = File.join(root, relative)
        FileUtils.mkdir_p(File.dirname(target))
        FileUtils.cp(File.join(ROOT, relative), target)
      end
      yield root
    end
  end
end
