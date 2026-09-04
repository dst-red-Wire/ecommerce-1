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
      "dependency map sync" => lambda { |data| data["services"]["inventory"]["sync"] = ["order"] }
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
      %w[platform progressive_delivery] => "flagger",
      %w[stateful object_storage] => "minio-community",
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
