# frozen_string_literal: true

require "fileutils"
require "minitest/autorun"
require "tmpdir"
require "yaml"
require_relative "../scripts/validate-architecture"

class ArchitectureValidatorTest < Minitest::Test
  ROOT = File.expand_path("..", __dir__)
  BASE_CONTRACT_FILES = %w[
    architecture.lock.yaml
    config/contracts/dependency-map.yaml
    config/contracts/event-contracts.yaml
    config/contracts/service-ownership.yaml
    docs/architecture/EVENT_CONTRACT_MATRIX.md
    docs/architecture/SERVICE_OWNERSHIP_MATRIX.md
  ].freeze

  def contract_files(root = ROOT)
    lock = YAML.safe_load(File.read(File.join(root, "architecture.lock.yaml")))
    machine_contracts = lock.fetch("machine_contracts").values
    (BASE_CONTRACT_FILES + machine_contracts).uniq
  end

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

  def test_mgmt_inventory_failures
    mutations = {
      "duplicate static IP" => lambda { |root|
        mutate_yaml(root, "config/infrastructure/mgmt-inventory.yaml") do |data|
          data["workers"]["worker-01"]["mgmt_ip"] = data["control_planes"]["cp-01"]["mgmt_ip"]
        end
      },
      "outside" => lambda { |root|
        mutate_yaml(root, "config/infrastructure/mgmt-inventory.yaml") do |data|
          data["control_planes"]["cp-01"]["mgmt_ip"] = "10.243.2.61"
        end
      },
      "MGMT unknown profile" => lambda { |root|
        mutate_yaml(root, "config/infrastructure/mgmt-inventory.yaml") do |data|
          data["workers"]["worker-01"]["profile"] = "unknown-profile"
        end
      },
      "MGMT exact workers" => lambda { |root|
        mutate_yaml(root, "config/infrastructure/mgmt-inventory.yaml") do |data|
          data["workers"].delete("worker-03")
        end
      }
    }

    mutations.each do |message, mutation|
      with_contract_copy do |root|
        mutation.call(root)
        errors = ArchitectureValidator.validate(root)
        refute_empty errors, message
        assert errors.any? { |error| error.include?(message) }, message
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

  def test_rejects_coordinated_prod_site_rename
    with_contract_copy do |root|
      mutate_yaml(root, "config/infrastructure/network-plan.yaml") do |data|
        data["address_domains"]["prod-c"] = data["address_domains"].delete("prod-b")
        data["vlans"]["prod-c"] = data["vlans"].delete("prod-b")
        data["kubernetes"]["prod-c"] = data["kubernetes"].delete("prod-b")
      end
      mutate_yaml(root, "config/infrastructure/prod-inventory.yaml") do |data|
        data["sites"]["prod-c"] = data["sites"].delete("prod-b")
      end

      errors = ArchitectureValidator.validate(root)
      assert errors.any? { |error| error.include?("exact PROD network sites") }
      assert errors.any? { |error| error.include?("exact PROD sites") }
    end
  end

  def test_rejects_noncanonical_prod_physical_host_ids
    mutations = {
      "renamed host" => lambda { |hosts| hosts["renamed-host"] = hosts.delete("a-host-01") },
      "missing host" => lambda { |hosts| hosts.delete("a-host-01") },
      "compensated noncanonical host" => lambda { |hosts|
        hosts["extra-host"] = hosts.delete("a-host-01")
      }
    }
    mutations.each do |message, mutation|
      with_contract_copy do |root|
        mutate_yaml(root, "config/infrastructure/prod-inventory.yaml") do |data|
          mutation.call(data["sites"]["prod-a"]["physical_hosts"])
        end
        errors = ArchitectureValidator.validate(root)
        assert errors.any? { |error| error.include?("prod-a exact physical hosts") }, message
      end
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

  def test_all_declared_machine_contract_paths_must_exist
    %w[preprod_inventory storage_plan deployment_waves].each do |contract|
      with_contract_copy do |root|
        mutate_yaml(root, "architecture.lock.yaml") do |data|
          data["machine_contracts"][contract] = "config/infrastructure/missing-#{contract}.yaml"
        end
        errors = ArchitectureValidator.validate(root)
        assert errors.any? { |error| error.include?("machine_contracts.#{contract} declared file does not exist") },
               contract
      end
    end
  end

  def test_machine_contract_paths_must_be_nonempty_strings
    {"non-string" => 42, "empty" => "", "whitespace-only" => "  "}.each do |message, value|
      with_contract_copy do |root|
        mutate_yaml(root, "architecture.lock.yaml") do |data|
          data["machine_contracts"]["preprod_inventory"] = value
        end
        errors = ArchitectureValidator.validate(root)
        assert errors.any? { |error| error.include?("must declare a non-empty relative path") }, message
      end
    end
  end

  def test_machine_contract_keys_must_be_nonempty_strings
    {"empty" => "", "non-string" => 42}.each do |message, key|
      with_contract_copy do |root|
        mutate_yaml(root, "architecture.lock.yaml") { |data| data["machine_contracts"][key] = "unused.yaml" }
        errors = ArchitectureValidator.validate(root)
        assert errors.any? { |error| error.include?("machine_contracts keys must be non-empty strings") }, message
      end
    end
  end

  def test_rejects_absolute_machine_contract_path
    with_contract_copy do |root|
      mutate_yaml(root, "architecture.lock.yaml") do |data|
        data["machine_contracts"]["preprod_inventory"] = "/tmp/outside.yaml"
      end
      assert ArchitectureValidator.validate(root).any? { |error| error.include?("must declare a relative path") }
    end
  end

  def test_rejects_machine_contract_symlink_escape
    with_contract_copy do |root|
      Dir.mktmpdir("architecture-validator-outside") do |outside|
        outside_file = File.join(outside, "contract.yaml")
        File.write(outside_file, "version: 1\n")
        symlink = File.join(root, "config/infrastructure/outside-contract.yaml")
        File.symlink(outside_file, symlink)
        mutate_yaml(root, "architecture.lock.yaml") do |data|
          data["machine_contracts"]["preprod_inventory"] = "config/infrastructure/outside-contract.yaml"
        end

        assert ArchitectureValidator.validate(root).any? { |error| error.include?("resolves outside the repository") }
      end
    end
  end

  def test_rejects_duplicate_machine_contract_key
    with_contract_copy do |root|
      replace_in_file(root, "architecture.lock.yaml",
                      "  network_plan: config/infrastructure/network-plan.yaml\n",
                      "  network_plan: config/infrastructure/missing.yaml\n" \
                      "  network_plan: config/infrastructure/network-plan.yaml\n")
      errors = ArchitectureValidator.validate(root)
      assert errors.any? { |error| error.include?("duplicate YAML key \"machine_contracts.network_plan\"") }
    end
  end

  def test_rejects_duplicate_top_level_yaml_key
    with_contract_copy do |root|
      File.open(File.join(root, "architecture.lock.yaml"), "a") { |file| file.write("status: locked-for-build\n") }
      errors = ArchitectureValidator.validate(root)
      assert errors.any? { |error| error.include?("duplicate YAML key \"status\"") }
    end
  end

  def test_rejects_duplicate_nested_machine_contract_key
    with_contract_copy do |root|
      replace_in_file(root, "config/infrastructure/network-plan.yaml",
                      "  require_unique_ips: true\n",
                      "  require_unique_ips: false\n  require_unique_ips: true\n")
      errors = ArchitectureValidator.validate(root)
      assert errors.any? do |error|
        error.include?("network-plan.yaml") && error.include?("duplicate YAML key \"validation.require_unique_ips\"")
      end
    end
  end

  def test_reports_invalid_boundary_types_without_a_stack_trace
    mutations = {
      "machine_contracts" => ["architecture.lock.yaml", lambda { |data| data["machine_contracts"] = [] }],
      "semantics" => ["config/contracts/event-contracts.yaml", lambda { |data| data["semantics"] = "invalid" }],
      "static_allocations" => ["config/infrastructure/network-plan.yaml",
                               lambda { |data| data["static_allocations"] = "invalid" }]
    }
    mutations.each do |label, (path, mutation)|
      with_contract_copy do |root|
        mutate_yaml(root, path, &mutation)
        errors = ArchitectureValidator.validate(root)
        assert_equal 1, errors.length, label
        assert_includes errors.first, "must be a mapping", label
      end
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
      %w[platform runtime_security] => "falco",
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

  YAML_EQUIVALENT_KEYS = {
    "quoted_string" => ["network_plan", '"network_plan"'],
    "boolean" => ["true", "True"],
    "uppercase_boolean" => ["True", "TRUE"],
    "yaml_boolean_spellings" => ["yes", "ON"],
    "false_boolean" => ["false", "OFF"],
    "null" => ["null", "~"],
    "integer" => ["1", "01"],
    "float" => ["1.0", "1.00"],
    "explicit_string_tag" => ["network_plan", "!!str network_plan"],
    "exact_string" => ["network_plan", "network_plan"]
  }.freeze

  YAML_EQUIVALENT_KEYS.each do |label, (left, right)|
    define_method("test_rejects_semantically_duplicate_#{label}_keys") do
      yaml = "#{left}: first\n#{right}: second\n"
      # Psych itself is the oracle, including Ruby Hash identity.
      assert_equal 1, YAML.safe_load(yaml, aliases: false).size, label
      with_contract_copy do |root|
        path = "config/infrastructure/network-plan.yaml"
        File.write(File.join(root, path), yaml)
        error = assert_raises(ArchitectureValidator::ContractLoadError) do
          ArchitectureValidator.load_yaml(root, path)
        end
        assert_includes error.message, path
        assert_includes error.message, "duplicate YAML key"
        assert_includes error.message, "at line 2"
      end
    end
  end

  def test_rejects_quoted_machine_contract_path_override
    with_contract_copy do |root|
      replace_in_file(root, "architecture.lock.yaml",
                      "  network_plan: config/infrastructure/network-plan.yaml\n",
                      "  network_plan: config/infrastructure/missing.yaml\n" \
                      "  \"network_plan\": config/infrastructure/network-plan.yaml\n")
      errors = ArchitectureValidator.validate(root)
      assert_equal 1, errors.size
      assert_includes errors.first, 'duplicate YAML key "machine_contracts.network_plan"'
      assert_includes errors.first, "architecture.lock.yaml"
    end
  end

  def test_semantic_duplicates_are_rejected_in_every_declared_contract_and_lock
    with_contract_copy do |root|
      lock = YAML.safe_load_file(File.join(root, "architecture.lock.yaml"), aliases: false)
      (["architecture.lock.yaml"] + lock.fetch("machine_contracts").values).each do |path|
        original = File.read(File.join(root, path))
        File.write(File.join(root, path), original + "\nprobe:\n  items:\n    - true: first\n      True: second\n")
        errors = ArchitectureValidator.validate(root)
        assert_equal 1, errors.size, path
        assert_includes errors.first, path
        assert_includes errors.first, 'duplicate YAML key "probe.items.[0].true"'
        File.write(File.join(root, path), original)
      end
    end
  end

  def test_nested_semantic_duplicate
    with_contract_copy do |root|
      path = "config/infrastructure/network-plan.yaml"
      File.open(File.join(root, path), "a") { |file| file.write("\nprobe:\n  null: first\n  ~: second\n") }
      errors = ArchitectureValidator.validate(root)
      assert_equal 1, errors.size
      assert_includes errors.first, 'duplicate YAML key "probe.nil"'
    end
  end

  def test_distinct_scalar_keys_preserve_safe_load_hash_identity
    [
      ["1", '"1"'], ["1", "1.0"], ["true", '"true"'], ["null", '"null"'],
      ["false", '"false"'], ["1", "!!str 1"]
    ].each do |left, right|
      yaml = "#{left}: first\n#{right}: second\n"
      expected = YAML.safe_load(yaml, aliases: false)
      assert_equal 2, expected.size, yaml
      with_contract_copy do |root|
        path = "config/infrastructure/network-plan.yaml"
        File.write(File.join(root, path), yaml)
        assert_equal expected, ArchitectureValidator.load_yaml(root, path)
      end
    end
  end

  def test_distinct_non_string_machine_contract_key_reports_structural_error
    with_contract_copy do |root|
      replace_in_file(root, "architecture.lock.yaml", "machine_contracts:\n",
                      "machine_contracts:\n  1: unused.yaml\n  \"1\": unused.yaml\n")
      errors = ArchitectureValidator.validate(root)
      assert_equal ["architecture.lock.yaml machine_contracts keys must be non-empty strings"], errors
    end
  end

  UNSUPPORTED_YAML_KEYS = {
    "sequence" => "? [one, two]\n: ignored\n",
    "mapping" => "? {one: two}\n: ignored\n",
    "custom_tag" => "!private marker: ignored\n",
    "ruby_object" => "!ruby/object:Object marker: ignored\n",
    "symbol_tag" => "!ruby/symbol marker: ignored\n",
    "implicit_symbol" => ":marker: ignored\n",
    "date" => "2026-01-01: ignored\n",
    "invalid_float" => "!!float invalid: ignored\n",
    "alias" => "anchor: &key marker\n*key: ignored\n"
  }.freeze

  UNSUPPORTED_YAML_KEYS.each do |label, yaml|
    define_method("test_rejects_unsupported_#{label}_key_with_location") do
      with_contract_copy do |root|
        path = "config/infrastructure/network-plan.yaml"
        File.open(File.join(root, path), "a") do |file|
          file.write("\nprobe:\n")
          yaml.each_line { |line| file.write("  #{line}") }
        end
        errors = ArchitectureValidator.validate(root)
        assert_equal 1, errors.size
        assert_includes errors.first, path
        assert_includes errors.first, 'mapping "probe"'
        assert_includes errors.first, "at line"
        assert_includes errors.first, "unsupported YAML key type"
        refute_includes errors.first, "ignored"
        refute_includes errors.first, "marker"
      end
    end
  end

  def test_alias_values_remain_forbidden
    with_contract_copy do |root|
      path = "config/infrastructure/network-plan.yaml"
      File.open(File.join(root, path), "a") { |file| file.write("\nprobe: &value example\ncopy: *value\n") }
      errors = ArchitectureValidator.validate(root)
      assert_equal 1, errors.size
      assert_includes errors.first, "is not valid YAML"
      assert_includes errors.first, "alias"
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

  def replace_in_file(root, relative, current, replacement)
    path = File.join(root, relative)
    contents = File.read(path)
    raise "#{current.inspect} not found in #{relative}" unless contents.include?(current)

    File.write(path, contents.sub(current, replacement))
  end

  def with_contract_copy
    Dir.mktmpdir do |root|
      contract_files.each do |relative|
        target = File.join(root, relative)
        FileUtils.mkdir_p(File.dirname(target))
        FileUtils.cp(File.join(ROOT, relative), target)
      end
      yield root
    end
  end
end
