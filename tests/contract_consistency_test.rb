# frozen_string_literal: true

require "fileutils"
require "minitest/autorun"
require "tmpdir"
require "yaml"
require_relative "../scripts/validate-contract-consistency"

class ContractConsistencyTest < Minitest::Test
  def write_yaml(root, path, value)
    absolute = File.join(root, path)
    FileUtils.mkdir_p(File.dirname(absolute))
    File.write(absolute, value.to_yaml)
  end

  def fixture(root)
    write_yaml(root, "architecture.lock.yaml", {
      "business" => {"services" => %w[product catalog], "frontends" => ["admin"]},
      "machine_contracts" => {
        "service_ownership" => "config/contracts/service-ownership.yaml",
        "dependency_map" => "config/contracts/dependency-map.yaml",
        "event_contracts" => "config/contracts/event-contracts.yaml",
        "public_api_contracts" => "config/contracts/public-api-contracts.yaml"
      }
    })
    write_yaml(root, "config/contracts/service-ownership.yaml", {
      "services" => {
        "product" => {"sync_dependencies" => []},
        "catalog" => {"sync_dependencies" => ["product"]}
      }
    })
    write_yaml(root, "config/contracts/dependency-map.yaml", {
      "services" => {
        "product" => {"sync" => [], "events_in" => []},
        "catalog" => {"sync" => ["product"], "events_in" => ["ProductUpdated.v1"]}
      }
    })
    write_yaml(root, "config/contracts/event-contracts.yaml", {
      "events" => {"product.ProductUpdated.v1" => {"consumers" => ["catalog"]}}
    })
    write_yaml(root, "config/contracts/public-api-contracts.yaml", {
      "contracts" => {"product" => {"audiences" => ["admin"]}}
    })
  end

  def test_valid_cross_registry_contracts_pass
    Dir.mktmpdir do |root|
      fixture(root)
      assert_empty ContractConsistency.validate(root)
    end
  end

  def test_sync_drift_fails
    Dir.mktmpdir do |root|
      fixture(root)
      write_yaml(root, "config/contracts/service-ownership.yaml", {
        "services" => {
          "product" => {"sync_dependencies" => []},
          "catalog" => {"sync_dependencies" => []}
        }
      })
      assert ContractConsistency.validate(root).any? { |error| error.include?("sync_dependencies differs") }
    end
  end

  def test_event_consumer_drift_fails
    Dir.mktmpdir do |root|
      fixture(root)
      write_yaml(root, "config/contracts/dependency-map.yaml", {
        "services" => {
          "product" => {"sync" => [], "events_in" => []},
          "catalog" => {"sync" => ["product"], "events_in" => []}
        }
      })
      assert ContractConsistency.validate(root).any? { |error| error.include?("missing ProductUpdated.v1") }
    end
  end
end
