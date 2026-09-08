# frozen_string_literal: true

require "fileutils"
require "minitest/autorun"
require "tmpdir"
require "yaml"
require_relative "../scripts/validate-observability"

class ObservabilityTopologyTest < Minitest::Test
  ROOT = File.expand_path("..", __dir__)

  def test_repository_contract_is_exact
    assert_empty ObservabilityTopologyValidator.validate(ROOT)
  end

  def test_rejects_prometheus_as_primary_tsdb
    with_contract_copy do |root|
      mutate_yaml(root, "architecture.lock.yaml") do |data|
        data["observability"]["metrics"] = "prometheus"
      end
      assert_includes ObservabilityTopologyValidator.validate(root),
                      "architecture.lock.yaml observability summary drift"
    end
  end

  def test_rejects_data_prepper_as_general_log_pipeline
    with_contract_copy do |root|
      mutate_yaml(root, "config/contracts/observability-topology.yaml") do |data|
        data["security_telemetry"]["forbidden_purposes"].delete("general-application-logs")
      end
      assert_includes ObservabilityTopologyValidator.validate(root), "Data Prepper must remain security-only"
    end
  end

  def test_rejects_overlapping_application_gateway
    with_contract_copy do |root|
      mutate_yaml(root, "config/contracts/observability-topology.yaml") do |data|
        data["authorities"]["application_telemetry_gateway"] = "opentelemetry-collector"
      end
      assert_includes ObservabilityTopologyValidator.validate(root), "observability authority map drift"
    end
  end

  private

  def with_contract_copy
    Dir.mktmpdir("observability-topology") do |root|
      %w[architecture.lock.yaml config/contracts/observability-topology.yaml].each do |relative|
        target = File.join(root, relative)
        FileUtils.mkdir_p(File.dirname(target))
        FileUtils.cp(File.join(ROOT, relative), target)
      end
      yield root
    end
  end

  def mutate_yaml(root, relative)
    path = File.join(root, relative)
    data = YAML.safe_load(File.read(path), aliases: false)
    yield data
    File.write(path, YAML.dump(data))
  end
end
