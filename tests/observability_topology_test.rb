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

  def test_deployment_wave_rejects_superseded_roles_and_missing_v5_components
    with_contract_copy do |root|
      path = File.join(root, "config/infrastructure/deployment-waves.yaml")
      original = File.read(path)
      %w[fluent-bit prometheus opensearch-logs].each do |component|
        data = YAML.safe_load(original, aliases: false)
        wave = data["waves"].find { |entry| entry["id"] == "50-observability" }
        wave["components"] << component
        File.write(path, YAML.dump(data))
        assert ObservabilityTopologyValidator.validate(root).any? { |error| error.include?("superseded general") }, component
      end
      %w[vmagent victoriametrics victorialogs].each do |component|
        data = YAML.safe_load(original, aliases: false)
        wave = data["waves"].find { |entry| entry["id"] == "50-observability" }
        wave["components"].delete(component)
        File.write(path, YAML.dump(data))
        assert ObservabilityTopologyValidator.validate(root).any? { |error| error.include?(component) }, component
      end
      File.write(path, original)
      assert_empty ObservabilityTopologyValidator.validate(root)
    end
  end

  def test_deployment_wave_requires_one_exact_observability_wave
    with_contract_copy do |root|
      path = File.join(root, "config/infrastructure/deployment-waves.yaml")
      original = File.read(path)
      data = YAML.safe_load(original, aliases: false)
      wave = data["waves"].find { |entry| entry["id"] == "50-observability" }

      data["waves"].delete(wave)
      File.write(path, YAML.dump(data))
      assert_includes ObservabilityTopologyValidator.validate(root),
                      "deployment wave 50-observability must occur exactly once"

      data = YAML.safe_load(original, aliases: false)
      data["waves"] << wave.merge("components" => ["prometheus"])
      File.write(path, YAML.dump(data))
      assert_includes ObservabilityTopologyValidator.validate(root),
                      "deployment wave 50-observability must occur exactly once"

      data = YAML.safe_load(original, aliases: false)
      data["waves"] << wave.dup
      File.write(path, YAML.dump(data))
      assert_includes ObservabilityTopologyValidator.validate(root),
                      "deployment wave 50-observability must occur exactly once"

      File.write(path, original)
      assert_empty ObservabilityTopologyValidator.validate(root)
    end
  end

  private

  def with_contract_copy
    Dir.mktmpdir("observability-topology") do |root|
      %w[architecture.lock.yaml config/contracts/observability-topology.yaml config/infrastructure/deployment-waves.yaml].each do |relative|
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
