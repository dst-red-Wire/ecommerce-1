# frozen_string_literal: true

require "minitest/autorun"
require "yaml"
require_relative "../scripts/validate-runtime-efficiency"

class RuntimeEfficiencyTest < Minitest::Test
  ROOT = File.expand_path("..", __dir__)

  def test_repository_runtime_efficiency_baseline
    assert_empty RuntimeEfficiencyValidator.validate(ROOT)
  end

  def test_required_platforms_are_multi_arch
    policy = YAML.safe_load(File.read(File.join(ROOT, "config/contracts/runtime-efficiency.yaml")))
    assert_equal %w[linux/amd64 linux/arm64], policy.dig("images", "required_platforms")
  end

  def test_certified_node_scaling_is_fixed
    policy = YAML.safe_load(File.read(File.join(ROOT, "config/contracts/runtime-efficiency.yaml")))
    assert_equal "fixed-exact-contract", policy.dig("node_capacity", "mgmt")
    assert_equal "fixed-exact-contract", policy.dig("node_capacity", "preprod_certified_baseline")
    assert_equal "fixed-exact-contract", policy.dig("node_capacity", "prod")
    assert_equal "existing-gate-only", policy.dig("node_capacity", "preprod_perf_burst")
  end
end
