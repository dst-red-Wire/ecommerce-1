# frozen_string_literal: true

require "minitest/autorun"
require_relative "../scripts/validate-observability"

class ObservabilityDurationMapTest < Minitest::Test
  def test_duration_map_rejects_extra_environment_key
    refute ObservabilityTopologyValidator.duration_map?({"preprod" => "12h", "prod" => "6h", "foo" => "1h"})
  end

  def test_retention_map_rejects_extra_environment_key
    refute ObservabilityTopologyValidator.retention_contract?({"preprod" => "14d", "prod" => "30d", "foo" => "1d"})
  end

  def test_opensearch_retention_requires_exact_hot_and_snapshot_keys
    value = {"preprod_hot" => "14d", "prod_hot" => "30d", "prod_snapshots" => "365d"}
    assert ObservabilityTopologyValidator.retention_contract?(value, %w[preprod_hot prod_hot prod_snapshots])
    refute ObservabilityTopologyValidator.retention_contract?(value.merge("foo" => "1d"), %w[preprod_hot prod_hot prod_snapshots])
  end
end
