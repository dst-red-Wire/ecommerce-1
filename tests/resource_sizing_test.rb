# frozen_string_literal: true

require "minitest/autorun"
require_relative "../scripts/resource-sizing"

class ResourceSizingTest < Minitest::Test
  ROOT = File.expand_path("..", __dir__)

  def evidence
    {
      "component" => "product",
      "source_sha" => "a" * 40,
      "representative" => true,
      "window_seconds" => 3600,
      "cpu_p50_millicores" => 54,
      "cpu_p95_millicores" => 91,
      "cpu_p99_millicores" => 144,
      "memory_rss_p95_mib" => 61,
      "memory_rss_peak_mib" => 79,
      "ephemeral_storage_p95_mib" => 17,
      "ephemeral_storage_peak_mib" => 25,
      "request_rate" => 250,
      "latency_p95_ms" => 18,
      "latency_p99_ms" => 27,
      "error_rate" => 0
    }
  end

  def test_candidate_is_deterministic_and_keeps_headroom
    result = ResourceSizing.candidate(evidence, ResourceSizing.load_policy(ROOT))
    assert_equal true, result.fetch("candidate_only")
    assert_equal "110m", result.dig("resources", "requests", "cpu")
    assert_equal "1000m", result.dig("resources", "limits", "cpu")
    assert_equal "80Mi", result.dig("resources", "requests", "memory")
    assert_equal "96Mi", result.dig("resources", "limits", "memory")
    assert_equal "32Mi", result.dig("resources", "requests", "ephemeral-storage")
    assert_equal "32Mi", result.dig("resources", "limits", "ephemeral-storage")
    assert_equal "80MiB", result.dig("go_runtime", "GOMEMLIMIT")
  end

  def test_unrepresentative_evidence_fails_closed
    bad = evidence.merge("representative" => false)
    assert_raises(ArgumentError) { ResourceSizing.candidate(bad, ResourceSizing.load_policy(ROOT)) }
  end

  def test_short_measurement_window_fails_closed
    bad = evidence.merge("window_seconds" => 60)
    assert_raises(ArgumentError) { ResourceSizing.candidate(bad, ResourceSizing.load_policy(ROOT)) }
  end
end
