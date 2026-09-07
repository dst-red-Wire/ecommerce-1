#!/usr/bin/env ruby
# frozen_string_literal: true

require "json"
require "yaml"

module ResourceSizing
  REQUIRED_POSITIVE_METRICS = %w[
    cpu_p50_millicores cpu_p95_millicores cpu_p99_millicores
    memory_rss_p95_mib memory_rss_peak_mib
    ephemeral_storage_p95_mib ephemeral_storage_peak_mib
    request_rate latency_p95_ms latency_p99_ms
  ].freeze

  module_function

  def positive_number!(evidence, key)
    value = evidence.fetch(key)
    number = Float(value)
    raise ArgumentError, "#{key} must be finite and positive" unless number.finite? && number.positive?

    number
  rescue KeyError, TypeError, ArgumentError => e
    raise ArgumentError, "invalid #{key}: #{e.message}"
  end

  def round_up(value, quantum)
    ((value.to_f / quantum).ceil * quantum).to_i
  end

  def validate_evidence!(evidence, policy)
    component = evidence.fetch("component")
    raise ArgumentError, "component must be a non-empty string" unless component.is_a?(String) && !component.strip.empty?

    sha = evidence.fetch("source_sha")
    raise ArgumentError, "source_sha must be a full 40 character Git SHA" unless sha.is_a?(String) && sha.match?(/\A[0-9a-f]{40}\z/)
    raise ArgumentError, "representative must be true" unless evidence["representative"] == true

    minimum_window = Integer(policy.dig("measurement", "minimum_window_seconds"))
    window = Integer(evidence.fetch("window_seconds"))
    raise ArgumentError, "window_seconds must be at least #{minimum_window}" if window < minimum_window

    REQUIRED_POSITIVE_METRICS.each { |key| positive_number!(evidence, key) }
    error_rate = Float(evidence.fetch("error_rate"))
    raise ArgumentError, "error_rate must be finite and non-negative" unless error_rate.finite? && error_rate >= 0
    raise ArgumentError, "cpu_p99_millicores must be >= cpu_p95_millicores" if positive_number!(evidence, "cpu_p99_millicores") < positive_number!(evidence, "cpu_p95_millicores")
    raise ArgumentError, "memory_rss_peak_mib must be >= memory_rss_p95_mib" if positive_number!(evidence, "memory_rss_peak_mib") < positive_number!(evidence, "memory_rss_p95_mib")
    raise ArgumentError, "ephemeral_storage_peak_mib must be >= ephemeral_storage_p95_mib" if positive_number!(evidence, "ephemeral_storage_peak_mib") < positive_number!(evidence, "ephemeral_storage_p95_mib")
    raise ArgumentError, "latency_p99_ms must be >= latency_p95_ms" if positive_number!(evidence, "latency_p99_ms") < positive_number!(evidence, "latency_p95_ms")
  rescue KeyError, TypeError, ArgumentError => e
    raise ArgumentError, e.message
  end

  def candidate(evidence, policy)
    validate_evidence!(evidence, policy)
    factors = policy.fetch("right_sizing").fetch("factors")
    rounding = policy.fetch("right_sizing").fetch("rounding")

    cpu_request = round_up(
      positive_number!(evidence, "cpu_p95_millicores") * Float(factors.fetch("cpu_request_from_p95")),
      Integer(rounding.fetch("cpu_request_millicores"))
    )
    cpu_limit = round_up(
      positive_number!(evidence, "cpu_p99_millicores") * Float(factors.fetch("cpu_limit_from_p99")),
      Integer(rounding.fetch("cpu_limit_millicores"))
    )
    memory_request = round_up(
      positive_number!(evidence, "memory_rss_p95_mib") * Float(factors.fetch("memory_request_from_rss_p95")),
      Integer(rounding.fetch("memory_mib"))
    )
    memory_limit = round_up(
      positive_number!(evidence, "memory_rss_peak_mib") * Float(factors.fetch("memory_limit_from_rss_peak")),
      Integer(rounding.fetch("memory_mib"))
    )
    ephemeral_request = round_up(
      positive_number!(evidence, "ephemeral_storage_p95_mib") * Float(factors.fetch("ephemeral_request_from_p95")),
      Integer(rounding.fetch("ephemeral_storage_mib"))
    )
    ephemeral_limit = round_up(
      positive_number!(evidence, "ephemeral_storage_peak_mib") * Float(factors.fetch("ephemeral_limit_from_peak")),
      Integer(rounding.fetch("ephemeral_storage_mib"))
    )

    memory_limit = [memory_limit, memory_request].max
    cpu_limit = [cpu_limit, cpu_request].max
    ephemeral_limit = [ephemeral_limit, ephemeral_request].max

    fraction = Float(policy.dig("go_runtime", "gomemlimit", "default_fraction"))
    memory_quantum = Integer(rounding.fetch("memory_mib"))
    gomemlimit = [((memory_limit * fraction) / memory_quantum).floor * memory_quantum, memory_quantum].max

    {
      "version" => 1,
      "candidate_only" => true,
      "component" => evidence.fetch("component"),
      "source_sha" => evidence.fetch("source_sha"),
      "window_seconds" => Integer(evidence.fetch("window_seconds")),
      "resources" => {
        "requests" => {
          "cpu" => "#{cpu_request}m",
          "memory" => "#{memory_request}Mi",
          "ephemeral-storage" => "#{ephemeral_request}Mi"
        },
        "limits" => {
          "cpu" => "#{cpu_limit}m",
          "memory" => "#{memory_limit}Mi",
          "ephemeral-storage" => "#{ephemeral_limit}Mi"
        }
      },
      "go_runtime" => {
        "GOMEMLIMIT" => "#{gomemlimit}MiB",
        "GOMAXPROCS" => "runtime-container-aware"
      },
      "promotion_requires" => policy.fetch("right_sizing").fetch("promotion_requires")
    }
  end

  def load_policy(root)
    YAML.safe_load(
      File.read(File.join(root, "config/contracts/runtime-efficiency.yaml")),
      aliases: false,
      filename: "config/contracts/runtime-efficiency.yaml"
    )
  end
end

if $PROGRAM_NAME == __FILE__
  evidence_path = ARGV.fetch(0) do
    warn "usage: ruby scripts/resource-sizing.rb <evidence.json>"
    exit 2
  end
  root = File.expand_path("..", __dir__)
  evidence = JSON.parse(File.read(evidence_path))
  puts YAML.dump(ResourceSizing.candidate(evidence, ResourceSizing.load_policy(root)))
end
