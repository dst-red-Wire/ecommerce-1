#!/usr/bin/env ruby
# frozen_string_literal: true

require "yaml"

module RuntimeEfficiencyValidator
  EXPECTED_PLATFORMS = %w[linux/amd64 linux/arm64].freeze
  EXPECTED_GO_BUILDER_DIGEST = "sha256:116d58cbd88c1297624acc6e967a060012422bacf9930927e23fb719189c6f36"

  module_function

  def yaml(root, relative)
    YAML.safe_load(File.read(File.join(root, relative)), aliases: false, filename: relative)
  end

  def add(errors, condition, message)
    errors << message unless condition
  end

  def validate(root)
    errors = []
    lock = yaml(root, "architecture.lock.yaml")
    policy = yaml(root, "config/contracts/runtime-efficiency.yaml")

    add(errors, lock.dig("machine_contracts", "runtime_efficiency") == "config/contracts/runtime-efficiency.yaml",
        "architecture.lock.yaml must register the runtime efficiency machine contract")
    add(errors, lock.dig("platform", "autoscaling", "synchronous_pods") == "kubernetes-hpa",
        "synchronous pod autoscaling authority must be kubernetes-hpa")
    add(errors, lock.dig("platform", "autoscaling", "event_driven_pods") == "keda",
        "event-driven pod autoscaling authority must be keda")
    add(errors, lock.dig("platform", "autoscaling", "certified_nodes") == "fixed",
        "certified node topology must stay fixed")
    add(errors, policy["status"] == "exact", "runtime efficiency contract must be exact")
    add(errors, policy.dig("scope", "certified_node_topology_changes") == "forbidden",
        "certified topology changes must be forbidden")
    add(errors, policy.dig("scope", "production_resource_values_without_measurement") == "forbidden",
        "unmeasured production resource values must be forbidden")
    add(errors, policy.dig("right_sizing", "output") == "candidate-only",
        "right sizing output must remain candidate-only")

    platforms = policy.dig("images", "required_platforms")
    add(errors, platforms == EXPECTED_PLATFORMS, "OCI platforms must be linux/amd64 and linux/arm64")
    add(errors, policy.dig("images", "go_builder", "digest") == EXPECTED_GO_BUILDER_DIGEST,
        "Go builder must use the reviewed immutable multi-platform digest")
    add(errors, policy.dig("go_runtime", "gomaxprocs", "mode") == "runtime-container-aware",
        "Go must retain container-aware GOMAXPROCS defaults")

    gomem_fraction = policy.dig("go_runtime", "gomemlimit", "default_fraction")
    add(errors, gomem_fraction.is_a?(Numeric) && gomem_fraction.positive? && gomem_fraction < 1,
        "GOMEMLIMIT fraction must be between zero and one")
    add(errors, policy.dig("go_runtime", "pgo", "synthetic_profile_for_production") == "forbidden",
        "synthetic PGO profiles must not be promoted to production")

    add(errors, policy.dig("pod_autoscaling", "synchronous_http", "controller") == "kubernetes-hpa",
        "synchronous HTTP workloads must use HPA")
    add(errors, policy.dig("pod_autoscaling", "synchronous_http", "scale_to_zero") == "forbidden",
        "synchronous HTTP workloads must not scale to zero")
    add(errors, policy.dig("pod_autoscaling", "event_driven", "controller") == "keda",
        "event-driven workloads must use KEDA")
    add(errors, policy.dig("pod_autoscaling", "event_driven", "scale_to_zero_requires_non_cpu_memory_trigger") == true,
        "KEDA scale-to-zero must require a non CPU/memory trigger")

    %w[mgmt preprod_certified_baseline prod].each do |scope|
      add(errors, policy.dig("node_capacity", scope) == "fixed-exact-contract",
          "#{scope} node capacity must remain fixed by exact contract")
    end
    add(errors, policy.dig("node_capacity", "preprod_perf_burst") == "existing-gate-only",
        "preprod performance burst must remain behind the existing gate")

    add(errors, policy.dig("service_mesh", "mode") == "istio-sidecar", "Istio sidecar mode must remain active")
    add(errors, policy.dig("service_mesh", "workload_identity") == "spire", "SPIRE must remain workload identity")
    add(errors, policy.dig("service_mesh", "ambient_mode") == "forbidden-until-spire-support-and-lock-change",
        "ambient mode must stay blocked while SPIRE is canonical")

    validate_next_config(errors, root, "frontend/apps/storefront/next.config.ts")
    validate_next_config(errors, root, "frontend/apps/admin/next.config.ts")
    validate_product_containerfile(errors, root, policy)
    errors
  rescue Errno::ENOENT, Psych::Exception => e
    [e.message]
  end

  def validate_next_config(errors, root, relative)
    content = File.read(File.join(root, relative))
    add(errors, content.include?('output: "standalone"'), "#{relative} must enable Next.js standalone output")
    add(errors, content.include?("outputFileTracingRoot"), "#{relative} must trace from the frontend workspace")
  end

  def validate_product_containerfile(errors, root, policy)
    relative = "services/product/Containerfile"
    content = File.read(File.join(root, relative))
    builder = policy.fetch("images").fetch("go_builder")
    expected = "#{builder.fetch('image')}:#{builder.fetch('tag')}@#{builder.fetch('digest')}"
    add(errors, content.include?(expected), "#{relative} must pin the reviewed Go builder digest")
    add(errors, content.include?("TARGETARCH"), "#{relative} must support target architecture selection")
    add(errors, content.include?("CGO_ENABLED=0"), "#{relative} must build a static Go binary")
    add(errors, content.match?(/^FROM scratch$/), "#{relative} runtime must be scratch")
    add(errors, content.include?("USER 65532:65532"), "#{relative} runtime must be non-root")
    add(errors, !content.match?(/:latest\b/), "#{relative} must not use mutable latest tags")
  end
end

if $PROGRAM_NAME == __FILE__
  root = File.expand_path("..", __dir__)
  errors = RuntimeEfficiencyValidator.validate(root)
  if errors.empty?
    puts "PASS runtime efficiency contract"
    exit 0
  end

  errors.each { |error| warn "FAIL #{error}" }
  exit 1
end
