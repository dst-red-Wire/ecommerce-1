#!/usr/bin/env ruby
# frozen_string_literal: true

require "pathname"
require "yaml"

module ServiceMeshPolicyValidator
  module_function

  def load_yaml(path)
    YAML.safe_load(File.read(path), aliases: false) || {}
  rescue Psych::Exception => e
    raise "#{File.basename(path)} invalid YAML: #{e.message}"
  end

  def validate(root)
    lock = load_yaml(File.join(root, "architecture.lock.yaml"))
    policy = load_yaml(File.join(root, "config/contracts/service-mesh-policy.yaml"))
    errors = []

    platform = lock.fetch("platform", {})
    services = Array(lock.dig("business", "services")).map(&:to_s)
    policy_services = policy.fetch("services", {})

    errors << "architecture platform.cni must be cilium" unless platform["cni"] == "cilium"
    errors << "architecture platform.mesh must be istio" unless platform["mesh"] == "istio"
    errors << "service mesh provider must be istio" unless policy["provider"] == "istio"
    errors << "service mesh mode must be ambient" unless policy["mode"] == "ambient"
    errors << "baseline cni must be cilium" unless policy.dig("baseline", "cni") == "cilium"
    errors << "baseline transport must be ztunnel" unless policy.dig("baseline", "transport") == "ztunnel"
    errors << "baseline mtls must be strict" unless policy.dig("baseline", "mtls") == "strict"
    errors << "baseline default dataplane must be ztunnel-only" unless policy.dig("baseline", "default_dataplane") == "ztunnel-only"
    errors << "baseline default waypoint must be false" unless policy.dig("baseline", "default_waypoint") == false

    missing = services - policy_services.keys.map(&:to_s)
    extra = policy_services.keys.map(&:to_s) - services
    errors << "mesh policy missing services: #{missing.sort.join(', ')}" unless missing.empty?
    errors << "mesh policy contains non-canonical services: #{extra.sort.join(', ')}" unless extra.empty?

    allowed_caps = %w[routing authorization traffic_policy]

    services.each do |service|
      entry = policy_services[service]
      next unless entry.is_a?(Hash)

      l7 = entry["l7"]
      unless l7.is_a?(Hash)
        errors << "#{service}: l7 must be a mapping"
        next
      end

      unknown = l7.keys.map(&:to_s) - allowed_caps
      errors << "#{service}: unknown l7 capabilities: #{unknown.sort.join(', ')}" unless unknown.empty?

      flags = allowed_caps.to_h do |capability|
        value = l7[capability]
        errors << "#{service}: l7.#{capability} must be boolean" unless value == true || value == false
        [capability, value == true]
      end

      waypoint_required = flags.values.any?
      expected_dataplane = waypoint_required ? "waypoint-required" : "ztunnel-only"
      actual_dataplane = entry["dataplane"]
      if actual_dataplane != expected_dataplane
        errors << "#{service}: dataplane must be #{expected_dataplane} for l7=#{flags.inspect}, got #{actual_dataplane.inspect}"
      end

      justifications = entry["justification"]
      if waypoint_required
        unless justifications.is_a?(Array) && !justifications.empty?
          errors << "#{service}: true L7 capability requires non-empty justification list"
          next
        end

        true_caps = flags.select { |_name, enabled| enabled }.keys.map { |name| "l7.#{name}" }
        justified_caps = []
        justifications.each_with_index do |item, index|
          unless item.is_a?(Hash)
            errors << "#{service}: justification[#{index}] must be a mapping"
            next
          end
          %w[owner capability reason source_contract].each do |field|
            value = item[field]
            unless value.is_a?(String) && !value.strip.empty?
              errors << "#{service}: justification[#{index}].#{field} must be a non-empty string"
            end
          end
          justified_caps << item["capability"] if item["capability"].is_a?(String)

          source_contract = item["source_contract"]
          if source_contract.is_a?(String) && !source_contract.strip.empty?
            source_path = Pathname.new(source_contract)
            if source_path.absolute? || source_contract.include?("..")
              errors << "#{service}: justification[#{index}].source_contract must stay repository-relative"
            else
              resolved = File.expand_path(source_contract, root)
              repository_root = File.expand_path(root)
              unless resolved.start_with?("#{repository_root}#{File::SEPARATOR}") && File.file?(resolved)
                errors << "#{service}: justification[#{index}].source_contract does not exist: #{source_contract}"
              end
            end
          end
        end

        missing_justifications = true_caps - justified_caps
        errors << "#{service}: missing justification for #{missing_justifications.join(', ')}" unless missing_justifications.empty?
      elsif justifications.is_a?(Array) && !justifications.empty?
        errors << "#{service}: ztunnel-only service must not retain waypoint justifications"
      end
    end

    errors
  end
end

if $PROGRAM_NAME == __FILE__
  root = ENV.fetch("SERVICE_MESH_POLICY_ROOT", File.expand_path("..", __dir__))
  begin
    errors = ServiceMeshPolicyValidator.validate(root)
  rescue StandardError => e
    warn "FAIL service mesh policy governance"
    warn "  - #{e.message}"
    exit 1
  end

  unless errors.empty?
    warn "FAIL service mesh policy governance"
    errors.each { |error| warn "  - #{error}" }
    exit 1
  end

  puts "PASS service mesh policy governance"
end
