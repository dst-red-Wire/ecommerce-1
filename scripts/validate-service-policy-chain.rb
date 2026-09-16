#!/usr/bin/env ruby
# frozen_string_literal: true

require "pathname"
require "yaml"

module ServicePolicyChainValidator
  CONTRACTS = {
    dependency: "config/contracts/dependency-map.yaml",
    mesh: "config/contracts/service-mesh-policy.yaml",
    authority: "config/contracts/mesh-policy-authority.yaml",
    waypoint: "config/contracts/waypoint-scope.yaml",
    resilience: "config/contracts/service-resilience-policy.yaml",
    authz: "config/contracts/service-authz-policy.yaml",
    exposure: "config/contracts/service-exposure-policy.yaml",
    egress: "config/contracts/egress-policy.yaml",
    slo: "config/contracts/service-slo.yaml",
    traffic: "config/contracts/traffic-class-policy.yaml",
    observability: "config/contracts/mesh-observability-policy.yaml",
    public_api: "config/contracts/public-api-contracts.yaml"
  }.freeze

  module_function

  def load_yaml(root, relative)
    path = File.join(root, relative)
    YAML.safe_load(File.read(path), aliases: false) || {}
  rescue Psych::Exception => e
    raise "#{relative} invalid YAML: #{e.message}"
  rescue SystemCallError => e
    raise "#{relative} cannot be loaded: #{e.message}"
  end

  def mapping(value, label, errors)
    return value if value.is_a?(Hash)

    errors << "#{label} must be a mapping"
    {}
  end

  def service_set(contract, key, label, canonical, errors)
    services = mapping(contract[key], "#{label}.#{key}", errors)
    actual = services.keys.map(&:to_s).sort
    expected = canonical.sort
    errors << "#{label} service set must match canonical services: expected #{expected.inspect}, got #{actual.inspect}" unless actual == expected
    services
  end

  def existing_relative_file?(root, relative)
    return false unless relative.is_a?(String) && !relative.strip.empty?
    path = Pathname.new(relative)
    return false if path.absolute?

    root_abs = File.expand_path(root)
    resolved = File.expand_path(relative, root_abs)
    resolved.start_with?("#{root_abs}#{File::SEPARATOR}") && File.file?(resolved)
  end

  def validate(root)
    errors = []
    lock = load_yaml(root, "architecture.lock.yaml")
    canonical = Array(lock.dig("business", "services")).map(&:to_s)
    errors << "architecture.lock.yaml must declare exactly 19 canonical services" unless canonical.size == 19 && canonical.uniq.size == 19

    c = CONTRACTS.transform_values { |path| load_yaml(root, path) }

    dependency_services = service_set(c[:dependency], "services", CONTRACTS[:dependency], canonical, errors)
    mesh_services = service_set(c[:mesh], "services", CONTRACTS[:mesh], canonical, errors)
    resilience_services = service_set(c[:resilience], "services", CONTRACTS[:resilience], canonical, errors)
    authz_services = service_set(c[:authz], "service_rules", CONTRACTS[:authz], canonical, errors)
    exposure_services = service_set(c[:exposure], "services", CONTRACTS[:exposure], canonical, errors)
    egress_services = service_set(c[:egress], "services", CONTRACTS[:egress], canonical, errors)
    slo_services = service_set(c[:slo], "services", CONTRACTS[:slo], canonical, errors)
    traffic_services = service_set(c[:traffic], "services", CONTRACTS[:traffic], canonical, errors)
    observability_services = service_set(c[:observability], "services", CONTRACTS[:observability], canonical, errors)

    # Layer ownership must remain single-authority for Ambient-managed traffic.
    errors << "mesh authority l3_l4 must be cilium" unless c[:authority].dig("layers", "l3_l4", "authority") == "cilium"
    errors << "mesh authority l7 must be istio-waypoint" unless c[:authority].dig("layers", "l7", "authority") == "istio-waypoint"
    unless c[:authority].dig("layers", "l7", "cilium_l7_policy") == "forbidden-for-ambient-managed-flows"
      errors << "Cilium L7 policy must be forbidden for Ambient-managed flows"
    end
    unless c[:authority].dig("rules", "single_l7_policy_authority_per_flow") == true
      errors << "single_l7_policy_authority_per_flow must be true"
    end

    # Derive the exact internal caller matrix and external egress from dependency-map.
    expected_callers = canonical.to_h { |service| [service, []] }
    canonical.each do |caller|
      entry = mapping(dependency_services[caller], "dependency #{caller}", errors)
      Array(entry["sync"]).map(&:to_s).each do |callee|
        if expected_callers.key?(callee)
          expected_callers[callee] << caller
        else
          errors << "#{caller}: sync dependency #{callee.inspect} is not a canonical service"
        end
      end

      expected_external = Array(entry["sync_external"]).map(&:to_s).sort
      actual_external = Array(egress_services.dig(caller, "external_destinations")).filter_map do |destination|
        destination.is_a?(Hash) ? destination["id"].to_s : nil
      end.sort
      unless actual_external == expected_external
        errors << "#{caller}: egress destinations must match sync_external: expected #{expected_external.inspect}, got #{actual_external.inspect}"
      end
    end

    canonical.each do |service|
      expected = expected_callers.fetch(service).sort
      actual = Array(authz_services.dig(service, "allowed_callers")).map(&:to_s).sort
      errors << "#{service}: allowed_callers must match dependency-map callers: expected #{expected.inspect}, got #{actual.inspect}" unless actual == expected

      mesh_entry = mapping(mesh_services[service], "mesh service #{service}", errors)
      l7 = mapping(mesh_entry["l7"], "mesh service #{service}.l7", errors)
      authz_l7 = authz_services.dig(service, "l7_required") == true
      errors << "#{service}: authz l7_required must match service-mesh l7.authorization" unless authz_l7 == (l7["authorization"] == true)

      authz_source = authz_services.dig(service, "source_contract")
      if authz_l7 && !existing_relative_file?(root, authz_source)
        errors << "#{service}: authz source_contract does not exist: #{authz_source.inspect}"
      end

      dataplane = mesh_entry["dataplane"]
      expected_waypoint = dataplane == "waypoint-required"
      waypoint_assignment = mapping(c[:waypoint]["assignments"], "waypoint assignments", errors)[service]
      if expected_waypoint && !waypoint_assignment.is_a?(Hash)
        errors << "#{service}: waypoint-required service must have waypoint-scope assignment"
      elsif !expected_waypoint && waypoint_assignment
        errors << "#{service}: ztunnel-only service must not have waypoint-scope assignment"
      end

      obs_mode = observability_services.dig(service, "mesh_mode")
      errors << "#{service}: observability mesh_mode #{obs_mode.inspect} must match dataplane #{dataplane.inspect}" unless obs_mode == dataplane
      if dataplane != "waypoint-required"
        if observability_services.dig(service, "l7_http_metrics") == true || observability_services.dig(service, "l7_access_logs") == true
          errors << "#{service}: ztunnel-only service cannot require waypoint L7 metrics/access logs"
        end
      end

      traffic_class = traffic_services.dig(service, "primary_class")
      resilience_class = resilience_services.dig(service, "class")
      errors << "#{service}: resilience class #{resilience_class.inspect} must match traffic class #{traffic_class.inspect}" unless resilience_class == traffic_class
      unless mapping(c[:traffic]["classes"], "traffic classes", errors).key?(traffic_class)
        errors << "#{service}: unknown traffic class #{traffic_class.inspect}"
      end
      unless mapping(c[:resilience]["classes"], "resilience classes", errors).key?(resilience_class)
        errors << "#{service}: missing resilience class definition #{resilience_class.inspect}"
      end

      resilience_source = resilience_services.dig(service, "source_contract")
      if resilience_source && !existing_relative_file?(root, resilience_source)
        errors << "#{service}: resilience source_contract does not exist: #{resilience_source.inspect}"
      end

      slo_profile = slo_services.dig(service, "profile")
      unless mapping(c[:slo]["profiles"], "SLO profiles", errors).key?(slo_profile)
        errors << "#{service}: unknown SLO profile #{slo_profile.inspect}"
      end

      exposure = exposure_services.dig(service, "exposure")
      unless %w[internal-only edge-exposed admin-only async-only].include?(exposure)
        errors << "#{service}: unsupported exposure #{exposure.inspect}"
      end
      if exposure == "async-only" && exposure_services.dig(service, "synchronous_ingress") != false
        errors << "#{service}: async-only service must explicitly disable synchronous_ingress"
      end
    end

    # Public API registry and exposure must agree.
    public_contracts = mapping(c[:public_api]["contracts"], "public API contracts", errors)
    public_contracts.each do |service, contract|
      next unless canonical.include?(service.to_s)
      audiences = Array(contract["audiences"]).map(&:to_s)
      exposure = exposure_services.dig(service.to_s, "exposure")
      if audiences == ["admin"] && exposure != "admin-only"
        errors << "#{service}: admin-only public API audience requires admin-only exposure"
      end
    end
    exposure_services.each do |service, entry|
      next unless entry.is_a?(Hash) && entry["exposure"] == "edge-exposed"
      errors << "#{service}: edge-exposed service requires registered public API contract" unless public_contracts.key?(service)
    end

    # Mesh L7 requirements must be backed by the specialized policy contracts.
    canonical.each do |service|
      l7 = mesh_services.dig(service, "l7") || {}
      if l7["authorization"] == true && authz_services.dig(service, "l7_required") != true
        errors << "#{service}: mesh L7 authorization lacks authz requirement"
      end
      if l7["traffic_policy"] == true
        source = resilience_services.dig(service, "source_contract")
        errors << "#{service}: mesh L7 traffic policy requires a service-specific resilience source_contract" unless existing_relative_file?(root, source)
      end
    end

    errors.uniq
  end
end

if $PROGRAM_NAME == __FILE__
  root = ENV.fetch("SERVICE_POLICY_CHAIN_ROOT", File.expand_path("..", __dir__))
  begin
    errors = ServicePolicyChainValidator.validate(root)
  rescue StandardError => e
    warn "FAIL service policy chain governance"
    warn "  - #{e.message}"
    exit 1
  end

  if errors.empty?
    puts "PASS service policy chain governance"
    exit 0
  end

  warn "FAIL service policy chain governance"
  errors.each { |error| warn "  - #{error}" }
  exit 1
end
