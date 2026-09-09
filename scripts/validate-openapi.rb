#!/usr/bin/env ruby
# frozen_string_literal: true

require "pathname"
require_relative "validate-architecture"

module OpenApiContractValidator
  HTTP_METHODS = %w[get post put patch delete options head trace].freeze
  WRITE_METHODS = %w[post put patch delete].freeze
  BODY_WRITE_METHODS = %w[post put patch].freeze

  module_function

  def validate(root)
    errors = []
    lock = ArchitectureValidator.expect_mapping(
      ArchitectureValidator.load_yaml(root, "architecture.lock.yaml"),
      "architecture.lock.yaml"
    )
    machine_contracts = ArchitectureValidator.expect_mapping(
      lock["machine_contracts"],
      "architecture.lock.yaml machine_contracts"
    )

    registry_path = machine_contracts["public_api_contracts"]
    unless registry_path.is_a?(String) && !registry_path.empty?
      return ["architecture.lock.yaml machine_contracts.public_api_contracts must be declared"]
    end

    registry = ArchitectureValidator.expect_mapping(
      ArchitectureValidator.load_yaml(root, registry_path),
      registry_path
    )
    ownership_path = machine_contracts.fetch("service_ownership")
    dependency_path = machine_contracts.fetch("dependency_map")
    ownership = ArchitectureValidator.expect_mapping(
      ArchitectureValidator.load_yaml(root, ownership_path),
      ownership_path
    )
    dependencies = ArchitectureValidator.expect_mapping(
      ArchitectureValidator.load_yaml(root, dependency_path),
      dependency_path
    )

    services = Array(lock.dig("business", "services"))
    ownership_services = ArchitectureValidator.expect_mapping(
      ownership["services"],
      "#{ownership_path} services"
    )
    contracts = ArchitectureValidator.expect_mapping(
      registry["contracts"],
      "#{registry_path} contracts"
    )
    rules = ArchitectureValidator.expect_mapping(
      registry["rules"],
      "#{registry_path} rules"
    )

    errors << "#{registry_path} status must be exact" unless registry["status"] == "exact"
    errors << "#{registry_path} protocol must match dependency-map public_protocol" unless registry["protocol"] == dependencies.dig("rules", "public_protocol")
    errors << "#{registry_path} openapi_version must be 3.1.0" unless registry["openapi_version"] == "3.1.0"
    errors << "#{registry_path} remote_refs_forbidden must be true" unless rules["remote_refs_forbidden"] == true

    common_path = registry["common_components"]
    common_absolute = safe_contract_path(root, common_path, errors)
    if common_absolute
      common = ArchitectureValidator.expect_mapping(
        ArchitectureValidator.load_yaml(root, common_path),
        common_path
      )
      errors << "#{common_path} openapi must match registry" unless common["openapi"] == registry["openapi_version"]
      errors << "#{common_path} jsonSchemaDialect must match registry" unless common["jsonSchemaDialect"] == registry["json_schema_dialect"]
      errors << "#{common_path} must not declare API paths" unless common["paths"] == {}
    end

    golden_service = registry["golden_service"]
    unless services.include?(golden_service)
      errors << "#{registry_path} golden_service #{golden_service.inspect} is not a canonical service"
    end
    unless contracts.key?(golden_service)
      errors << "#{registry_path} must include the golden service contract #{golden_service.inspect}"
    end

    operation_ids = {}
    cache = {}
    contracts.each do |service, entry|
      unless services.include?(service)
        errors << "#{registry_path} contract #{service.inspect} is not a canonical service"
        next
      end
      entry = ArchitectureValidator.expect_mapping(entry, "#{registry_path} contracts.#{service}")
      service_ownership = ownership_services[service]
      unless service_ownership.is_a?(Hash)
        errors << "#{registry_path} contract #{service.inspect} has no service ownership contract"
        next
      end

      contract_path = entry["path"]
      absolute = safe_contract_path(root, contract_path, errors)
      next unless absolute

      spec = ArchitectureValidator.expect_mapping(
        ArchitectureValidator.load_yaml(root, contract_path),
        contract_path
      )
      cache[contract_path] = spec
      errors.concat(
        validate_document(
          root: root,
          spec_path: contract_path,
          spec: spec,
          service: service,
          entry: entry,
          ownership: service_ownership,
          registry: registry,
          cache: cache,
          operation_ids: operation_ids
        )
      )
    end

    errors
  rescue KeyError, TypeError, NoMethodError, ArgumentError => e
    ["OpenAPI contract structure is invalid: #{e.message}"]
  rescue ArchitectureValidator::ContractLoadError => e
    [e.message]
  end

  def safe_contract_path(root, path, errors)
    unless path.is_a?(String) && path.start_with?("contracts/openapi/") && !path.end_with?("/")
      errors << "OpenAPI contract path must stay under contracts/openapi/: #{path.inspect}"
      return nil
    end

    repository_root = File.expand_path(root)
    absolute = File.expand_path(path, repository_root)
    unless absolute.start_with?("#{repository_root}#{File::SEPARATOR}") && File.file?(absolute)
      errors << "OpenAPI contract file does not exist inside the repository: #{path}"
      return nil
    end
    absolute
  end

  def validate_document(root:, spec_path:, spec:, service:, entry:, ownership:, registry:, cache:, operation_ids:)
    errors = []
    rules = registry.fetch("rules")
    openapi_version = registry.fetch("openapi_version")
    path_major = entry.fetch("path_major")
    expected_prefix = "/#{path_major}/"

    errors << "#{spec_path} openapi must be #{openapi_version}" unless spec["openapi"] == openapi_version
    errors << "#{spec_path} jsonSchemaDialect must match registry" unless spec["jsonSchemaDialect"] == registry["json_schema_dialect"]
    errors << "#{spec_path} info.version must equal registry api_version" unless spec.dig("info", "version") == entry["api_version"]
    errors << "#{spec_path} x-ecommerce-service must be #{service}" unless spec["x-ecommerce-service"] == service
    errors << "#{spec_path} x-ecommerce-authoritative-store must match service ownership" unless spec["x-ecommerce-authoritative-store"] == ownership["db"]
    errors << "#{spec_path} x-ecommerce-ownership must match exact service ownership" unless spec["x-ecommerce-ownership"] == ownership["owns"]
    errors << "#{spec_path} x-ecommerce-audiences must match registry" unless spec["x-ecommerce-audiences"] == entry["audiences"]

    paths = spec["paths"]
    unless paths.is_a?(Hash) && !paths.empty?
      errors << "#{spec_path} paths must be a non-empty mapping"
      return errors
    end

    paths.each do |path, path_item|
      errors << "#{spec_path} path #{path} must start with #{expected_prefix}" unless path.start_with?(expected_prefix)
      unless path_item.is_a?(Hash)
        errors << "#{spec_path} path #{path} must map to an object"
        next
      end

      HTTP_METHODS.each do |method|
        operation = path_item[method]
        next unless operation
        unless operation.is_a?(Hash)
          errors << "#{spec_path} #{method.upcase} #{path} must map to an operation object"
          next
        end

        operation_id = operation["operationId"]
        if !operation_id.is_a?(String) || operation_id.empty?
          errors << "#{spec_path} #{method.upcase} #{path} must declare operationId"
        elsif operation_ids.key?(operation_id)
          errors << "duplicate operationId #{operation_id.inspect} in #{spec_path} and #{operation_ids[operation_id]}"
        else
          operation_ids[operation_id] = "#{method.upcase} #{path}"
        end

        responses = operation["responses"]
        unless responses.is_a?(Hash) && responses.keys.any? { |status| status.to_s.match?(/^2\d\d$/) }
          errors << "#{spec_path} #{method.upcase} #{path} must declare at least one 2xx response"
        end

        next unless WRITE_METHODS.include?(method)

        effective_security = operation.key?("security") ? operation["security"] : spec["security"]
        security_scheme = rules.fetch("security_scheme")
        unless security_requirement?(effective_security, security_scheme)
          errors << "#{spec_path} #{method.upcase} #{path} must require #{security_scheme}"
        end

        idempotency_header = rules.fetch("write_idempotency_header")
        unless required_header_parameter?(root, spec_path, spec, path_item, operation, idempotency_header, cache, errors)
          errors << "#{spec_path} #{method.upcase} #{path} must require #{idempotency_header}"
        end

        if BODY_WRITE_METHODS.include?(method) && !operation["requestBody"].is_a?(Hash)
          errors << "#{spec_path} #{method.upcase} #{path} must declare requestBody"
        end

        if method == "patch"
          concurrency_header = rules.fetch("optimistic_concurrency_header")
          unless required_header_parameter?(root, spec_path, spec, path_item, operation, concurrency_header, cache, errors)
            errors << "#{spec_path} PATCH #{path} must require #{concurrency_header}"
          end
        end
      end
    end

    validate_refs(root, spec_path, spec, spec, cache, errors, {})
    errors
  end

  def security_requirement?(security, scheme)
    security.is_a?(Array) && security.any? do |requirement|
      requirement.is_a?(Hash) && requirement.key?(scheme)
    end
  end

  def required_header_parameter?(root, spec_path, spec, path_item, operation, header_name, cache, errors)
    parameters = Array(path_item["parameters"]) + Array(operation["parameters"])
    parameters.any? do |parameter|
      object = parameter
      if parameter.is_a?(Hash) && parameter["$ref"]
        resolved = resolve_ref(root, spec_path, spec, parameter["$ref"], cache, errors)
        object = resolved&.first
      end
      object.is_a?(Hash) && object["in"] == "header" && object["name"] == header_name && object["required"] == true
    end
  end

  def validate_refs(root, document_path, document, value, cache, errors, visited)
    walk_refs(value) do |ref|
      key = "#{document_path}|#{ref}"
      next if visited[key]

      visited[key] = true
      resolved = resolve_ref(root, document_path, document, ref, cache, errors)
      next unless resolved

      target, target_document, target_path = resolved
      validate_refs(root, target_path, target_document, target, cache, errors, visited) if target.is_a?(Hash) || target.is_a?(Array)
      cache[target_path] ||= target_document
    end
  end

  def walk_refs(value, &block)
    case value
    when Hash
      value.each do |key, child|
        yield child if key == "$ref" && child.is_a?(String)
        walk_refs(child, &block)
      end
    when Array
      value.each { |child| walk_refs(child, &block) }
    end
  end

  def resolve_ref(root, document_path, document, ref, cache, errors)
    if ref.match?(%r{\A[a-z][a-z0-9+.\-]*:}i)
      errors << "#{document_path} remote $ref is forbidden: #{ref}"
      return nil
    end

    file_part, fragment = ref.split("#", 2)
    if file_part.nil? || file_part.empty?
      target_document = document
      target_path = document_path
    else
      candidate = File.expand_path(file_part, File.join(File.expand_path(root), File.dirname(document_path)))
      repository_root = File.expand_path(root)
      unless candidate.start_with?("#{repository_root}#{File::SEPARATOR}") && File.file?(candidate)
        errors << "#{document_path} unresolved local $ref file: #{ref}"
        return nil
      end
      target_path = Pathname.new(candidate).relative_path_from(Pathname.new(repository_root)).to_s
      target_document = cache[target_path] ||= ArchitectureValidator.load_yaml(root, target_path)
    end

    target = resolve_pointer(target_document, fragment)
    unless target
      errors << "#{document_path} unresolved $ref pointer: #{ref}"
      return nil
    end
    [target, target_document, target_path]
  rescue ArchitectureValidator::ContractLoadError => e
    errors << e.message
    nil
  end

  def resolve_pointer(document, fragment)
    return document if fragment.nil? || fragment.empty?
    return nil unless fragment.start_with?("/")

    fragment.split("/")[1..].reduce(document) do |current, raw_token|
      return nil unless current.is_a?(Hash) || current.is_a?(Array)

      token = raw_token.gsub("~1", "/").gsub("~0", "~")
      if current.is_a?(Hash)
        return nil unless current.key?(token)
        current[token]
      else
        return nil unless token.match?(/^\d+$/)
        current.fetch(token.to_i, nil)
      end
    end
  end
end

if $PROGRAM_NAME == __FILE__
  root = ARGV.fetch(0, File.expand_path("..", __dir__))
  errors = OpenApiContractValidator.validate(root)
  if errors.empty?
    puts "[contracts] OpenAPI contracts: PASS"
  else
    warn errors.map { |error| "[contracts] #{error}" }.join("\n")
    exit 1
  end
end
