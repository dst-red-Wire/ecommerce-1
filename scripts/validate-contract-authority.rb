#!/usr/bin/env ruby
# frozen_string_literal: true

require "pathname"
require "yaml"

module ContractAuthorityValidator
  module_function

  DURATION = /\A[1-9]\d*[hd]\z/
  MLOPS_METADATA_COMPONENTS = %w[lakefs-metadata-cnpg mlflow-metadata-cnpg].freeze
  REQUIRED_MLOPS_STORAGE_FIELDS = %w[
    engine deployment_mode storage topology retention backup network data_scope encryption
    operational_authority dependencies failure_behavior environments
  ].freeze
  REQUIRED_GRAPH_POLICY = {
    "unique_wave_ids_required" => true,
    "requires_must_resolve" => true,
    "cycles_forbidden" => true,
    "unreachable_waves_forbidden" => true
  }.freeze
  REQUIRED_EXECUTION_POLICY = {
    "health_condition" => "all-components-ready-and-declared-gates-pass",
    "timeout" => "required-runtime-binding-before-activation",
    "retry_semantics" => "bounded-controller-retry-required",
    "failure_behavior" => "fail-closed-block-dependent-waves",
    "evidence_output" => "exact-sha-environment-reference-required",
    "rollback_destroy_hook" => "required-before-activation"
  }.freeze

  def load_yaml(root, relative)
    YAML.safe_load(File.read(File.join(root, relative)), aliases: false, filename: relative) || {}
  rescue Psych::Exception, SystemCallError => e
    raise ArgumentError, "#{relative}: #{e.message}"
  end

  def machine_path(lock, root, key)
    relative = lock.dig("machine_contracts", key)
    unless relative.is_a?(String) && !relative.strip.empty?
      raise ArgumentError, "architecture.lock.yaml machine_contracts.#{key} must declare a path"
    end
    raise ArgumentError, "architecture.lock.yaml machine_contracts.#{key} must be relative" if Pathname.new(relative).absolute?

    repository = File.expand_path(root)
    absolute = File.expand_path(relative, repository)
    unless absolute.start_with?("#{repository}#{File::SEPARATOR}") && File.file?(absolute)
      raise ArgumentError,
            "architecture.lock.yaml machine_contracts.#{key} declared file does not exist inside repository: #{relative}"
    end

    real_repository = File.realpath(repository)
    real_contract = File.realpath(absolute)
    unless real_contract.start_with?("#{real_repository}#{File::SEPARATOR}")
      raise ArgumentError, "architecture.lock.yaml machine_contracts.#{key} resolves outside repository: #{relative}"
    end
    relative
  end

  def wave_components(wave)
    Array(wave["components"]) + Array(wave["parallel_groups"]).flatten + Array(wave["serial_after_parallel"])
  end

  def validate_exact_contracts(errors, lock, root)
    declared = lock["machine_contracts"]
    unless declared.is_a?(Hash)
      errors << "architecture.lock.yaml machine_contracts must be a mapping"
      return
    end

    declared.each_key do |key|
      relative = machine_path(lock, root, key)
      contract = load_yaml(root, relative)
      errors << "machine contract #{key} must have status exact" unless contract["status"] == "exact"
    end
  end

  def validate_milestone_dependencies(errors, lock)
    milestones = Array(lock["build_milestones"])
    errors << "build milestones must be unique" unless milestones.uniq == milestones
    dependencies = lock["milestone_dependencies"]
    unless dependencies.is_a?(Hash)
      errors << "architecture.lock.yaml milestone_dependencies must be a mapping"
      return
    end
    unless dependencies.keys.sort == milestones.sort
      errors << "milestone dependency keys must match build_milestones"
    end
    dependencies.each do |milestone, required|
      unless required.is_a?(Array)
        errors << "milestone #{milestone} dependencies must be an array"
        next
      end
      errors << "milestone #{milestone} has duplicate dependencies" unless required.uniq == required
      required.each do |dependency|
        errors << "milestone #{milestone} has unknown dependency #{dependency}" unless milestones.include?(dependency)
        errors << "milestone #{milestone} cannot depend on itself" if dependency == milestone
      end
    end

    expected = {
      "M2-golden-service-product" => ["M1-monorepo-bootstrap"],
      "M2-5-persistent-mgmt-bootstrap" => ["M1-monorepo-bootstrap"],
      "M3-preprod-infrastructure" => ["M2-5-persistent-mgmt-bootstrap"],
      "M4-platform-baseline" => ["M3-preprod-infrastructure"],
      "M5-commerce-vertical-slice" => ["M2-golden-service-product", "M4-platform-baseline"]
    }
    expected.each do |milestone, required|
      errors << "milestone #{milestone} dependency drift" unless Array(dependencies[milestone]).sort == required.sort
    end

    state = {}
    stack = []
    visit = lambda do |milestone|
      return if state[milestone] == :done
      if state[milestone] == :visiting
        start = stack.index(milestone) || 0
        message = "milestone dependency cycle detected: #{(stack[start..] + [milestone]).join(' -> ')}"
        errors << message unless errors.include?(message)
        return
      end
      state[milestone] = :visiting
      stack << milestone
      Array(dependencies[milestone]).each { |dependency| visit.call(dependency) if dependencies.key?(dependency) }
      stack.pop
      state[milestone] = :done
    end
    dependencies.each_key { |milestone| visit.call(milestone) }
  end

  def validate_dag(errors, waves_contract)
    errors << "deployment-waves status must be exact" unless waves_contract["status"] == "exact"
    graph_policy = waves_contract["graph_policy"] || {}
    root_id = graph_policy["root_wave"]
    errors << "deployment graph policy must declare a root_wave" unless root_id.is_a?(String) && !root_id.empty?
    REQUIRED_GRAPH_POLICY.each do |field, expected|
      errors << "deployment graph policy #{field} must be #{expected}" unless graph_policy[field] == expected
    end
    execution_policy = waves_contract.dig("execution_policy", "default") || {}
    REQUIRED_EXECUTION_POLICY.each do |field, expected|
      errors << "deployment execution policy #{field} drift" unless execution_policy[field] == expected
    end

    waves = Array(waves_contract["waves"])
    ids = waves.map { |wave| wave["id"] }
    invalid_ids = ids.reject { |id| id.is_a?(String) && !id.empty? }
    errors << "deployment waves must have non-empty string ids" unless invalid_ids.empty?
    duplicates = ids.group_by(&:itself).select { |_id, values| values.length > 1 }.keys.compact
    errors << "deployment wave ids must be unique: #{duplicates.sort.join(', ')}" unless duplicates.empty?

    component_locations = Hash.new { |hash, key| hash[key] = [] }
    waves.each do |wave|
      wave_components(wave).each { |component| component_locations[component] << wave["id"] }
    end
    duplicate_components = component_locations.select { |component, locations| !component.nil? && locations.length > 1 }
    duplicate_components.each do |component, locations|
      errors << "deployment component #{component} appears in multiple waves: #{locations.join(', ')}"
    end

    by_id = waves.each_with_object({}) { |wave, memo| memo[wave["id"]] ||= wave if wave["id"].is_a?(String) }
    waves.each do |wave|
      id = wave["id"]
      requires = wave["requires"]
      unless requires.is_a?(Array)
        errors << "deployment wave #{id.inspect} requires must be an array"
        next
      end
      errors << "deployment wave #{id} has duplicate requires entries" unless requires.uniq == requires
      requires.each do |required|
        errors << "deployment wave #{id} has unknown dependency #{required}" unless by_id.key?(required)
        errors << "deployment wave #{id} cannot depend on itself" if required == id
      end
    end

    state = {}
    stack = []
    visit = lambda do |id|
      return if state[id] == :done
      if state[id] == :visiting
        start = stack.index(id) || 0
        cycle = stack[start..] + [id]
        message = "deployment wave cycle detected: #{cycle.join(' -> ')}"
        errors << message unless errors.include?(message)
        return
      end
      state[id] = :visiting
      stack << id
      Array(by_id.dig(id, "requires")).each { |required| visit.call(required) if by_id.key?(required) }
      stack.pop
      state[id] = :done
    end
    by_id.each_key { |id| visit.call(id) }

    return unless root_id.is_a?(String) && !root_id.empty?
    unless by_id.key?(root_id)
      errors << "deployment DAG root wave is missing: #{root_id}"
      return
    end
    errors << "deployment DAG root #{root_id} must not require another wave" unless Array(by_id[root_id]["requires"]).empty?

    dependents = Hash.new { |hash, key| hash[key] = [] }
    waves.each do |wave|
      Array(wave["requires"]).each do |required|
        dependents[required] << wave["id"] if by_id.key?(required)
      end
    end
    reachable = {}
    queue = [root_id]
    until queue.empty?
      id = queue.shift
      next if reachable[id]

      reachable[id] = true
      queue.concat(dependents[id])
    end
    unreachable = by_id.keys.reject { |id| reachable[id] }
    errors << "deployment waves unreachable from #{root_id}: #{unreachable.sort.join(', ')}" unless unreachable.empty?
  end

  def wave_dependency_reachable?(waves_by_id, prerequisite_wave_id, consumer_wave_id, visited = {})
    return false if prerequisite_wave_id.nil? || consumer_wave_id.nil?
    return true if prerequisite_wave_id == consumer_wave_id
    return false if visited[consumer_wave_id]

    consumer = waves_by_id[consumer_wave_id]
    return false unless consumer

    requirements = Array(consumer["requires"])
    return true if requirements.include?(prerequisite_wave_id)

    next_visited = visited.merge(consumer_wave_id => true)
    requirements.any? do |required|
      wave_dependency_reachable?(waves_by_id, prerequisite_wave_id, required, next_visited)
    end
  end

  def validate_storage_dependency_edges(errors, storage, waves_contract)
    waves = Array(waves_contract["waves"])
    by_id = waves.to_h { |wave| [wave["id"], wave] }
    component_wave = {}
    waves.each { |wave| wave_components(wave).each { |component| component_wave[component] = wave["id"] } }

    storage.fetch("engines", {}).each do |component, spec|
      next unless spec.is_a?(Hash) && component_wave.key?(component)

      Array(spec["dependencies"]).each do |dependency|
        next unless component_wave.key?(dependency)
        next if wave_dependency_reachable?(by_id, component_wave[dependency], component_wave[component])

        errors << "deployment wave for #{component} must depend on wave containing #{dependency}"
      end
    end
  end

  def validate_resilience_binding(errors, lock, root, storage)
    authority_path = machine_path(lock, root, "resilience_governance")
    authority = load_yaml(root, authority_path)
    profile = authority.dig("profiles", "mlops-metadata-cnpg")
    unless profile.is_a?(Hash)
      errors << "resilience governance must define profile mlops-metadata-cnpg"
      return
    end

    %w[schedule retention rpo rto].each do |field|
      values = profile[field]
      valid = values.is_a?(Hash) && %w[preprod prod].all? do |env|
        values[env].is_a?(String) && values[env].match?(DURATION)
      end
      errors << "resilience profile mlops-metadata-cnpg #{field} must define positive measurable preprod/prod durations" unless valid
    end
    errors << "resilience profile mlops-metadata-cnpg restore validation must be required" unless profile["restore_validation"] == "required"
    errors << "resilience profile mlops-metadata-cnpg component set drift" unless Array(profile["components"]).sort == MLOPS_METADATA_COMPONENTS.sort
    errors << "resilience profile mlops-metadata-cnpg backup method drift" unless profile["backup_method"] == "barman-pitr-compatible"
    errors << "resilience profile mlops-metadata-cnpg backup authority must be seaweedfs-s3" unless profile["backup_object_authority"] == "seaweedfs-s3"
    errors << "resilience profile mlops-metadata-cnpg backup failure domain drift" unless profile["backup_failure_domain"] == "independent-from-source-site"
    errors << "resilience profile mlops-metadata-cnpg backup execution authority drift" unless profile["backup_execution_authority"] == "rancher-fleet-kubernetes-cronjob"
    errors << "resilience profile mlops-metadata-cnpg local override must be forbidden" unless profile["local_objective_override"] == "forbidden"
    validation = authority["validation"] || {}
    errors << "resilience governance duration format drift" unless validation["duration_format"] == "positive-integer-hours-or-days"
    errors << "resilience governance null objectives must be forbidden" unless validation["null_objectives_forbidden"] == true
    errors << "resilience governance restore validation guard must be required" unless validation["restore_validation_required"] == true
    errors << "resilience governance undeclared profiles must be forbidden" unless validation["undeclared_profile_forbidden"] == true

    engines = storage.fetch("engines", {})
    MLOPS_METADATA_COMPONENTS.each do |component|
      spec = engines[component]
      unless spec.is_a?(Hash)
        errors << "storage contract missing #{component}"
        next
      end
      missing = REQUIRED_MLOPS_STORAGE_FIELDS.reject { |field| spec.key?(field) && !spec[field].nil? }
      errors << "#{component} missing storage fields: #{missing.join(', ')}" unless missing.empty?
      consumer = component.start_with?("lakefs-") ? "lakefs" : "mlflow"
      errors << "#{component} engine must be cloudnativepg-postgresql" unless spec["engine"] == "cloudnativepg-postgresql"
      errors << "#{component} deployment mode must be cloudnativepg" unless spec["deployment_mode"] == "cloudnativepg"
      errors << "#{component} storage binding drift" unless spec.dig("storage", "class") == "localpv" && spec.dig("storage", "access_mode") == "ReadWriteOnce"
      errors << "#{component} replica anti-affinity must be strict" unless spec.dig("topology", "anti_affinity") == "strict"
      errors << "#{component} network identities drift" unless Array(spec.dig("network", "writers")) == [consumer] &&
        Array(spec.dig("network", "readers")) == [consumer] && spec.dig("network", "public_access") == "forbidden"
      errors << "#{component} data scope must forbid business data" unless spec.dig("data_scope", "business_data") == "forbidden"
      errors << "#{component} transport encryption is required" unless spec.dig("encryption", "in_transit") == "required"
      errors << "#{component} desired-state authority must remain Rancher Fleet" unless spec.dig("operational_authority", "desired_state") == "rancher-fleet"
      errors << "#{component} database operator must be CloudNativePG" unless spec.dig("operational_authority", "database_operator") == "cloudnativepg"
      errors << "#{component} failure behavior must fail closed on quorum loss" unless spec.dig("failure_behavior", "quorum_loss") == "fail-closed"
      errors << "#{component} empty reinitialization must be forbidden" unless spec.dig("failure_behavior", "empty_reinitialization") == "forbidden"
      errors << "#{component} environment activation drift" unless spec["environments"] == {
        "mgmt" => "deferred", "preprod" => "required", "prod" => "required"
      }

      backup = spec["backup"] || {}
      unless backup["objectives_authority"] == {"machine_contract" => "resilience_governance", "profile" => "mlops-metadata-cnpg"}
        errors << "#{component} objectives authority must resolve through machine_contract resilience_governance profile mlops-metadata-cnpg"
      end
      errors << "#{component} local objective override must be forbidden" unless backup["local_objective_override"] == "forbidden"
      %w[schedule retention rpo rto].each do |field|
        errors << "#{component} backup #{field} must match resilience governance" unless backup[field] == profile[field]
      end
      unless backup["restore_validation"] == profile["restore_validation"]
        errors << "#{component} restore validation must match resilience governance"
      end
      errors << "#{component} backup method must match resilience governance" unless backup["method"] == profile["backup_method"]
      errors << "#{component} backup target must match resilience governance" unless backup["target"] == profile["backup_object_authority"]
      errors << "#{component} backup failure domain must match resilience governance" unless backup["target_failure_domain"] == profile["backup_failure_domain"]
    end
  end

  def validate(root)
    errors = []
    lock = load_yaml(root, "architecture.lock.yaml")
    validate_exact_contracts(errors, lock, root)
    validate_milestone_dependencies(errors, lock)
    storage_path = machine_path(lock, root, "storage_plan")
    waves_path = machine_path(lock, root, "deployment_waves")
    storage = load_yaml(root, storage_path)
    waves = load_yaml(root, waves_path)
    validate_dag(errors, waves)
    validate_storage_dependency_edges(errors, storage, waves)
    validate_resilience_binding(errors, lock, root, storage)
    errors
  rescue ArgumentError, KeyError, TypeError, NoMethodError => e
    ["contract authority structure is invalid: #{e.message}"]
  end
end

if $PROGRAM_NAME == __FILE__
  root = ARGV.fetch(0, File.expand_path("..", __dir__))
  errors = ContractAuthorityValidator.validate(root)
  if errors.empty?
    puts "[governance] contract authority: PASS"
  else
    warn errors.map { |error| "[governance] #{error}" }.join("\n")
    exit 1
  end
end
