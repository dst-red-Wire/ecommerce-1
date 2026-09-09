#!/usr/bin/env ruby
# frozen_string_literal: true

require "pathname"
require "yaml"

module ContractAuthorityValidator
  module_function

  DURATION = /\A[1-9]\d*[hd]\z/
  EXECUTION_DURATION = /\A[1-9]\d*[smh]\z/
  MLOPS_METADATA_COMPONENTS = %w[lakefs-metadata-cnpg mlflow-metadata-cnpg].freeze
  OBSERVABILITY_STATEFUL_COMPONENTS = %w[
    victoriametrics victorialogs clickhouse mongodb-oss-self-hosted opensearch-security
  ].freeze
  PLATFORM_STATEFUL_COMPONENTS = %w[
    postgresql strimzi-kafka rabbitmq redis opensearch-business seaweedfs apicurio
  ].freeze
  REQUIRED_STATEFUL_FIELDS = %w[
    engine deployment_mode storage topology retention backup encryption network data_scope
    operational_authority dependencies failure_behavior environments
  ].freeze
  REQUIRED_MLOPS_STORAGE_FIELDS = REQUIRED_STATEFUL_FIELDS.freeze
  REQUIRED_GRAPH_POLICY = {
    "unique_wave_ids_required" => true,
    "requires_must_resolve" => true,
    "cycles_forbidden" => true,
    "unreachable_waves_forbidden" => true
  }.freeze
  REQUIRED_EXECUTION_POLICY = {
    "activation_requires_resolved_binding" => true,
    "placeholders_forbidden" => true,
    "unbound_components_forbidden" => true,
    "unknown_bindings_forbidden" => true,
    "automatic_destroy" => "forbidden"
  }.freeze
  REQUIRED_EVIDENCE_FIELDS = %w[
    exact_sha environment component wave observed_revision gate_results
  ].freeze
  EXPECTED_MILESTONE_DEPENDENCIES = {
    "M0-architecture-sync" => [],
    "M1-monorepo-bootstrap" => ["M0-architecture-sync"],
    "M2-golden-service-product" => ["M1-monorepo-bootstrap"],
    "M2-5-persistent-mgmt-bootstrap" => ["M1-monorepo-bootstrap"],
    "M3-preprod-infrastructure" => ["M2-5-persistent-mgmt-bootstrap"],
    "M4-platform-baseline" => ["M3-preprod-infrastructure"],
    "M5-commerce-vertical-slice" => ["M2-golden-service-product", "M4-platform-baseline"],
    "M6-full-application" => ["M5-commerce-vertical-slice"],
    "M7-qualification" => ["M6-full-application"],
    "M8-preprod-certification" => ["M7-qualification"],
    "M9-prod-ab" => ["M8-preprod-certification"]
  }.freeze
  REQUIRED_STORAGE_CLASS_FIELDS = {
    "provisioner" => "kubernetes.io/no-provisioner",
    "filesystem" => "xfs",
    "access_mode" => "ReadWriteOnce",
    "volume_binding_mode" => "WaitForFirstConsumer",
    "reclaim_policy" => "Retain",
    "encryption_at_rest" => "luks2",
    "allocation" => "dedicated-static-pv-per-member",
    "xfs_project_quota" => "required",
    "failure_domain" => "host-and-site"
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

  def duration_map?(value, keys = %w[preprod prod])
    value.is_a?(Hash) && value.keys.sort == keys.sort &&
      keys.all? { |key| value[key].is_a?(String) && value[key].match?(DURATION) }
  end

  def retention_contract?(value, keys = %w[preprod prod])
    return value == "persistent-until-explicit-deletion" if value.is_a?(String)
    return false unless value.is_a?(Hash) && value.keys.sort == keys.sort

    value.values.all? do |entry|
      entry == "persistent-until-explicit-deletion" || (entry.is_a?(String) && entry.match?(DURATION))
    end
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
    errors << "milestone dependency keys must match build_milestones" unless dependencies.keys.sort == milestones.sort
    errors << "build milestone catalogue drift" unless milestones == EXPECTED_MILESTONE_DEPENDENCIES.keys

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

    EXPECTED_MILESTONE_DEPENDENCIES.each do |milestone, required|
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

  def validate_execution_bindings(errors, waves_contract, waves)
    policy = waves_contract["execution_policy"] || {}
    REQUIRED_EXECUTION_POLICY.each do |field, expected|
      errors << "deployment execution policy #{field} drift" unless policy[field] == expected
    end
    extra_policy = policy.keys - REQUIRED_EXECUTION_POLICY.keys
    errors << "deployment execution policy has unknown fields: #{extra_policy.sort.join(', ')}" unless extra_policy.empty?

    profiles = waves_contract["execution_profiles"]
    bindings = waves_contract["component_execution_bindings"]
    unless profiles.is_a?(Hash) && !profiles.empty?
      errors << "deployment execution_profiles must be a non-empty mapping"
      profiles = {}
    end
    unless bindings.is_a?(Hash)
      errors << "deployment component_execution_bindings must be a mapping"
      bindings = {}
    end

    components = waves.flat_map { |wave| wave_components(wave) }
    component_set = components.uniq.sort
    errors << "deployment component execution bindings must cover every wave component exactly" unless bindings.keys.sort == component_set

    bindings.each do |component, profile_name|
      errors << "deployment execution binding references unknown component #{component}" unless component_set.include?(component)
      errors << "deployment execution binding for #{component} references unknown profile #{profile_name}" unless profiles.key?(profile_name)
    end

    profiles.each do |name, profile|
      unless profile.is_a?(Hash)
        errors << "deployment execution profile #{name} must be a mapping"
        next
      end
      timeout = profile["timeout"]
      errors << "deployment execution profile #{name} timeout must be a positive s/m/h duration" unless timeout.is_a?(String) && timeout.match?(EXECUTION_DURATION)
      retry_policy = profile["retry"] || {}
      attempts = retry_policy["max_attempts"]
      backoff = retry_policy["backoff"]
      errors << "deployment execution profile #{name} retry.max_attempts must be between 1 and 5" unless attempts.is_a?(Integer) && attempts.between?(1, 5)
      errors << "deployment execution profile #{name} retry.backoff must be a positive s/m/h duration" unless backoff.is_a?(String) && backoff.match?(EXECUTION_DURATION)
      checks = profile["health_checks"]
      errors << "deployment execution profile #{name} health_checks must be non-empty and unique" unless checks.is_a?(Array) && !checks.empty? && checks.uniq == checks && checks.all? { |entry| entry.is_a?(String) && !entry.empty? }
      evidence = profile["evidence"] || {}
      errors << "deployment execution profile #{name} evidence fields drift" unless evidence.keys.sort == REQUIRED_EVIDENCE_FIELDS.sort && REQUIRED_EVIDENCE_FIELDS.all? { |field| evidence[field] == "required" }
      failure = profile["failure"] || {}
      errors << "deployment execution profile #{name} failure.behavior must be explicit" unless failure["behavior"].is_a?(String) && !failure["behavior"].empty?
      errors << "deployment execution profile #{name} failure.hook must be explicit" unless failure["hook"].is_a?(String) && !failure["hook"].empty?
      errors << "deployment execution profile #{name} automatic destroy must be forbidden" unless failure["automatic_destroy"] == "forbidden"
    end

    unused_profiles = profiles.keys - bindings.values.uniq
    errors << "deployment execution profiles are unreferenced: #{unused_profiles.sort.join(', ')}" unless unused_profiles.empty?
  end

  def validate_dag(errors, waves_contract)
    errors << "deployment-waves status must be exact" unless waves_contract["status"] == "exact"
    graph_policy = waves_contract["graph_policy"] || {}
    root_id = graph_policy["root_wave"]
    errors << "deployment graph policy must declare a root_wave" unless root_id.is_a?(String) && !root_id.empty?
    REQUIRED_GRAPH_POLICY.each do |field, expected|
      errors << "deployment graph policy #{field} must be #{expected}" unless graph_policy[field] == expected
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

    validate_execution_bindings(errors, waves_contract, waves)

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

  def validate_storage_classes(errors, storage)
    classes = storage["storage_classes"]
    unless classes.is_a?(Hash)
      errors << "storage_classes must be a mapping"
      return
    end
    classes.each do |name, spec|
      unless spec.is_a?(Hash)
        errors << "storage class #{name} must be a mapping"
        next
      end
      REQUIRED_STORAGE_CLASS_FIELDS.each do |field, expected|
        errors << "storage class #{name} #{field} drift" unless spec[field] == expected
      end
      pools = spec["backing_pools"]
      errors << "storage class #{name} backing_pools must be non-empty and unique" unless pools.is_a?(Array) && !pools.empty? && pools.uniq == pools
    end

    storage.fetch("engines", {}).each do |component, spec|
      next unless spec.is_a?(Hash)
      storage_class = spec.dig("storage", "class")
      next if storage_class.nil? || storage_class == "none"
      errors << "storage component #{component} references unknown storage class #{storage_class}" unless classes.key?(storage_class)
    end
  end

  def validate_stateful_contracts(errors, storage)
    engines = storage.fetch("engines", {})
    required_components = (PLATFORM_STATEFUL_COMPONENTS + MLOPS_METADATA_COMPONENTS + OBSERVABILITY_STATEFUL_COMPONENTS).uniq
    required_components.each do |component|
      spec = engines[component]
      unless spec.is_a?(Hash)
        errors << "stateful component #{component} lacks complete storage contract"
        next
      end
      missing = REQUIRED_STATEFUL_FIELDS.reject { |field| spec.key?(field) && !spec[field].nil? }
      errors << "stateful component #{component} missing storage fields: #{missing.join(', ')}" unless missing.empty?
      next unless missing.empty?

      retention_keys = component == "opensearch-security" ? %w[preprod_hot prod_hot prod_snapshots] : %w[preprod prod]
      errors << "stateful component #{component} retention contract is incomplete" unless retention_contract?(spec["retention"], retention_keys)
      backup = spec["backup"] || {}
      %w[schedule retention rpo rto].each do |field|
        errors << "stateful component #{component} backup #{field} must define exact preprod/prod durations" unless duration_map?(backup[field])
      end
      errors << "stateful component #{component} restore validation is required" unless backup["restore_validation"] == "required"
      errors << "stateful component #{component} public access must be forbidden" unless spec.dig("network", "public_access") == "forbidden"
      errors << "stateful component #{component} desired-state authority must remain Rancher Fleet" unless spec.dig("operational_authority", "desired_state") == "rancher-fleet"
      errors << "stateful component #{component} environment activation drift" unless spec["environments"] == {
        "mgmt" => "deferred", "preprod" => "required", "prod" => "required"
      }
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
        unless component_wave.key?(dependency)
          errors << "storage dependency #{dependency} for #{component} is not located in deployment waves"
          next
        end
        next if wave_dependency_reachable?(by_id, component_wave[dependency], component_wave[component])

        errors << "deployment wave for #{component} must depend on wave containing #{dependency}"
      end
    end
  end

  def validate_superseded_components(errors, lock, waves_contract)
    superseded = lock["superseded"]
    unless superseded.is_a?(Hash)
      errors << "architecture.lock.yaml superseded must be a mapping"
      return
    end
    active = Array(waves_contract["waves"]).flat_map { |wave| wave_components(wave) }
    present = active & superseded.keys
    errors << "superseded components active in deployment waves: #{present.sort.join(', ')}" unless present.empty?
  end

  def validate_trust_zones(errors, lock, root, waves_contract)
    path = machine_path(lock, root, "security_trust_zones")
    contract = load_yaml(root, path)
    errors << "security trust zones status must be exact" unless contract["status"] == "exact"
    documentation = lock.dig("topology_contracts", "security_zones")
    errors << "security trust zones documentation authority drift" unless contract["documentation"] == documentation

    zones = contract["zones"]
    errors << "security trust zones must define exactly Z0 through Z6" unless zones.is_a?(Hash) && zones.keys.sort == %w[Z0 Z1 Z2 Z3 Z4 Z5 Z6]
    active = Array(waves_contract["waves"]).flat_map { |wave| wave_components(wave) }.uniq.sort
    subjects = contract["subjects"]
    unless subjects.is_a?(Hash)
      errors << "security trust zone subjects must be a mapping"
      return
    end
    errors << "security trust zone subjects must exactly cover active deployment components" unless subjects.keys.sort == active
    subjects.each do |component, zone|
      errors << "security trust zone subject #{component} references unknown zone #{zone}" unless zones.is_a?(Hash) && zones.key?(zone)
    end

    services = Array(lock.dig("business", "services"))
    frontends = Array(lock.dig("business", "frontends"))
    errors << "security trust zone business service catalogue drift" unless Array(contract["business_services"]) == services
    errors << "security trust zone frontend catalogue drift" unless Array(contract["frontends"]) == frontends
    services.each { |service| errors << "business service #{service} must be in trust zone Z3" unless subjects[service] == "Z3" }
    frontends.each { |frontend| errors << "frontend #{frontend} must be in trust zone Z3" unless subjects[frontend] == "Z3" }
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
      errors << "resilience profile mlops-metadata-cnpg #{field} must define exact positive preprod/prod durations" unless duration_map?(profile[field])
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
      errors << "#{component} restore validation must match resilience governance" unless backup["restore_validation"] == profile["restore_validation"]
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
    validate_superseded_components(errors, lock, waves)
    validate_storage_classes(errors, storage)
    validate_stateful_contracts(errors, storage)
    validate_storage_dependency_edges(errors, storage, waves)
    validate_resilience_binding(errors, lock, root, storage)
    validate_trust_zones(errors, lock, root, waves)
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
