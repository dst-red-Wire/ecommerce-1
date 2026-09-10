#!/usr/bin/env ruby
# frozen_string_literal: true

require "json"
require "open3"
require "optparse"
require "set"
require "yaml"

module AffectedComponents
  module_function

  FRONTENDS = %w[storefront admin].freeze
  PLATFORM_COMPONENTS = %w[platform:terraform platform:ansible].freeze
  SEMANTIC_CONTRACTS = %w[
    config/contracts/service-ownership.yaml
    config/contracts/dependency-map.yaml
    config/contracts/event-contracts.yaml
    config/contracts/public-api-contracts.yaml
  ].freeze

  def public_contract_index(public_api)
    public_api.fetch("contracts", {}).each_with_object({}) do |(service, spec), index|
      index[spec.fetch("path")] = {
        "service" => service,
        "audiences" => spec.fetch("audiences", [])
      }
    end
  end

  def force_all!(components, services)
    FRONTENDS.each { |frontend| components << "frontend:#{frontend}" }
    services.each { |service| components << "service:#{service}" }
    PLATFORM_COMPONENTS.each { |component| components << component }
    components << "system"
  end

  def classify(paths, services:, public_contracts:, common_openapi: nil, contract_impact: {}, strict_unknown: false)
    components = Set.new(["global"])

    paths.each do |raw_path|
      path = raw_path.to_s.sub(%r{\A\./}, "")
      next if path.empty?

      case path
      when "architecture.lock.yaml", "Makefile", "go.work",
           "config/contracts/ci-topology.yaml", "config/toolchain/versions.env",
           "config/toolchain/capabilities.json"
        force_all!(components, services)
      when %r{\Ascripts/ci-[^/]+\.(?:rb|py)\z}, "scripts/repoctl.py",
           %r{\Aplatform/tekton/}
        force_all!(components, services)
      when %r{\Aservices/([^/]+)/}
        service = Regexp.last_match(1)
        raise ArgumentError, "unknown service path changed: #{service}" unless services.include?(service)

        components << "service:#{service}"
      when %r{\Afrontend/apps/(storefront|admin)/}
        components << "frontend:#{Regexp.last_match(1)}"
      when %r{\Afrontend/packages/},
           %r{\Afrontend/(?:package\.json|pnpm-lock\.yaml|pnpm-workspace\.yaml|eslint\.config\.mjs|vitest\.setup\.ts|playwright\.config\.ts|turbo\.json)\z}
        FRONTENDS.each { |frontend| components << "frontend:#{frontend}" }
      when %r{\Afrontend/e2e/}
        FRONTENDS.each { |frontend| components << "frontend:#{frontend}" }
        components << "system"
      when %r{\Aplatform/terraform/}
        components << "platform:terraform"
      when %r{\Aplatform/ansible/}
        components << "platform:ansible"
      when %r{\Acontracts/openapi/}
        if path == common_openapi
          FRONTENDS.each { |frontend| components << "frontend:#{frontend}" }
          services.each { |service| components << "service:#{service}" }
        elsif (contract = public_contracts[path])
          components << "service:#{contract.fetch('service')}"
          contract.fetch("audiences", []).each do |audience|
            components << "frontend:#{audience}" if FRONTENDS.include?(audience)
          end
        else
          raise ArgumentError, "unregistered OpenAPI contract changed: #{path}"
        end
      when %r{\Acontracts/(?:protobuf|events|schemas)/}
        # These registries do not yet expose a canonical file -> producer/consumer
        # mapping. Fail closed until they do rather than guessing from filenames.
        services.each { |service| components << "service:#{service}" }
        components << "system"
      when *SEMANTIC_CONTRACTS
        impact = contract_impact[path]
        if impact.nil?
          # Callers that do not provide a base/head semantic delta are deliberately
          # conservative. The CLI always provides one.
          services.each { |service| components << "service:#{service}" }
          components << "system"
        else
          Array(impact).each { |component| components << component }
          components << "system" unless impact.empty?
        end
      when "config/contracts/runtime-efficiency.yaml",
           "scripts/resource-sizing.rb", "scripts/validate-runtime-efficiency.rb",
           "tests/resource_sizing_test.rb", "tests/runtime_efficiency_test.rb"
        # The runtime-efficiency gate is globally authoritative and always runs on
        # the new SHA, so these inputs do not require the broad system suite.
      when %r{\Atests/}, %r{\Ascripts/}
        # Other repository-level tests and native helpers are exercised by system.
        components << "system"
      else
        # Incremental reuse needs stronger guarantees than ordinary affected routing.
        # Unknown deltas may not inherit component PASS evidence.
        force_all!(components, services) if strict_unknown
      end
    end

    components.to_a.sort
  end

  def run_git(root, *args, allow_failure: false)
    stdout, stderr, status = Open3.capture3("git", *args, chdir: root)
    return stdout if status.success?
    return nil if allow_failure

    raise "git #{args.join(' ')} failed: #{stderr.strip}"
  end

  def changed_paths(root, base, head)
    if head == "WORKTREE"
      output = run_git(root, "diff", "--name-only", "--diff-filter=ACMRTUXB", base, "--") || ""
      untracked = run_git(root, "ls-files", "--others", "--exclude-standard") || ""
      return (output.lines + untracked.lines).map(&:strip).reject(&:empty?).uniq.sort
    end

    output = run_git(root, "diff", "--name-only", "--diff-filter=ACMRTUXB", base, head, "--")
    output.lines.map(&:strip).reject(&:empty?).uniq.sort
  end

  def yaml_at(root, ref, path)
    text = if ref == "WORKTREE"
             absolute = File.join(root, path)
             File.file?(absolute) ? File.read(absolute) : nil
           else
             run_git(root, "show", "#{ref}:#{path}", allow_failure: true)
           end
    return {} if text.nil? || text.empty?

    YAML.safe_load(text, aliases: false) || {}
  rescue Psych::SyntaxError => e
    raise ArgumentError, "invalid YAML at #{ref}:#{path}: #{e.message}"
  end

  def changed_keys(before, after)
    before = before.is_a?(Hash) ? before : {}
    after = after.is_a?(Hash) ? after : {}
    (before.keys | after.keys).select { |key| before[key] != after[key] }.sort
  end

  def canonical_service_components(names, services)
    Array(names).filter_map do |name|
      name = name.to_s
      "service:#{name}" if services.include?(name)
    end
  end

  def event_tail(event_name)
    event_name.to_s.split(".", 2).last
  end

  def event_producer(event_name)
    event_name.to_s.split(".", 2).first
  end

  def event_index(events)
    entries = events.fetch("events", {})
    entries.each_with_object({}) do |(event_name, spec), index|
      index[event_tail(event_name)] = {
        "producer" => event_producer(event_name),
        "consumers" => Array(spec && spec["consumers"])
      }
    end
  end

  def dependency_entry_impact(service, before_entry, after_entry, services, before_events, after_events)
    impact = Set.new(["service:#{service}"])
    %w[sync sync_external].each do |key|
      refs = Array(before_entry && before_entry[key]) | Array(after_entry && after_entry[key])
      canonical_service_components(refs, services).each { |component| impact << component }
    end

    old_index = event_index(before_events)
    new_index = event_index(after_events)
    before_in = Array(before_entry && before_entry["events_in"])
    after_in = Array(after_entry && after_entry["events_in"])
    changed_events = (before_in - after_in) | (after_in - before_in)
    changed_events.each do |tail|
      [old_index[tail], new_index[tail]].compact.each do |event|
        canonical_service_components([event["producer"], *event["consumers"]], services).each do |component|
          impact << component
        end
      end
    end
    impact
  end

  def semantic_contract_impact(path, before:, after:, services:, frontends:, context: {})
    impact = Set.new
    case path
    when "config/contracts/service-ownership.yaml"
      old_services = before.fetch("services", {})
      new_services = after.fetch("services", {})
      changed_keys(old_services, new_services).each do |service|
        next unless services.include?(service)

        impact << "service:#{service}"
        refs = Array(old_services.dig(service, "sync_dependencies")) |
               Array(new_services.dig(service, "sync_dependencies"))
        canonical_service_components(refs, services).each { |component| impact << component }
      end
    when "config/contracts/dependency-map.yaml"
      old_services = before.fetch("services", {})
      new_services = after.fetch("services", {})
      before_events = context.fetch(:before_events, {})
      after_events = context.fetch(:after_events, {})
      changed_keys(old_services, new_services).each do |service|
        next unless services.include?(service)

        dependency_entry_impact(service, old_services[service], new_services[service], services,
                                before_events, after_events).each { |component| impact << component }
      end
    when "config/contracts/event-contracts.yaml"
      old_events = before.fetch("events", {})
      new_events = after.fetch("events", {})
      changed_keys(old_events, new_events).each do |event_name|
        old_spec = old_events[event_name] || {}
        new_spec = new_events[event_name] || {}
        refs = [event_producer(event_name), *Array(old_spec["consumers"]), *Array(new_spec["consumers"])]
        canonical_service_components(refs, services).each { |component| impact << component }
      end
    when "config/contracts/public-api-contracts.yaml"
      global_keys = (before.keys | after.keys) - ["contracts"]
      global_changed = global_keys.any? { |key| before[key] != after[key] }
      if global_changed
        services.each { |service| impact << "service:#{service}" }
        frontends.each { |frontend| impact << "frontend:#{frontend}" }
      else
        old_contracts = before.fetch("contracts", {})
        new_contracts = after.fetch("contracts", {})
        changed_keys(old_contracts, new_contracts).each do |service|
          impact << "service:#{service}" if services.include?(service)
          old_audiences = Array(old_contracts.dig(service, "audiences"))
          new_audiences = Array(new_contracts.dig(service, "audiences"))
          (old_audiences | new_audiences).each do |audience|
            impact << "frontend:#{audience}" if frontends.include?(audience)
          end
        end
      end
    end
    impact.to_a.sort
  end

  def contract_impact_map(root, base, head, paths, services:, frontends: FRONTENDS)
    before_events = yaml_at(root, base, "config/contracts/event-contracts.yaml")
    after_events = yaml_at(root, head, "config/contracts/event-contracts.yaml")
    context = {before_events: before_events, after_events: after_events}

    SEMANTIC_CONTRACTS.each_with_object({}) do |path, impacts|
      next unless paths.include?(path)

      impacts[path] = semantic_contract_impact(
        path,
        before: yaml_at(root, base, path),
        after: yaml_at(root, head, path),
        services: services,
        frontends: frontends,
        context: context
      )
    end
  end

  def load_project(root, ref)
    lock = yaml_at(root, ref, "architecture.lock.yaml")
    ownership = yaml_at(root, ref, "config/contracts/service-ownership.yaml")
    public_api = yaml_at(root, ref, "config/contracts/public-api-contracts.yaml")
    services = ownership.fetch("services").keys
    canonical = lock.dig("business", "services") || []
    raise "service ownership differs from architecture.lock.yaml" unless services.sort == canonical.sort

    [services, public_contract_index(public_api), public_api["common_components"]]
  end
end

if $PROGRAM_NAME == __FILE__
  options = {head: ENV["HEAD"].to_s.empty? ? "HEAD" : ENV["HEAD"], format: "lines", strict_unknown: false}
  parser = OptionParser.new do |opts|
    opts.banner = "Usage: ci-affected.rb --base REF [--head REF|WORKTREE] [--format lines|json]"
    opts.on("--base REF") { |value| options[:base] = value }
    opts.on("--head REF") { |value| options[:head] = value }
    opts.on("--format FORMAT") { |value| options[:format] = value }
    opts.on("--strict-unknown") { options[:strict_unknown] = true }
  end
  parser.parse!(ARGV)
  options[:base] ||= ENV["BASE"] unless ENV["BASE"].to_s.empty?
  abort parser.to_s if options[:base].to_s.empty?
  abort "format must be lines or json" unless %w[lines json].include?(options[:format])

  root = File.expand_path("..", __dir__)
  services, public_contracts, common_openapi = AffectedComponents.load_project(root, options[:head])
  paths = AffectedComponents.changed_paths(root, options[:base], options[:head])
  contract_impact = AffectedComponents.contract_impact_map(
    root, options[:base], options[:head], paths, services: services
  )
  affected = AffectedComponents.classify(
    paths,
    services: services,
    public_contracts: public_contracts,
    common_openapi: common_openapi,
    contract_impact: contract_impact,
    strict_unknown: options[:strict_unknown]
  )
  if options[:format] == "json"
    puts JSON.generate(affected)
  else
    puts affected
  end
end
