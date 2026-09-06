#!/usr/bin/env ruby
# frozen_string_literal: true

require "json"
require "optparse"
require "set"
require "yaml"

module AffectedComponents
  module_function

  FRONTENDS = %w[storefront admin].freeze
  PLATFORM_COMPONENTS = %w[platform:terraform platform:ansible].freeze

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

  def classify(paths, services:, public_contracts:, common_openapi: nil)
    components = Set.new(["global"])

    paths.each do |raw_path|
      path = raw_path.to_s.sub(%r{\A\./}, "")
      next if path.empty?

      case path
      when "architecture.lock.yaml", "Makefile", "go.work",
           "config/contracts/ci-topology.yaml", "config/toolchain/versions.env"
        force_all!(components, services)
      when %r{\Ascripts/ci-[^/]+\.(?:sh|rb|py)\z}, %r{\Aplatform/tekton/}
        force_all!(components, services)
      when %r{\Aservices/([^/]+)/}
        service = Regexp.last_match(1)
        raise ArgumentError, "unknown service path changed: #{service}" unless services.include?(service)

        components << "service:#{service}"
      when %r{\Afrontend/apps/(storefront|admin)/}
        components << "frontend:#{Regexp.last_match(1)}"
      when %r{\Afrontend/packages/}, %r{\Afrontend/(?:package\.json|pnpm-lock\.yaml|pnpm-workspace\.yaml|eslint\.config\.mjs|vitest\.setup\.ts|playwright\.config\.ts)\z}
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
        services.each { |service| components << "service:#{service}" }
        components << "system"
      when "config/contracts/service-ownership.yaml", "config/contracts/dependency-map.yaml",
           "config/contracts/event-contracts.yaml", "config/contracts/public-api-contracts.yaml"
        services.each { |service| components << "service:#{service}" }
        components << "system"
      when %r{\Atests/(?:e2e|integration|performance|security|resilience|chaos)/}
        components << "system"
      end
    end

    components.to_a.sort
  end

  def changed_paths(base, head)
    output = IO.popen(["git", "diff", "--name-only", "--diff-filter=ACMRTUXB", base, head, "--"], &:read)
    status = $?
    raise "git diff failed for #{base}..#{head}" unless status&.success?

    output.lines.map(&:strip).reject(&:empty?)
  end

  def load_project(root)
    lock = YAML.safe_load(File.read(File.join(root, "architecture.lock.yaml")))
    ownership = YAML.safe_load(File.read(File.join(root, "config/contracts/service-ownership.yaml")))
    public_api = YAML.safe_load(File.read(File.join(root, "config/contracts/public-api-contracts.yaml")))
    services = ownership.fetch("services").keys
    canonical = lock.dig("business", "services") || []
    raise "service ownership differs from architecture.lock.yaml" unless services.sort == canonical.sort

    [services, public_contract_index(public_api), public_api["common_components"]]
  end
end

if $PROGRAM_NAME == __FILE__
  options = {head: ENV["HEAD"].to_s.empty? ? "HEAD" : ENV["HEAD"], format: "lines"}
  parser = OptionParser.new do |opts|
    opts.banner = "Usage: ci-affected.rb --base SHA [--head SHA] [--format lines|json]"
    opts.on("--base SHA") { |value| options[:base] = value }
    opts.on("--head SHA") { |value| options[:head] = value }
    opts.on("--format FORMAT") { |value| options[:format] = value }
  end
  parser.parse!(ARGV)
  options[:base] ||= ENV["BASE"] unless ENV["BASE"].to_s.empty?
  abort parser.to_s if options[:base].to_s.empty?
  abort "format must be lines or json" unless %w[lines json].include?(options[:format])

  root = File.expand_path("..", __dir__)
  services, public_contracts, common_openapi = AffectedComponents.load_project(root)
  paths = AffectedComponents.changed_paths(options[:base], options[:head])
  affected = AffectedComponents.classify(paths, services: services, public_contracts: public_contracts,
                                          common_openapi: common_openapi)
  if options[:format] == "json"
    puts JSON.generate(affected)
  else
    puts affected
  end
end
