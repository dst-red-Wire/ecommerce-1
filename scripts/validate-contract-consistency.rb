#!/usr/bin/env ruby
# frozen_string_literal: true

require "yaml"

module ContractConsistency
  module_function

  FILES = {
    lock: "architecture.lock.yaml",
    ownership: "config/contracts/service-ownership.yaml",
    dependencies: "config/contracts/dependency-map.yaml",
    events: "config/contracts/event-contracts.yaml",
    public_api: "config/contracts/public-api-contracts.yaml"
  }.freeze

  def load_yaml(root, relative)
    YAML.safe_load(File.read(File.join(root, relative)), aliases: false) || {}
  end

  def validate(root)
    data = FILES.transform_values { |path| load_yaml(root, path) }
    errors = []
    canonical_services = Array(data[:lock].dig("business", "services"))
    frontends = Array(data[:lock].dig("business", "frontends"))
    ownership = data[:ownership].fetch("services", {})
    dependencies = data[:dependencies].fetch("services", {})

    errors << "service-ownership services must equal architecture.lock.yaml services" unless ownership.keys.sort == canonical_services.sort
    errors << "dependency-map services must equal architecture.lock.yaml services" unless dependencies.keys.sort == canonical_services.sort

    canonical_services.each do |service|
      owned_sync = Array(ownership.dig(service, "sync_dependencies"))
      dependency_sync = Array(dependencies.dig(service, "sync")) + Array(dependencies.dig(service, "sync_external"))
      unless owned_sync.sort == dependency_sync.sort
        errors << "#{service} sync_dependencies differs between service-ownership and dependency-map: #{owned_sync.inspect} != #{dependency_sync.inspect}"
      end
    end

    events = data[:events].fetch("events", {})
    by_tail = Hash.new { |hash, key| hash[key] = [] }
    events.each do |event_name, spec|
      producer, tail = event_name.to_s.split(".", 2)
      if tail.to_s.empty?
        errors << "invalid event name: #{event_name}"
        next
      end
      errors << "event #{event_name} producer is not canonical: #{producer}" unless canonical_services.include?(producer)
      by_tail[tail] << event_name
      Array(spec && spec["consumers"]).each do |consumer|
        unless canonical_services.include?(consumer)
          errors << "event #{event_name} consumer is not canonical: #{consumer}"
          next
        end
        incoming = Array(dependencies.dig(consumer, "events_in"))
        errors << "#{consumer} dependency-map is missing #{tail} consumed from #{event_name}" unless incoming.include?(tail)
      end
    end

    canonical_services.each do |service|
      Array(dependencies.dig(service, "events_in")).each do |tail|
        matches = by_tail[tail]
        if matches.empty?
          errors << "#{service} events_in references unknown event tail #{tail}"
        elsif matches.length > 1
          errors << "#{service} events_in event tail #{tail} is ambiguous: #{matches.join(', ')}"
        elsif !Array(events.dig(matches.first, "consumers")).include?(service)
          errors << "#{service} events_in contains #{tail} but #{matches.first} does not declare #{service} as consumer"
        end
      end
    end

    data[:public_api].fetch("contracts", {}).each do |service, contract|
      errors << "public API contract owner is not canonical: #{service}" unless canonical_services.include?(service)
      Array(contract && contract["audiences"]).each do |audience|
        errors << "public API audience is not a canonical frontend: #{service} -> #{audience}" unless frontends.include?(audience)
      end
    end

    errors
  rescue Errno::ENOENT, Psych::SyntaxError, KeyError, TypeError => e
    ["contract consistency input is invalid: #{e.message}"]
  end
end

if $PROGRAM_NAME == __FILE__
  root = ARGV.fetch(0, File.expand_path("..", __dir__))
  errors = ContractConsistency.validate(root)
  if errors.empty?
    puts "[contracts] cross-registry consistency: PASS"
  else
    warn errors.map { |error| "[contracts] #{error}" }.join("\n")
    exit 1
  end
end
