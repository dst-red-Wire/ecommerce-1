#!/usr/bin/env ruby
# frozen_string_literal: true

require "json"
require "yaml"

root = File.expand_path("../../../..", __dir__)
contract_path = File.join(root, "config/infrastructure/mgmt-inventory.yaml")
contract = YAML.safe_load(File.read(contract_path))

control_planes = contract.fetch("control_planes")
workers = contract.fetch("workers")

hostvars = {}

control_planes.each do |name, node|
  hostvars[name] = {
    "ansible_host" => node.fetch("mgmt_ip"),
    "rke2_role" => "server",
    "profile" => node.fetch("profile"),
    "mgmt_ip" => node.fetch("mgmt_ip"),
    "k8s_ip" => node.fetch("k8s_ip")
  }
end

workers.each do |name, node|
  hostvars[name] = {
    "ansible_host" => node.fetch("mgmt_ip"),
    "rke2_role" => "agent",
    "profile" => node.fetch("profile"),
    "mgmt_ip" => node.fetch("mgmt_ip"),
    "k8s_ip" => node.fetch("k8s_ip"),
    "storage_ip" => node.fetch("storage_ip"),
    "backup_ip" => node.fetch("backup_ip")
  }
end

inventory = {
  "_meta" => { "hostvars" => hostvars },
  "all" => {
    "children" => %w[rke2_servers rke2_agents]
  },
  "rke2_servers" => {
    "hosts" => control_planes.keys
  },
  "rke2_agents" => {
    "hosts" => workers.keys
  }
}

puts JSON.generate(inventory)
