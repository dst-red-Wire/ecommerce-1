#!/usr/bin/env ruby
# frozen_string_literal: true

require "json"
require "yaml"

root = File.expand_path("../../../..", __dir__)
contract_path = File.join(root, "config/infrastructure/mgmt-inventory.yaml")
network_plan_path = File.join(root, "config/infrastructure/network-plan.yaml")
contract = YAML.safe_load(File.read(contract_path))
network_plan = YAML.safe_load(File.read(network_plan_path))

control_planes = contract.fetch("control_planes")
workers = contract.fetch("workers")
mgmt_segments = network_plan.fetch("vlans").fetch("mgmt")
transport_path = ENV.fetch("MGMT_TRANSPORT_INVENTORY", File.join(root, ".context/runtime/mgmt-ansible-transport.json"))
transport = File.file?(transport_path) ? JSON.parse(File.read(transport_path)) : nil
transport_hosts = transport ? transport.fetch("hosts") : {}
expected_hosts = (control_planes.keys + workers.keys).sort
if transport && transport_hosts.keys.sort != expected_hosts
  warn "MGMT transport overlay host set mismatch"
  exit 2
end

def cidr_for(ip, segment, segments)
  prefix = segments.fetch(segment).fetch("cidr").split("/", 2).fetch(1)
  "#{ip}/#{prefix}"
end

hostvars = {}

control_planes.each do |name, node|
  hostvars[name] = {
    "ansible_host" => transport_hosts.fetch(name, node.fetch("mgmt_ip")),
    "rke2_role" => "server",
    "profile" => node.fetch("profile"),
    "mgmt_ip" => node.fetch("mgmt_ip"),
    "k8s_ip" => node.fetch("k8s_ip"),
    "mgmt_private_alias_cidrs" => [cidr_for(node.fetch("k8s_ip"), 402, mgmt_segments)]
  }
end

workers.each do |name, node|
  hostvars[name] = {
    "ansible_host" => transport_hosts.fetch(name, node.fetch("mgmt_ip")),
    "rke2_role" => "agent",
    "profile" => node.fetch("profile"),
    "mgmt_ip" => node.fetch("mgmt_ip"),
    "k8s_ip" => node.fetch("k8s_ip"),
    "storage_ip" => node.fetch("storage_ip"),
    "backup_ip" => node.fetch("backup_ip"),
    "mgmt_private_alias_cidrs" => [
      cidr_for(node.fetch("k8s_ip"), 402, mgmt_segments),
      cidr_for(node.fetch("storage_ip"), 403, mgmt_segments),
      cidr_for(node.fetch("backup_ip"), 405, mgmt_segments)
    ]
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
