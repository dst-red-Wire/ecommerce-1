#!/usr/bin/env ruby
# frozen_string_literal: true

require "json"
require "yaml"

root = File.expand_path("../../../..", __dir__)
contract_path = File.join(root, "config/infrastructure/mgmt-inventory.yaml")
network_plan_path = File.join(root, "config/infrastructure/network-plan.yaml")
access_path = File.join(root, "config/infrastructure/mgmt-access-gateways.yaml")
bootstrap_path = File.join(root, "config/infrastructure/mgmt-bootstrap.yaml")
contract = YAML.safe_load(File.read(contract_path))
network_plan = YAML.safe_load(File.read(network_plan_path))
access_contract = YAML.safe_load(File.read(access_path))
bootstrap = YAML.safe_load(File.read(bootstrap_path))

control_planes = contract.fetch("control_planes")
workers = contract.fetch("workers")
access_gateways = access_contract.fetch("access_gateways")
mgmt_segments = network_plan.fetch("vlans").fetch("mgmt")
transport_path = ENV.fetch("MGMT_TRANSPORT_INVENTORY", File.join(root, ".context/runtime/mgmt-ansible-transport.json"))
transport = File.file?(transport_path) ? JSON.parse(File.read(transport_path)) : nil
transport_hosts = transport ? transport.fetch("hosts") : {}
expected_hosts = (control_planes.keys + workers.keys + access_gateways.keys).sort
transport_host_sets = [expected_hosts, (control_planes.keys + workers.keys).sort]
if transport && !transport_host_sets.include?(transport_hosts.keys.sort)
  warn "MGMT transport overlay host set mismatch"
  exit 2
end

def cidr_for(ip, segment, segments)
  prefix = segments.fetch(segment).fetch("cidr").split("/", 2).fetch(1)
  "#{ip}/#{prefix}"
end

hostvars = {}
rke2_version = bootstrap.fetch("rke2").fetch("version")
bootstrap_server = bootstrap.fetch("rke2").fetch("bootstrap_server")
server_url = "https://#{control_planes.fetch(bootstrap_server).fetch('k8s_ip')}:9345"

control_planes.each do |name, node|
  hostvars[name] = {
    "ansible_host" => transport_hosts.fetch(name, node.fetch("mgmt_ip")),
    "rke2_role" => "server",
    "profile" => node.fetch("profile"),
    "mgmt_ip" => node.fetch("mgmt_ip"),
    "k8s_ip" => node.fetch("k8s_ip"),
    "mgmt_private_alias_cidrs" => [cidr_for(node.fetch("k8s_ip"), 402, mgmt_segments)],
    "rke2_version" => rke2_version,
    "rke2_server_url" => name == bootstrap_server ? "" : server_url
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
    ],
    "rke2_version" => rke2_version,
    "rke2_server_url" => server_url
  }
end

access_gateways.each do |name, node|
  hostvars[name] = {
    "ansible_host" => transport_hosts.fetch(name, node.fetch("mgmt_ip")),
    "mgmt_ip" => node.fetch("mgmt_ip"),
    "wireguard_listen_port" => network_plan.dig("wireguard", "mgmt", "endpoint", "listen_port"),
    "wireguard_tunnel_cidr" => network_plan.dig("wireguard", "mgmt", "tunnel_cidr"),
    "wireguard_gateway_tunnel_ip" => network_plan.dig("wireguard", "mgmt", "gateway_tunnel_ip"),
    "wireguard_allowed_routes" => network_plan.dig("wireguard", "mgmt", "allowed_routes")
  }
end

inventory = {
  "_meta" => { "hostvars" => hostvars },
  "all" => {
    "children" => %w[access_gateways rke2_servers rke2_agents]
  },
  "rke2_servers" => {
    "hosts" => control_planes.keys
  },
  "rke2_agents" => {
    "hosts" => workers.keys
  },
  "access_gateways" => {
    "hosts" => access_gateways.keys
  }
}

puts JSON.generate(inventory)
