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
if transport && transport_hosts.keys.sort != expected_hosts
  warn "MGMT transport overlay host set mismatch"
  exit 2
end


def transport_vars(hosts, name, fallback)
  return { "ansible_host" => fallback } if hosts.empty?

  value = hosts.fetch(name)
  raise KeyError, "transport host #{name} must be a mapping" unless value.is_a?(Hash)
  value.slice("ansible_host", "ansible_ssh_common_args", "transport")
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
  hostvars[name] = transport_vars(transport_hosts, name, node.fetch("mgmt_ip")).merge({
    "rke2_role" => "server",
    "profile" => node.fetch("profile"),
    "mgmt_ip" => node.fetch("mgmt_ip"),
    "k8s_ip" => node.fetch("k8s_ip"),
    "mgmt_private_alias_cidrs" => [cidr_for(node.fetch("k8s_ip"), 402, mgmt_segments)],
    "rke2_version" => rke2_version,
    "rke2_server_url" => name == bootstrap_server ? "" : server_url,
    "rke2_cluster_cidr" => network_plan.dig("kubernetes", "mgmt", "pod_cidr"),
    "rke2_service_cidr" => network_plan.dig("kubernetes", "mgmt", "service_cidr"),
    "mgmt_firewall_role" => "control-plane",
    "mgmt_firewall_cidrs" => mgmt_segments.transform_values { |segment| segment.fetch("cidr") }
  })
end

workers.each do |name, node|
  hostvars[name] = transport_vars(transport_hosts, name, node.fetch("mgmt_ip")).merge({
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
    "rke2_server_url" => server_url,
    "mgmt_firewall_role" => "worker",
    "mgmt_firewall_cidrs" => mgmt_segments.transform_values { |segment| segment.fetch("cidr") }
  })
end

access_gateways.each do |name, node|
  hostvars[name] = transport_vars(transport_hosts, name, node.fetch("mgmt_ip")).merge({
    "mgmt_ip" => node.fetch("mgmt_ip"),
    "wireguard_listen_port" => network_plan.dig("wireguard", "mgmt", "endpoint", "listen_port"),
    "wireguard_operator_pool" => network_plan.dig("wireguard", "mgmt", "operator_pool"),
    "wireguard_break_glass_pool" => network_plan.dig("wireguard", "mgmt", "break_glass_pool"),
    "wireguard_tunnel_cidr" => network_plan.dig("wireguard", "mgmt", "tunnel_cidr"),
    "wireguard_gateway_tunnel_ip" => network_plan.dig("wireguard", "mgmt", "gateway_tunnel_ip"),
    "wireguard_allowed_routes" => network_plan.dig("wireguard", "mgmt", "allowed_routes"),
    "wireguard_snat_source_cidr" => network_plan.dig("wireguard", "mgmt", "return_path", "source_cidr"),
    "wireguard_snat_destination_cidr" => network_plan.dig("wireguard", "mgmt", "return_path", "destination_cidr"),
    "wireguard_snat_to_source" => network_plan.dig("wireguard", "mgmt", "return_path", "translated_source_ip")
  })
end

inventory = {
  "_meta" => { "hostvars" => hostvars },
  "all" => {
    "children" => %w[access_gateways rke2_servers rke2_agents],
    "vars" => {
      "mgmt_private_block" => network_plan.dig("address_domains", "mgmt"),
      "mgmt_pod_cidr" => network_plan.dig("kubernetes", "mgmt", "pod_cidr"),
      "mgmt_service_cidr" => network_plan.dig("kubernetes", "mgmt", "service_cidr")
    }
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
