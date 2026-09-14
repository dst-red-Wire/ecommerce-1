output "network_id" {
  description = "Hetzner Cloud network ID for the persistent management plane."
  value       = module.hcloud_mgmt.network_id
}

output "servers" {
  description = "Canonical management-plane server IDs and public transport addresses."
  value       = module.hcloud_mgmt.servers
}

output "private_networks" {
  description = "Canonical management-plane private network and alias realization."
  value       = module.hcloud_mgmt.private_networks
}

output "access_gateways" {
  description = "Provider addresses for the controlled management-access boundary."
  value       = module.hcloud_mgmt.access_gateways
}

output "runtime_transport" {
  description = "Non-secret fail-closed bootstrap/steady transport model for dynamic Ansible inventory."
  value       = module.hcloud_mgmt.runtime_transport
}

output "declared_static_inventory" {
  description = "Contract-derived resource counts; this is not provider plan evidence."
  value       = module.hcloud_mgmt.declared_static_inventory
}
