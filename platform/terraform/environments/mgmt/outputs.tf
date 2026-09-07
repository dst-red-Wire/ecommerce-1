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
