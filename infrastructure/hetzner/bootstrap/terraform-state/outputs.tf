output "server_public_ipv4" {
  description = "Public IPv4 used only for restricted SSH administration and local tunnels."
  value       = hcloud_server.terraform_state.ipv4_address
}

output "postgresql_volume_id" {
  description = "Protected persistent volume containing PostgreSQL data."
  value       = hcloud_volume.postgresql.id
}

output "inventory_contract" {
  description = "Non-secret contract consumed by the separate bootstrap Ansible inventory renderer."
  value = {
    server_id                   = hcloud_server.terraform_state.id
    server_name                 = hcloud_server.terraform_state.name
    server_ipv4                 = hcloud_server.terraform_state.ipv4_address
    hostname                    = "terraform-state-mgmt"
    ansible_host                = hcloud_server.terraform_state.ipv4_address
    service                     = "terraform-state-postgresql"
    postgresql_bind_address     = "127.0.0.1"
    postgresql_volume_device    = hcloud_volume.postgresql.linux_device
    postgresql_volume_id        = hcloud_volume.postgresql.id
    ssh_allowed_ipv4_cidrs      = var.ssh_allowed_cidrs
    public_postgresql_exposed   = false
    management_plane_dependency = false
  }
}

output "cost_review_contract" {
  description = "Explicit sizing inputs to review at the paid bootstrap plan gate."
  value = {
    location          = var.location
    server_type       = var.server_type
    server_count      = 1
    public_ipv4_count = 1
    volume_count      = 1
    volume_size_gb    = var.postgresql_volume_size_gb
  }
}
