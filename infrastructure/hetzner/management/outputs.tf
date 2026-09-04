output "git_url" {
  description = "Future authoritative Gitea URL."
  value       = "https://${var.git_dns_name}.${var.dns_zone}"
}

output "registry_url" {
  description = "Future authoritative Harbor registry URL."
  value       = "https://${var.registry_dns_name}.${var.dns_zone}"
}

output "gitea_public_ipv4" {
  description = "Public IPv4 address of gitea-mgmt."
  value       = hcloud_server.gitea.ipv4_address
}

output "harbor_public_ipv4" {
  description = "Public IPv4 address of harbor-mgmt."
  value       = hcloud_server.harbor.ipv4_address
}

output "gitea_private_ipv4" {
  description = "Deterministic private IPv4 address of gitea-mgmt."
  value       = hcloud_server_network.gitea.ip
}

output "harbor_private_ipv4" {
  description = "Deterministic private IPv4 address of harbor-mgmt."
  value       = hcloud_server_network.harbor.ip
}

output "data_private_ipv4" {
  description = "Deterministic private IPv4 address of private-only data-mgmt."
  value       = local.private_ips.data
}

output "management_network_id" {
  description = "Hetzner ID of the dedicated management network."
  value       = hcloud_network.management.id
}

output "inventory_contract" {
  description = "Non-secret contract for the future management Ansible inventory."
  value = {
    "gitea-mgmt" = {
      ansible_host = hcloud_server.gitea.ipv4_address
      private_ip   = hcloud_server_network.gitea.ip
      service      = "gitea"
    }
    "harbor-mgmt" = {
      ansible_host = hcloud_server.harbor.ipv4_address
      private_ip   = hcloud_server_network.harbor.ip
      service      = "harbor"
    }
    "data-mgmt" = {
      ansible_host      = local.private_ips.data
      private_ip        = local.private_ips.data
      bastion           = hcloud_server.gitea.ipv4_address
      egress_proxy_host = local.private_ips.gitea
      egress_proxy_port = 3128
      service           = "postgresql-management"
    }
  }
}

output "management_ssh_allowed_cidrs" {
  description = "Approved CIDRs to reproduce the Terraform SSH boundary in the Ansible host firewall."
  value       = var.ssh_allowed_cidrs
}
