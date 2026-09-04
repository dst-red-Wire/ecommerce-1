output "api_endpoint" {
  description = "Private DNS HA endpoint for kubeadm controlPlaneEndpoint."
  value       = "${var.api_server_dns_name}:6443"
}

output "api_private_ipv4" {
  description = "Private load balancer address that the API DNS name must resolve to."
  value       = hcloud_load_balancer_network.api.ip
}

output "control_plane_ipv4" {
  description = "Public control-plane addresses used to generate Ansible inventory."
  value = {
    for name, server in hcloud_server.nodes : name => server.ipv4_address
    if local.nodes[name].role == "control-plane"
  }
}

output "worker_ipv4" {
  description = "Public worker addresses used to generate Ansible inventory."
  value = {
    for name, server in hcloud_server.nodes : name => server.ipv4_address
    if local.nodes[name].role == "worker"
  }
}

output "private_ipv4" {
  description = "Private addresses used for Kubernetes node communication."
  value = {
    for name, attachment in hcloud_server_network.nodes : name => attachment.ip
  }
}

output "inventory_contract" {
  description = "Deterministic, non-secret input for the Ansible inventory renderer."
  value = {
    api_endpoint     = "${var.api_server_dns_name}:6443"
    api_private_ipv4 = hcloud_load_balancer_network.api.ip
    campaign = {
      id          = var.campaign_id
      owner       = var.owner
      expires_at  = var.expires_at
      cost_center = var.cost_center
    }
    control_planes = {
      for name, server in hcloud_server.nodes : name => {
        ansible_host = server.ipv4_address
        private_ip   = hcloud_server_network.nodes[name].ip
      } if local.nodes[name].role == "control-plane"
    }
    workers = {
      for name, server in hcloud_server.nodes : name => {
        ansible_host = server.ipv4_address
        private_ip   = hcloud_server_network.nodes[name].ip
      } if local.nodes[name].role == "worker"
    }
  }
}
