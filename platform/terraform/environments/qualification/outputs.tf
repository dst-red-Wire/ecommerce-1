output "qualification_server_id" { value = module.hcloud_qualification.server_id }
output "qualification_runner_private_ipv4" { value = module.hcloud_qualification.runner_private_ip }
output "qualification_gateway_ipv4" { value = module.hcloud_qualification.gateway_ipv4 }
output "qualification_gateway_private_ipv4" { value = module.hcloud_qualification.gateway_private_ip }
output "qualification_gateway_user" { value = module.hcloud_qualification.gateway_user }
output "qualification_network_zone" { value = module.hcloud_qualification.network_zone }
output "qualification_user" { value = module.hcloud_qualification.user }
output "qualification_image_identity" { value = module.hcloud_qualification.image_identity }

output "qualification_inventory_host_line" {
  description = "Non-secret ProxyJump inventory handoff for canonical qualification-runner.yml."
  value       = "qualification ansible_host=${module.hcloud_qualification.runner_private_ip} ansible_user=${module.hcloud_qualification.user} qualification_user=${module.hcloud_qualification.user} qualification_proxy_url=http://${module.hcloud_qualification.gateway_private_ip}:3128 qualification_proxy_no_proxy=localhost,127.0.0.1,${module.hcloud_qualification.runner_private_ip},${module.hcloud_qualification.gateway_private_ip} ansible_ssh_common_args='-o UserKnownHostsFile=$${QUALIFICATION_KNOWN_HOSTS} -o GlobalKnownHostsFile=/dev/null -o StrictHostKeyChecking=yes -o HostKeyAlias=${module.hcloud_qualification.runner_private_ip} -o ForwardAgent=no -o ClearAllForwardings=yes -o ProxyCommand=\"ssh -o UserKnownHostsFile=$${QUALIFICATION_KNOWN_HOSTS} -o GlobalKnownHostsFile=/dev/null -o StrictHostKeyChecking=yes -o HostKeyAlias=${module.hcloud_qualification.gateway_ipv4} -o ForwardAgent=no -o ClearAllForwardings=yes -l ${module.hcloud_qualification.gateway_user} -W %h:%p ${module.hcloud_qualification.gateway_ipv4}\"'"
}

output "qualification_gateway_inventory_host_line" {
  description = "Non-secret gateway inventory handoff for qualification-egress.yml."
  value       = "gateway ansible_host=${module.hcloud_qualification.gateway_ipv4} ansible_user=${module.hcloud_qualification.gateway_user} qualification_gateway_user=${module.hcloud_qualification.gateway_user} qualification_runner_private_ip=${module.hcloud_qualification.runner_private_ip} qualification_squid_version=${var.qualification_squid_version} qualification_ubuntu_snapshot=${var.qualification_ubuntu_snapshot} ansible_ssh_common_args='-o UserKnownHostsFile=$${QUALIFICATION_KNOWN_HOSTS} -o GlobalKnownHostsFile=/dev/null -o StrictHostKeyChecking=yes -o HostKeyAlias=${module.hcloud_qualification.gateway_ipv4} -o ForwardAgent=no -o ClearAllForwardings=yes'"
}

output "qualification_proxyjump" {
  value = "${module.hcloud_qualification.gateway_user}@${module.hcloud_qualification.gateway_ipv4}"
}

output "qualification_ansible_ssh_args" {
  description = "Strict two-hop SSH arguments; the operator must first create and export the verified dedicated known-hosts path."
  value       = "-o UserKnownHostsFile=$${QUALIFICATION_KNOWN_HOSTS} -o GlobalKnownHostsFile=/dev/null -o StrictHostKeyChecking=yes -o HostKeyAlias=${module.hcloud_qualification.runner_private_ip} -o ForwardAgent=no -o ClearAllForwardings=yes -o ProxyCommand=\"ssh -o UserKnownHostsFile=$${QUALIFICATION_KNOWN_HOSTS} -o GlobalKnownHostsFile=/dev/null -o StrictHostKeyChecking=yes -o HostKeyAlias=${module.hcloud_qualification.gateway_ipv4} -o ForwardAgent=no -o ClearAllForwardings=yes -l ${module.hcloud_qualification.gateway_user} -W %h:%p ${module.hcloud_qualification.gateway_ipv4}\""
}

output "qualification_proxy_environment" {
  description = "Non-secret proxy environment for runner tools; the provider firewall is the enforcement boundary."
  value = {
    HTTP_PROXY  = "http://${module.hcloud_qualification.gateway_private_ip}:3128"
    HTTPS_PROXY = "http://${module.hcloud_qualification.gateway_private_ip}:3128"
    NO_PROXY    = "localhost,127.0.0.1,${module.hcloud_qualification.runner_private_ip},${module.hcloud_qualification.gateway_private_ip}"
  }
}
