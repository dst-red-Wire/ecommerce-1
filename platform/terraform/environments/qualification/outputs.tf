output "qualification_server_id" { value = module.hcloud_qualification.server_id }
output "qualification_runner_private_ipv4" { value = module.hcloud_qualification.runner_private_ip }
output "qualification_gateway_ipv4" { value = module.hcloud_qualification.gateway_ipv4 }
output "qualification_gateway_private_ipv4" { value = module.hcloud_qualification.gateway_private_ip }
output "qualification_user" { value = module.hcloud_qualification.user }
output "qualification_image_identity" { value = module.hcloud_qualification.image_identity }

output "qualification_inventory_host_line" {
  description = "Non-secret ProxyJump inventory handoff for canonical qualification-runner.yml."
  value       = "qualification ansible_host=${module.hcloud_qualification.runner_private_ip} ansible_user=${module.hcloud_qualification.user} qualification_user=${module.hcloud_qualification.user} ansible_ssh_common_args='-o ProxyJump=ubuntu@${module.hcloud_qualification.gateway_ipv4}'"
}

output "qualification_proxy_environment" {
  description = "Non-secret proxy environment for runner tools; the provider firewall is the enforcement boundary."
  value = {
    HTTP_PROXY  = "http://${module.hcloud_qualification.gateway_private_ip}:3128"
    HTTPS_PROXY = "http://${module.hcloud_qualification.gateway_private_ip}:3128"
    NO_PROXY    = "localhost,127.0.0.1,${module.hcloud_qualification.runner_private_ip},${module.hcloud_qualification.gateway_private_ip}"
  }
}
