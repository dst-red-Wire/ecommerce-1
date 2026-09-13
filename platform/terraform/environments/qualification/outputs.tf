output "qualification_server_id" {
  value = module.hcloud_qualification.server_id
}

output "qualification_ipv4" {
  value = module.hcloud_qualification.ipv4
}

output "qualification_host" {
  value = module.hcloud_qualification.ipv4
}

output "qualification_user" {
  value = module.hcloud_qualification.user
}

output "qualification_image_identity" {
  value = module.hcloud_qualification.image_identity
}

output "qualification_inventory_host_line" {
  description = "Non-secret inventory handoff for the canonical qualification-runner.yml playbook."
  value       = "qualification ansible_host=${module.hcloud_qualification.ipv4} ansible_user=${module.hcloud_qualification.user}"
}
