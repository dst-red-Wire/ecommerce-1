module "hcloud_qualification" {
  source = "../../modules/hcloud-qualification"

  location           = var.hcloud_location
  image              = var.qualification_image
  server_type        = var.qualification_server_type
  gateway_server_type = var.qualification_gateway_server_type
  ssh_key_id         = var.qualification_ssh_key_id
  ssh_allowed_cidrs  = var.qualification_ssh_allowed_cidrs
  qualification_user = var.qualification_user
  network_cidr       = var.qualification_network_cidr
  subnet_cidr        = var.qualification_subnet_cidr
  gateway_private_ip = var.qualification_gateway_private_ip
  runner_private_ip  = var.qualification_runner_private_ip
  squid_version      = var.qualification_squid_version
  ubuntu_snapshot    = var.qualification_ubuntu_snapshot
}
