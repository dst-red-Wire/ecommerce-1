module "hcloud_mgmt" {
  source = "../../modules/hcloud-mgmt"

  nodes        = local.nodes
  vm_profiles  = local.vm_profiles
  network_cidr = local.mgmt_private_block

  location     = var.hcloud_location
  image        = var.hcloud_image
  server_types = var.hcloud_server_types
}
