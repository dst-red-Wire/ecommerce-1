module "hcloud_mgmt" {
  source = "../../modules/hcloud-mgmt"

  nodes        = local.nodes
  vm_profiles  = local.vm_profiles
  network_cidr = local.mgmt_private_block
  subnets = {
    for vlan, segment in local.mgmt_segments : tostring(vlan) => segment.cidr
  }
  network_zone = var.hcloud_network_zone

  location     = var.hcloud_location
  image        = var.hcloud_image
  server_types = var.hcloud_server_types

  access_gateways       = local.access_gateways
  access_profiles       = local.access_profiles
  access_server_types   = var.hcloud_access_server_types
  wireguard_listen_port = local.wireguard.endpoint.listen_port
  management_cidr       = local.mgmt_segments[401].cidr
  kubernetes_cidr       = local.mgmt_segments[402].cidr
}
