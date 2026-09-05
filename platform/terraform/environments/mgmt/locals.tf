locals {
  repository_root = abspath("${path.module}/../../../..")

  mgmt_inventory = yamldecode(
    file("${local.repository_root}/config/infrastructure/mgmt-inventory.yaml")
  )

  network_plan = yamldecode(
    file("${local.repository_root}/config/infrastructure/network-plan.yaml")
  )

  control_planes = local.mgmt_inventory.control_planes
  workers        = local.mgmt_inventory.workers

  nodes = merge(
    {
      for name, node in local.control_planes :
      name => merge(node, { role = "server" })
    },
    {
      for name, node in local.workers :
      name => merge(node, { role = "agent" })
    }
  )

  vm_profiles = local.mgmt_inventory.vm_profiles

  mgmt_private_block = local.mgmt_inventory.private_block
  mgmt_segments      = local.network_plan.vlans.mgmt
  mgmt_static_ips    = local.network_plan.static_allocations.mgmt

  expected_nodes = toset([
    "cp-01",
    "cp-02",
    "cp-03",
    "worker-01",
    "worker-02",
    "worker-03",
  ])
}
