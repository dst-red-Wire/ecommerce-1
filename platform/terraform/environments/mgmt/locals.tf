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

  # Terraform has no built-in IPv4 containment predicate. Convert addresses to
  # integers so checks can compare each inventory address to its CIDR bounds.
  ipv4_octet_weights = [16777216, 65536, 256, 1]

  mgmt_segment_ipv4_bounds = {
    for vlan, segment in local.mgmt_segments :
    vlan => {
      first = sum([
        for index, octet in split(".", cidrhost(segment.cidr, 0)) :
        tonumber(octet) * local.ipv4_octet_weights[index]
      ])
      last = sum([
        for index, octet in split(".", cidrhost(segment.cidr, -1)) :
        tonumber(octet) * local.ipv4_octet_weights[index]
      ])
    }
  }

  node_ipv4_numbers = {
    for name, node in local.nodes :
    name => {
      mgmt = sum([
        for index, octet in split(".", node.mgmt_ip) :
        tonumber(octet) * local.ipv4_octet_weights[index]
      ])
      k8s = sum([
        for index, octet in split(".", node.k8s_ip) :
        tonumber(octet) * local.ipv4_octet_weights[index]
      ])
      storage = try(sum([
        for index, octet in split(".", node.storage_ip) :
        tonumber(octet) * local.ipv4_octet_weights[index]
      ]), null)
      backup = try(sum([
        for index, octet in split(".", node.backup_ip) :
        tonumber(octet) * local.ipv4_octet_weights[index]
      ]), null)
    }
  }

  expected_nodes = toset([
    "cp-01",
    "cp-02",
    "cp-03",
    "worker-01",
    "worker-02",
    "worker-03",
  ])
}
