check "exact_mgmt_node_set" {
  assert {
    condition     = toset(keys(local.nodes)) == local.expected_nodes
    error_message = "MGMT inventory must contain exactly cp-01..03 and worker-01..03."
  }
}

check "known_vm_profiles" {
  assert {
    condition = alltrue([
      for node in values(local.nodes) :
      contains(keys(local.vm_profiles), node.profile)
    ])
    error_message = "Every MGMT node must reference a declared vm_profile."
  }
}

check "private_block_consistency" {
  assert {
    condition     = local.mgmt_private_block == local.network_plan.address_domains.mgmt
    error_message = "MGMT private block differs between inventory and network plan."
  }
}

check "mgmt_ips_inside_segment" {
  assert {
    condition = alltrue([
      for node in values(local.nodes) :
      cidrcontains(local.mgmt_segments["401"].cidr, node.mgmt_ip)
    ])
    error_message = "Every MGMT management IP must belong to VLAN/segment 401."
  }
}

check "k8s_ips_inside_segment" {
  assert {
    condition = alltrue([
      for node in values(local.nodes) :
      cidrcontains(local.mgmt_segments["402"].cidr, node.k8s_ip)
    ])
    error_message = "Every MGMT Kubernetes node IP must belong to VLAN/segment 402."
  }
}

check "worker_storage_ips_inside_segment" {
  assert {
    condition = alltrue([
      for node in values(local.workers) :
      cidrcontains(local.mgmt_segments["403"].cidr, node.storage_ip)
    ])
    error_message = "Every MGMT worker storage IP must belong to VLAN/segment 403."
  }
}

check "worker_backup_ips_inside_segment" {
  assert {
    condition = alltrue([
      for node in values(local.workers) :
      cidrcontains(local.mgmt_segments["405"].cidr, node.backup_ip)
    ])
    error_message = "Every MGMT worker backup IP must belong to VLAN/segment 405."
  }
}

check "unique_static_ips" {
  assert {
    condition = length(distinct(concat(
      [for node in values(local.nodes) : node.mgmt_ip],
      [for node in values(local.nodes) : node.k8s_ip],
      [for node in values(local.workers) : node.storage_ip],
      [for node in values(local.workers) : node.backup_ip],
    ))) == 18
    error_message = "MGMT static node IP addresses must be globally unique."
  }
}

check "inventory_matches_network_allocations" {
  assert {
    condition = alltrue(concat(
      [
        for name, node in local.nodes :
        local.mgmt_static_ips["401"][name] == node.mgmt_ip
      ],
      [
        for name, node in local.nodes :
        local.mgmt_static_ips["402"][name] == node.k8s_ip
      ],
      [
        for name, node in local.workers :
        local.mgmt_static_ips["403"][name] == node.storage_ip
      ],
      [
        for name, node in local.workers :
        local.mgmt_static_ips["405"][name] == node.backup_ip
      ],
    ))
    error_message = "MGMT inventory IPs must exactly match network-plan static allocations."
  }
}
