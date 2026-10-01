# A failed check block only warns. Preconditions block planning and apply.
output "mgmt_contract_guard" {
  description = "Canonical MGMT inventory, addressing, and access gates must be valid."
  value       = true

  precondition {
    condition     = toset(keys(local.nodes)) == local.expected_nodes
    error_message = "MGMT inventory must contain exactly cp-01..03 and worker-01..03."
  }

  precondition {
    condition     = toset(keys(local.access_gateways)) == toset(["wg-01"])
    error_message = "MGMT access inventory must contain exactly the wg-01 gateway."
  }

  precondition {
    condition = try(
      local.access_gateways["wg-01"].mgmt_ip == local.mgmt_static_ips["401"]["wg-01"] &&
      local.access_gateways["wg-01"].mgmt_ip == local.wireguard.gateway_mgmt_ip,
      false
    )
    error_message = "wg-01 management IP must match the canonical static allocation and WireGuard return path."
  }

  precondition {
    condition = try(
      cidrhost(format("%s/%s", local.access_gateways["wg-01"].mgmt_ip, split("/", local.mgmt_segments["401"].cidr)[1]), 0) ==
      cidrhost(local.mgmt_segments["401"].cidr, 0),
      false
    )
    error_message = "wg-01 management IP must belong to VLAN/segment 401."
  }

  precondition {
    condition = !var.bootstrap_ssh_enabled || (
      var.bootstrap_ssh_human_gate_confirmed && length(var.bootstrap_ssh_allowed_cidrs) > 0
    )
    error_message = "Temporary wg-01 bootstrap SSH requires a confirmed human gate and at least one explicit restricted source CIDR."
  }

  precondition {
    condition     = !var.wireguard_udp_enabled || var.wireguard_udp_human_gate_confirmed
    error_message = "Public WireGuard UDP activation requires an explicit human gate."
  }

  precondition {
    condition = alltrue([
      for node in values(local.nodes) :
      contains(keys(local.vm_profiles), node.profile)
    ])
    error_message = "Every MGMT node must reference a declared vm_profile."
  }

  precondition {
    condition     = local.mgmt_private_block == local.network_plan.address_domains.mgmt
    error_message = "MGMT private block differs between inventory and network plan."
  }

  precondition {
    condition = alltrue([
      for node in values(local.node_ipv4_numbers) :
      node.mgmt >= local.mgmt_segment_ipv4_bounds["401"].first &&
      node.mgmt <= local.mgmt_segment_ipv4_bounds["401"].last
    ])
    error_message = "Every MGMT management IP must belong to VLAN/segment 401."
  }

  precondition {
    condition = alltrue([
      for node in values(local.node_ipv4_numbers) :
      node.k8s >= local.mgmt_segment_ipv4_bounds["402"].first &&
      node.k8s <= local.mgmt_segment_ipv4_bounds["402"].last
    ])
    error_message = "Every MGMT Kubernetes node IP must belong to VLAN/segment 402."
  }

  precondition {
    condition = alltrue([
      for name in keys(local.workers) :
      local.node_ipv4_numbers[name].storage >= local.mgmt_segment_ipv4_bounds["403"].first &&
      local.node_ipv4_numbers[name].storage <= local.mgmt_segment_ipv4_bounds["403"].last
    ])
    error_message = "Every MGMT worker storage IP must belong to VLAN/segment 403."
  }

  precondition {
    condition = alltrue([
      for name in keys(local.workers) :
      local.node_ipv4_numbers[name].backup >= local.mgmt_segment_ipv4_bounds["405"].first &&
      local.node_ipv4_numbers[name].backup <= local.mgmt_segment_ipv4_bounds["405"].last
    ])
    error_message = "Every MGMT worker backup IP must belong to VLAN/segment 405."
  }

  precondition {
    condition = length(distinct(concat(
      [for node in values(local.nodes) : node.mgmt_ip],
      [for node in values(local.nodes) : node.k8s_ip],
      [for node in values(local.workers) : node.storage_ip],
      [for node in values(local.workers) : node.backup_ip],
      [for gateway in values(local.access_gateways) : gateway.mgmt_ip],
    ))) == 18 + length(local.access_gateways)
    error_message = "MGMT static node and gateway IP addresses must be globally unique."
  }

  precondition {
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
