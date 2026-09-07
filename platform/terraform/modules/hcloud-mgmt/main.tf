terraform {
  required_providers {
    hcloud = {
      source = "hetznercloud/hcloud"
    }
  }
}

variable "nodes" {
  type = map(object({
    role       = string
    profile    = string
    mgmt_ip    = string
    k8s_ip     = string
    storage_ip = optional(string)
    backup_ip  = optional(string)
  }))
}

variable "vm_profiles" {
  type = map(object({
    vcpu        = number
    ram_gib     = number
    os_disk_gib = number
  }))
}

variable "server_types" {
  type = map(string)

  validation {
    condition = alltrue([
      for profile in distinct([for node in values(var.nodes) : node.profile]) :
      contains(keys(var.server_types), profile)
    ])
    error_message = "Every canonical vm_profile must map to an explicit Hetzner server type."
  }
}

variable "network_cidr" {
  type = string
}

variable "subnets" {
  description = "Canonical MGMT segment CIDRs keyed by VLAN/segment number."
  type        = map(string)

  validation {
    condition     = contains(keys(var.subnets), "401")
    error_message = "MGMT provider realization requires canonical segment 401 for each node primary private IP."
  }
}

variable "network_zone" {
  description = "Hetzner Cloud network zone matching the selected runtime location."
  type        = string

  validation {
    condition     = length(trimspace(var.network_zone)) > 0
    error_message = "network_zone must be an explicit non-empty Hetzner Cloud network zone."
  }
}

variable "location" {
  type = string
}

variable "image" {
  type = string
}

resource "hcloud_network" "mgmt" {
  name     = "ecommerce-mgmt"
  ip_range = var.network_cidr
}

# Hetzner Networks require provider subnets before servers can receive canonical
# private addresses. The segment CIDRs remain sourced from network-plan.yaml.
resource "hcloud_network_subnet" "segment" {
  for_each = var.subnets

  network_id   = hcloud_network.mgmt.id
  type         = "cloud"
  network_zone = var.network_zone
  ip_range     = each.value
}

resource "hcloud_server" "node" {
  for_each = var.nodes

  name        = each.key
  location    = var.location
  image       = var.image
  server_type = var.server_types[each.value.profile]

  labels = {
    project = "ecommerce-1"
    site    = "mgmt"
    role    = each.value.role
  }
}

# Segment 401 is the provider primary private IP. Canonical K8S/storage/backup
# addresses are reserved as aliases on the same Hetzner Network. Hetzner DHCP
# configures only the primary address; host-side alias reconciliation remains an
# Ansible-owned runtime prerequisite and is not claimed by this Terraform slice.
resource "hcloud_server_network" "node" {
  for_each = var.nodes

  server_id = hcloud_server.node[each.key].id
  subnet_id = hcloud_network_subnet.segment["401"].id
  ip        = each.value.mgmt_ip
  alias_ips = compact([
    each.value.k8s_ip,
    try(each.value.storage_ip, ""),
    try(each.value.backup_ip, ""),
  ])

  # Alias addresses may belong to other canonical segments, so all provider
  # subnets must exist before the attachment is created.
  depends_on = [hcloud_network_subnet.segment]
}

output "network_id" {
  value = hcloud_network.mgmt.id
}

output "servers" {
  value = {
    for name, server in hcloud_server.node :
    name => {
      id   = server.id
      ipv4 = server.ipv4_address
      ipv6 = server.ipv6_address
    }
  }
}

output "private_networks" {
  value = {
    for name, attachment in hcloud_server_network.node :
    name => {
      ip        = attachment.ip
      alias_ips = sort(tolist(attachment.alias_ips))
    }
  }
}
