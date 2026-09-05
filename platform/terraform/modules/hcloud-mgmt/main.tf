terraform {
  required_providers {
    hcloud = {
      source = "hetznercloud/hcloud"
    }
  }
}

variable "nodes" {
  type = map(object({
    role    = string
    profile = string
    mgmt_ip = string
    k8s_ip  = string
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
