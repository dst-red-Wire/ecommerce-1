terraform {
  required_providers {
    hcloud = { source = "hetznercloud/hcloud" }
  }
}

variable "location" {
  type = string
  validation {
    condition     = length(trimspace(var.location)) > 0
    error_message = "location must be explicit."
  }
}
variable "image" {
  type = string
  validation {
    condition     = can(regex("^ubuntu-24\\.04(?:-[a-z0-9.-]+)?$", var.image))
    error_message = "image must identify Ubuntu 24.04."
  }
}
variable "server_type" {
  type = string
  validation {
    condition     = length(trimspace(var.server_type)) > 0
    error_message = "server_type must be explicit."
  }
}
variable "gateway_server_type" {
  type = string
  validation {
    condition     = length(trimspace(var.gateway_server_type)) > 0
    error_message = "gateway_server_type must be explicit."
  }
}
variable "ssh_key_id" {
  type = number
  validation {
    condition     = var.ssh_key_id > 0
    error_message = "ssh_key_id must be positive."
  }
}
variable "ssh_allowed_cidrs" {
  type = list(string)
  validation {
    condition = length(var.ssh_allowed_cidrs) > 0 && alltrue([
      for cidr in var.ssh_allowed_cidrs : can(cidrhost(cidr, 0)) && !endswith(cidr, "/0")
    ])
    error_message = "ssh_allowed_cidrs must contain valid restricted CIDRs."
  }
}
variable "qualification_user" {
  type = string
  validation {
    condition     = can(regex("^[a-z_][a-z0-9_-]{0,30}$", var.qualification_user)) && var.qualification_user != "root"
    error_message = "qualification_user must be a valid non-root Linux account name."
  }
}
variable "gateway_user" {
  type = string
  validation {
    condition     = can(regex("^[a-z_][a-z0-9_-]{0,30}$", var.gateway_user)) && var.gateway_user != "root"
    error_message = "gateway_user must be a valid non-root Linux account name."
  }
}
variable "network_cidr" { type = string }

locals {
  subnet_cidr        = var.network_cidr
  gateway_private_ip = cidrhost(var.network_cidr, 2)
  runner_private_ip  = cidrhost(var.network_cidr, 3)
}

data "hcloud_image" "qualification" {
  name              = var.image
  with_architecture = "x86"
}

data "hcloud_server_type" "runner" {
  name = var.server_type
}

data "hcloud_server_type" "gateway" {
  name = var.gateway_server_type
}

data "hcloud_ssh_key" "qualification" {
  id = var.ssh_key_id
}

data "hcloud_location" "qualification" {
  name = var.location
}

resource "hcloud_network" "qualification" {
  name     = "ecommerce-m1-qualification"
  ip_range = var.network_cidr
}

resource "hcloud_network_subnet" "qualification" {
  network_id   = hcloud_network.qualification.id
  type         = "cloud"
  network_zone = data.hcloud_location.qualification.network_zone
  ip_range     = local.subnet_cidr
}

resource "hcloud_firewall" "runner" {
  name = "ecommerce-m1-qualification-runner"
  rule {
    direction   = "in"
    protocol    = "tcp"
    port        = "22"
    source_ips  = ["${local.gateway_private_ip}/32"]
    description = "SSH through the dedicated qualification bastion only"
  }
  rule {
    direction       = "out"
    protocol        = "tcp"
    port            = "3128"
    destination_ips = ["${local.gateway_private_ip}/32"]
    description     = "Proxy-only application egress"
  }
}

resource "hcloud_firewall" "gateway" {
  name = "ecommerce-m1-qualification-gateway"
  rule {
    direction   = "in"
    protocol    = "tcp"
    port        = "22"
    source_ips  = var.ssh_allowed_cidrs
    description = "SSH from explicitly trusted qualification controllers only"
  }
  rule {
    direction   = "in"
    protocol    = "tcp"
    port        = "3128"
    source_ips  = ["${local.runner_private_ip}/32"]
    description = "Squid from the isolated runner only"
  }
  rule {
    direction       = "out"
    protocol        = "tcp"
    port            = "22"
    destination_ips = ["${local.runner_private_ip}/32"]
    description     = "Bastion SSH to the isolated runner"
  }
  rule {
    direction       = "out"
    protocol        = "tcp"
    port            = "80"
    destination_ips = ["0.0.0.0/0", "::/0"]
    description     = "Gateway package and permitted proxy HTTP"
  }
  rule {
    direction       = "out"
    protocol        = "tcp"
    port            = "443"
    destination_ips = ["0.0.0.0/0", "::/0"]
    description     = "Gateway package and permitted proxy HTTPS"
  }
  rule {
    direction       = "out"
    protocol        = "udp"
    port            = "53"
    destination_ips = ["0.0.0.0/0", "::/0"]
    description     = "Gateway-owned DNS resolution"
  }
  rule {
    direction       = "out"
    protocol        = "tcp"
    port            = "53"
    destination_ips = ["0.0.0.0/0", "::/0"]
    description     = "Gateway-owned DNS fallback"
  }
}

resource "hcloud_server" "gateway" {
  name         = "ecommerce-m1-qualification-gateway"
  location     = var.location
  image        = data.hcloud_image.qualification.id
  server_type  = data.hcloud_server_type.gateway.id
  ssh_keys     = [data.hcloud_ssh_key.qualification.id]
  firewall_ids = [hcloud_firewall.gateway.id]
  user_data = templatefile("${path.module}/gateway-cloud-init.yaml.tftpl", {
    gateway_user   = var.gateway_user
    ssh_public_key = data.hcloud_ssh_key.qualification.public_key
  })
  public_net {
    ipv4_enabled = true
    ipv6_enabled = false
  }
  labels = { project = "ecommerce-1", lifecycle = "single-use-qualification", role = "egress-gateway-bastion" }
}

resource "hcloud_server_network" "gateway" {
  server_id  = hcloud_server.gateway.id
  network_id = hcloud_network.qualification.id
  ip         = local.gateway_private_ip
  depends_on = [hcloud_network_subnet.qualification]
}

resource "hcloud_server" "runner" {
  name         = "ecommerce-m1-qualification-runner"
  location     = var.location
  image        = data.hcloud_image.qualification.id
  server_type  = data.hcloud_server_type.runner.id
  ssh_keys     = [data.hcloud_ssh_key.qualification.id]
  firewall_ids = [hcloud_firewall.runner.id]
  user_data = templatefile("${path.module}/cloud-init.yaml.tftpl", {
    qualification_user = var.qualification_user
    ssh_public_key     = data.hcloud_ssh_key.qualification.public_key
  })
  public_net {
    ipv4_enabled = false
    ipv6_enabled = false
  }
  labels = { project = "ecommerce-1", lifecycle = "single-use-qualification", role = "runner" }
  lifecycle {
    precondition {
      condition     = data.hcloud_image.qualification.os_flavor == "ubuntu" && startswith(data.hcloud_image.qualification.os_version, "24.04") && data.hcloud_image.qualification.architecture == "x86"
      error_message = "The resolved qualification image must be Ubuntu 24.04 x86_64."
    }
    precondition {
      condition     = data.hcloud_server_type.runner.architecture == "x86" && data.hcloud_server_type.gateway.architecture == "x86"
      error_message = "Both qualification server types must resolve to x86_64."
    }
  }
}

resource "hcloud_server_network" "runner" {
  server_id  = hcloud_server.runner.id
  network_id = hcloud_network.qualification.id
  ip         = local.runner_private_ip
  depends_on = [hcloud_network_subnet.qualification]
}

output "server_id" {
  value = hcloud_server.runner.id
}
output "runner_private_ip" {
  value = local.runner_private_ip
}
output "gateway_ipv4" {
  value = hcloud_server.gateway.ipv4_address
}
output "gateway_private_ip" {
  value = local.gateway_private_ip
}
output "user" {
  value = var.qualification_user
}
output "gateway_user" {
  value = var.gateway_user
}
output "network_zone" {
  value = data.hcloud_location.qualification.network_zone
}
output "image_identity" {
  value = { id = data.hcloud_image.qualification.id, name = data.hcloud_image.qualification.name, os_flavor = data.hcloud_image.qualification.os_flavor, os_version = data.hcloud_image.qualification.os_version, architecture = data.hcloud_image.qualification.architecture }
}
