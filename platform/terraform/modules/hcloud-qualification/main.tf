terraform {
  required_providers {
    hcloud = {
      source = "hetznercloud/hcloud"
    }
  }
}

variable "location" {
  description = "Explicit Hetzner Cloud location for the isolated qualification host."
  type        = string

  validation {
    condition     = length(trimspace(var.location)) > 0
    error_message = "location must be an explicit non-empty Hetzner Cloud location."
  }
}

variable "image" {
  description = "Provider image name for Ubuntu 24.04; resolved provider identity is exported."
  type        = string

  validation {
    condition     = can(regex("^ubuntu-24\\.04(?:-[a-z0-9.-]+)?$", var.image))
    error_message = "image must identify an Ubuntu 24.04 provider image (for example ubuntu-24.04)."
  }
}

variable "server_type" {
  description = "Explicit x86 Hetzner Cloud server type sized for Docker, Testcontainers, race tests, and make ci."
  type        = string

  validation {
    condition     = length(trimspace(var.server_type)) > 0
    error_message = "server_type must be explicitly supplied."
  }
}

variable "ssh_key_id" {
  description = "Existing Hetzner provider-side SSH public key ID; Terraform never owns private key material."
  type        = number

  validation {
    condition     = var.ssh_key_id > 0
    error_message = "ssh_key_id must be a positive provider-side public key ID."
  }
}

variable "ssh_allowed_cidrs" {
  description = "Non-empty trusted-controller CIDRs permitted to reach SSH."
  type        = list(string)

  validation {
    condition = (
      length(var.ssh_allowed_cidrs) > 0 &&
      alltrue([
        for cidr in var.ssh_allowed_cidrs : can(cidrhost(cidr, 0)) && !endswith(cidr, "/0")
      ])
    )
    error_message = "ssh_allowed_cidrs must contain valid trusted CIDRs and must not contain an IPv4 or IPv6 zero-prefix network."
  }
}

variable "qualification_user" {
  description = "Regular non-root account created before the canonical Ansible runner executes."
  type        = string

  validation {
    condition     = can(regex("^[a-z_][a-z0-9_-]{0,30}$", var.qualification_user)) && var.qualification_user != "root"
    error_message = "qualification_user must be a valid non-root Linux account name."
  }
}

data "hcloud_image" "qualification" {
  name              = var.image
  with_architecture = "x86"
}

data "hcloud_server_type" "qualification" {
  name = var.server_type
}

data "hcloud_ssh_key" "qualification" {
  id = var.ssh_key_id
}

resource "hcloud_firewall" "qualification" {
  name = "ecommerce-m1-qualification"

  rule {
    direction   = "in"
    protocol    = "tcp"
    port        = "22"
    source_ips  = var.ssh_allowed_cidrs
    description = "SSH from explicitly trusted qualification controllers only"
  }

  # No outbound rules are declared: Hetzner's firewall preserves outbound
  # access needed for public packages, source, and containers. It cannot enforce
  # domain-level egress policy. No private network is attached to this host.
}

resource "hcloud_server" "qualification" {
  name         = "ecommerce-m1-qualification"
  location     = var.location
  image        = data.hcloud_image.qualification.id
  server_type  = data.hcloud_server_type.qualification.id
  ssh_keys     = [data.hcloud_ssh_key.qualification.id]
  firewall_ids = [hcloud_firewall.qualification.id]

  user_data = templatefile("${path.module}/cloud-init.yaml.tftpl", {
    qualification_user = var.qualification_user
    ssh_public_key     = data.hcloud_ssh_key.qualification.public_key
  })

  labels = {
    project   = "ecommerce-1"
    lifecycle = "single-use-qualification"
    milestone = "m1"
  }

  public_net {
    ipv4_enabled = true
    ipv6_enabled = false
  }

  lifecycle {
    precondition {
      condition     = data.hcloud_image.qualification.os_flavor == "ubuntu" && startswith(data.hcloud_image.qualification.os_version, "24.04") && data.hcloud_image.qualification.architecture == "x86"
      error_message = "The resolved qualification image must be Ubuntu 24.04 x86_64."
    }

    precondition {
      condition     = data.hcloud_server_type.qualification.architecture == "x86"
      error_message = "qualification_server_type must resolve to an x86_64 server type."
    }
  }
}

output "server_id" {
  value = hcloud_server.qualification.id
}

output "ipv4" {
  value = hcloud_server.qualification.ipv4_address
}

output "user" {
  value = var.qualification_user
}

output "image_identity" {
  description = "Provider-resolved image identity retained as qualification evidence."
  value = {
    id           = data.hcloud_image.qualification.id
    name         = data.hcloud_image.qualification.name
    os_flavor    = data.hcloud_image.qualification.os_flavor
    os_version   = data.hcloud_image.qualification.os_version
    architecture = data.hcloud_image.qualification.architecture
  }
}
