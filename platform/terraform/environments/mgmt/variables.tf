variable "hcloud_location" {
  description = "Hetzner Cloud location for persistent MGMT nodes."
  type        = string
}

variable "hcloud_network_zone" {
  description = "Hetzner Cloud network zone matching hcloud_location; runtime input, never guessed from repository state."
  type        = string

  validation {
    condition     = length(trimspace(var.hcloud_network_zone)) > 0
    error_message = "hcloud_network_zone must be an explicit non-empty value such as the provider-reported network zone."
  }
}

variable "hcloud_image" {
  description = "Pinned Rocky Linux 10.2 Packer image identifier/name."
  type        = string
}

variable "hcloud_server_types" {
  description = "Mapping from canonical vm_profile names to exact Hetzner Cloud server types."
  type        = map(string)

  validation {
    condition = alltrue([
      for profile in keys(local.vm_profiles) :
      contains(keys(var.hcloud_server_types), profile)
    ])
    error_message = "Every canonical MGMT vm_profile must have an explicit Hetzner server type mapping."
  }
}

variable "hcloud_access_server_types" {
  description = "Explicit provider mapping for canonical access-gateway profiles."
  type        = map(string)

  validation {
    condition = alltrue([
      for profile in keys(local.access_profiles) :
      contains(keys(var.hcloud_access_server_types), profile)
    ])
    error_message = "Every access-gateway profile requires an explicit reviewed server type mapping."
  }
}

variable "bootstrap_ssh_enabled" {
  description = "Human-gated temporary public SSH ingress for wg-01 bootstrap only; disable after WireGuard proof."
  type        = bool
  default     = false
}

variable "bootstrap_ssh_allowed_cidrs" {
  description = "Explicit operator-approved source CIDRs for temporary wg-01 bootstrap SSH. Never inferred."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for cidr in var.bootstrap_ssh_allowed_cidrs :
      can(cidrhost(cidr, 0)) && try(tonumber(split("/", cidr)[1]) > 0, false)
    ])
    error_message = "bootstrap SSH CIDRs must be valid and must not grant globally permissive IPv4 or IPv6 access."
  }
}

variable "bootstrap_ssh_human_gate_confirmed" {
  description = "Ephemeral human authorization marker required whenever temporary wg-01 public SSH is enabled."
  type        = bool
  default     = false
}

variable "wireguard_udp_enabled" {
  description = "Human-gated activation of the steady public WireGuard UDP endpoint."
  type        = bool
  default     = false
}

variable "wireguard_udp_human_gate_confirmed" {
  description = "Ephemeral human authorization marker required when public WireGuard UDP is activated."
  type        = bool
  default     = false
}

variable "hcloud_ssh_key_ids" {
  description = "Explicit existing Hetzner SSH public-key IDs authorized for bootstrap access to the gateway and private nodes. No private key enters Terraform."
  type        = list(number)

  validation {
    condition = length(var.hcloud_ssh_key_ids) > 0 && alltrue([
      for key_id in var.hcloud_ssh_key_ids : key_id > 0 && floor(key_id) == key_id
    ])
    error_message = "At least one existing positive integer provider SSH public-key ID is required."
  }
}
