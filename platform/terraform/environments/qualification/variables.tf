variable "hcloud_location" {
  description = "Explicit location for the temporary qualification VM."
  type        = string
  validation {
    condition     = length(trimspace(var.hcloud_location)) > 0
    error_message = "hcloud_location must be explicitly supplied."
  }
}

variable "qualification_image" {
  description = "Hetzner public Ubuntu 24.04 image name (normally ubuntu-24.04); its resolved ID is output as evidence."
  type        = string
  validation {
    condition     = can(regex("^ubuntu-24\\.04(?:-[a-z0-9.-]+)?$", var.qualification_image))
    error_message = "qualification_image must identify Ubuntu 24.04."
  }
}

variable "qualification_server_type" {
  description = "Explicit x86 server type. Select enough CPU/RAM for Docker, PostgreSQL Testcontainers, Go race tests, and make ci."
  type        = string
  validation {
    condition     = length(trimspace(var.qualification_server_type)) > 0
    error_message = "qualification_server_type must be explicitly supplied."
  }
}

variable "qualification_ssh_key_id" {
  description = "Existing Hetzner provider-side SSH public key ID."
  type        = number
  validation {
    condition     = var.qualification_ssh_key_id > 0
    error_message = "qualification_ssh_key_id must be positive."
  }
}

variable "qualification_ssh_allowed_cidrs" {
  description = "Required trusted-controller CIDRs; unrestricted IPv4/IPv6 SSH is rejected."
  type        = list(string)
  validation {
    condition = length(var.qualification_ssh_allowed_cidrs) > 0 && alltrue([
      for cidr in var.qualification_ssh_allowed_cidrs : can(cidrhost(cidr, 0)) && !endswith(cidr, "/0")
    ])
    error_message = "qualification_ssh_allowed_cidrs must be non-empty, valid, and restricted."
  }
}

variable "qualification_user" {
  description = "Pre-Ansible regular non-root account."
  type        = string
  default     = "ubuntu"
  validation {
    condition     = can(regex("^[a-z_][a-z0-9_-]{0,30}$", var.qualification_user)) && var.qualification_user != "root"
    error_message = "qualification_user must be a valid non-root Linux account name."
  }
}
