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

variable "qualification_gateway_server_type" {
  description = "Explicit x86 server type for the dedicated Squid/bastion gateway."
  type        = string
  validation {
    condition     = length(trimspace(var.qualification_gateway_server_type)) > 0
    error_message = "qualification_gateway_server_type must be explicitly supplied."
  }
}

variable "qualification_network_cidr" {
  description = "Dedicated RFC1918 qualification network; the operator must avoid all other internal ranges."
  type        = string
  default     = "10.248.0.0/24"
  validation {
    condition     = can(cidrhost(var.qualification_network_cidr, 0)) && startswith(var.qualification_network_cidr, "10.248.")
    error_message = "qualification_network_cidr must use the reserved qualification-only 10.248.0.0/16 range."
  }
}

variable "qualification_subnet_cidr" {
  description = "Cloud subnet contained by the dedicated qualification network."
  type        = string
  default     = "10.248.0.0/24"
  validation {
    condition     = can(cidrhost(var.qualification_subnet_cidr, 0)) && startswith(var.qualification_subnet_cidr, "10.248.")
    error_message = "qualification_subnet_cidr must use the reserved qualification-only 10.248.0.0/16 range."
  }
}

variable "qualification_gateway_private_ip" {
  type    = string
  default = "10.248.0.2"
  validation {
    condition     = can(cidrhost("${var.qualification_gateway_private_ip}/32", 0)) && startswith(var.qualification_gateway_private_ip, "10.248.")
    error_message = "qualification_gateway_private_ip must be in the qualification-only range."
  }
}

variable "qualification_runner_private_ip" {
  type    = string
  default = "10.248.0.3"
  validation {
    condition     = can(cidrhost("${var.qualification_runner_private_ip}/32", 0)) && startswith(var.qualification_runner_private_ip, "10.248.")
    error_message = "qualification_runner_private_ip must be in the qualification-only range."
  }
}

variable "qualification_ubuntu_snapshot" {
  description = "Immutable Ubuntu snapshot shared with canonical #78 package provenance."
  type        = string
  default     = "20250601T000000Z"
  validation {
    condition     = can(regex("^[0-9]{8}T[0-9]{6}Z$", var.qualification_ubuntu_snapshot))
    error_message = "qualification_ubuntu_snapshot must be an immutable timestamp."
  }
}

variable "qualification_squid_version" {
  description = "Exact Squid package version available in the immutable Ubuntu snapshot."
  type        = string
  default     = "6.6-1ubuntu3.2"
  validation {
    condition     = can(regex("^[0-9][0-9A-Za-z.+:~-]+$", var.qualification_squid_version))
    error_message = "qualification_squid_version must be exact."
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
