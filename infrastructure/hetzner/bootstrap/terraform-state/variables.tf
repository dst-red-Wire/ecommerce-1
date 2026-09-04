variable "location" {
  description = "Hetzner location for the independent Terraform state service."
  type        = string
  default     = "nbg1"

  validation {
    condition     = var.location == "nbg1"
    error_message = "The Terraform state service is fixed to the reviewed nbg1 location."
  }
}

variable "server_type" {
  description = "Small x86 Hetzner server type reviewed for the low-volume PostgreSQL backend."
  type        = string
  default     = "cx23"

  validation {
    condition     = var.server_type == "cx23"
    error_message = "The reviewed bootstrap size is cx23 (2 vCPU, 4 GB RAM, 40 GB disk)."
  }
}

variable "image" {
  description = "Pinned operating system image for terraform-state-mgmt."
  type        = string
  default     = "ubuntu-24.04"

  validation {
    condition     = var.image == "ubuntu-24.04"
    error_message = "terraform-state-mgmt requires the reviewed Ubuntu 24.04 image."
  }
}

variable "ssh_key_name" {
  description = "Name of an existing Hetzner SSH key."
  type        = string

  validation {
    condition     = length(trimspace(var.ssh_key_name)) > 0
    error_message = "An existing Hetzner SSH key name is required."
  }
}

variable "ssh_allowed_cidrs" {
  description = "Explicit public IPv4 CIDRs allowed to reach SSH for administration and PostgreSQL tunnelling."
  type        = list(string)

  validation {
    condition = (
      length(var.ssh_allowed_cidrs) > 0 &&
      length(var.ssh_allowed_cidrs) == length(distinct(var.ssh_allowed_cidrs)) &&
      alltrue([
        for cidr in var.ssh_allowed_cidrs :
        can(cidrnetmask(cidr)) &&
        try(tonumber(split("/", cidr)[1]) >= 24, false) &&
        try(tonumber(split("/", cidr)[1]) <= 32, false) &&
        cidr != "0.0.0.0/0"
      ])
    )
    error_message = "SSH sources must be unique explicit IPv4 CIDRs between /24 and /32; Internet-wide access is forbidden."
  }
}

variable "postgresql_volume_size_gb" {
  description = "Minimum Hetzner Volume size for PostgreSQL data; expansion is possible but shrinking is not."
  type        = number
  default     = 10

  validation {
    condition     = var.postgresql_volume_size_gb == 10
    error_message = "The reviewed bootstrap volume size is the Hetzner minimum of 10 GB."
  }
}
