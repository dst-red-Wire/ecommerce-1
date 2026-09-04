variable "location" {
  description = "Hetzner location for all management servers."
  type        = string
  default     = "nbg1"

  validation {
    condition     = var.location == "nbg1"
    error_message = "The management plane is fixed to the approved nbg1 location."
  }
}

variable "network_zone" {
  description = "Hetzner private network zone."
  type        = string
  default     = "eu-central"

  validation {
    condition     = var.network_zone == "eu-central"
    error_message = "The nbg1 management network must remain in eu-central."
  }
}

variable "network_cidr" {
  description = "Dedicated management network CIDR."
  type        = string
  default     = "10.30.0.0/16"

  validation {
    condition = (
      can(cidrnetmask(var.network_cidr)) &&
      can(regex("^(10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.)", cidrhost(var.network_cidr, 0))) &&
      can(regex("^(10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.)", cidrhost(var.network_cidr, -1)))
    )
    error_message = "The management network must be a valid IPv4 CIDR fully contained in an RFC1918 range."
  }
}

variable "subnet_cidr" {
  description = "Management server subnet CIDR."
  type        = string
  default     = "10.30.0.0/24"

  validation {
    condition = (
      can(cidrnetmask(var.subnet_cidr)) &&
      can(cidrhost(var.subnet_cidr, 30)) &&
      try(cidrhost(var.subnet_cidr, 30) != cidrhost(var.subnet_cidr, -1), false)
    )
    error_message = "The management subnet must be a valid IPv4 CIDR with usable hosts 10, 20, and 30."
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
  description = "Explicit public CIDRs allowed to reach SSH on public management servers."
  type        = list(string)

  validation {
    condition = (
      length(var.ssh_allowed_cidrs) > 0 &&
      length(var.ssh_allowed_cidrs) == length(distinct(var.ssh_allowed_cidrs)) &&
      alltrue([
        for cidr in var.ssh_allowed_cidrs :
        can(cidrnetmask(cidr)) &&
        try(tonumber(split("/", cidr)[1]) >= 24, false) &&
        try(tonumber(split("/", cidr)[1]) <= 32, false)
      ])
    )
    error_message = "SSH sources must be unique explicit IPv4 CIDRs between /24 and /32; Internet-wide rules are forbidden."
  }
}

variable "gitea_server_type" {
  description = "Hetzner server type for gitea-mgmt."
  type        = string
  default     = "cpx22"

  validation {
    condition     = var.gitea_server_type == "cpx22"
    error_message = "The reviewed integration size for gitea-mgmt is cpx22."
  }
}

variable "harbor_server_type" {
  description = "Hetzner server type for harbor-mgmt."
  type        = string
  default     = "cpx32"

  validation {
    condition     = var.harbor_server_type == "cpx32"
    error_message = "The reviewed integration size for harbor-mgmt is cpx32."
  }
}

variable "data_server_type" {
  description = "Hetzner server type for data-mgmt."
  type        = string
  default     = "cpx32"

  validation {
    condition     = var.data_server_type == "cpx32"
    error_message = "The reviewed integration size for data-mgmt is cpx32."
  }
}

variable "dns_zone" {
  description = "Existing ClouDNS master zone imported into the management state."
  type        = string
  default     = "deployfrance.com"

  validation {
    condition     = var.dns_zone == "deployfrance.com"
    error_message = "This management root is dedicated to deployfrance.com; dns_zone cannot be overridden."
  }
}

variable "git_dns_name" {
  description = "Relative DNS label for the authoritative Gitea endpoint."
  type        = string
  default     = "git"

  validation {
    condition     = var.git_dns_name == "git"
    error_message = "The authoritative Gitea DNS label is fixed to git."
  }
}

variable "registry_dns_name" {
  description = "Relative DNS label for the authoritative Harbor endpoint."
  type        = string
  default     = "registry"

  validation {
    condition     = var.registry_dns_name == "registry"
    error_message = "The authoritative Harbor DNS label is fixed to registry."
  }
}
