variable "cluster_name" {
  description = "Name prefix for ephemeral preproduction resources."
  type        = string
  default     = "ecommerce-preproduction"
}

variable "location" {
  description = "Hetzner location for all preproduction resources."
  type        = string
  default     = "nbg1"
}

variable "network_zone" {
  description = "Hetzner private network zone."
  type        = string
  default     = "eu-central"
}

variable "network_cidr" {
  description = "Private cluster network CIDR."
  type        = string
  default     = "10.40.0.0/16"
}

variable "subnet_cidr" {
  description = "Private node subnet CIDR."
  type        = string
  default     = "10.40.0.0/24"
}

variable "ssh_key_name" {
  description = "Existing Hetzner SSH key name; this stack does not duplicate it."
  type        = string
}

variable "ssh_allowed_cidrs" {
  description = "Explicit CIDRs allowed to reach SSH. Supply out of band."
  type        = list(string)

  validation {
    condition     = length(var.ssh_allowed_cidrs) > 0
    error_message = "At least one explicit SSH source CIDR is required."
  }
}

variable "api_server_dns_name" {
  description = "DNS name included in kubeadm API SANs and resolved to the private load balancer IP."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$", var.api_server_dns_name))
    error_message = "The API server DNS name must be lowercase and syntactically valid."
  }
}

variable "owner" {
  description = "Named owner accountable for the ephemeral campaign and cost."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{1,62}$", var.owner))
    error_message = "Owner must be a lowercase label-safe identifier."
  }
}

variable "campaign_id" {
  description = "Unique, label-safe validation campaign identifier."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{2,62}$", var.campaign_id))
    error_message = "Campaign ID must be a lowercase label-safe identifier."
  }
}

variable "expires_at" {
  description = "RFC3339 campaign expiration. It is an operational guard, not an automatic destroy trigger."
  type        = string

  validation {
    condition     = can(formatdate("YYYY-MM-DD'T'hh:mm:ssZ", var.expires_at))
    error_message = "Expiration must be a valid RFC3339 timestamp."
  }

  validation {
    condition     = timecmp(var.expires_at, timestamp()) > 0
    error_message = "Expiration must be in the future when a campaign is planned."
  }
}

variable "cost_center" {
  description = "Cost attribution identifier required before planning infrastructure."
  type        = string

  validation {
    condition     = length(trimspace(var.cost_center)) > 0
    error_message = "A cost center is required."
  }
}

variable "control_plane_count" {
  description = "Odd number of kubeadm control-plane nodes with stacked etcd."
  type        = number
  default     = 3

  validation {
    condition     = var.control_plane_count >= 3 && var.control_plane_count % 2 == 1
    error_message = "The control-plane count must be odd and at least three."
  }
}

variable "worker_count" {
  description = "Number of real worker VMs."
  type        = number
  default     = 2

  validation {
    condition     = var.worker_count >= 2
    error_message = "Preproduction requires at least two workers."
  }
}

variable "control_plane_server_type" {
  description = "Dedicated-vCPU server type for control-plane nodes."
  type        = string
  default     = "ccx23"
}

variable "worker_server_type" {
  description = "Dedicated-vCPU server type for worker nodes."
  type        = string
  default     = "ccx23"
}
