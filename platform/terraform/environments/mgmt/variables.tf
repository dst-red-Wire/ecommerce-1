variable "hcloud_location" {
  description = "Hetzner Cloud location for persistent MGMT nodes."
  type        = string
}

variable "hcloud_image" {
  description = "Pinned Rocky Linux 9 image identifier/name."
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
