variable "iso_url" {
  type = string
}

variable "iso_checksum" {
  type      = string
  sensitive = true
}

variable "build_ssh_public_key" {
  type      = string
  sensitive = true

  validation {
    condition     = can(regex("^ssh-(ed25519|rsa) [A-Za-z0-9+/]+={0,3}(?: [A-Za-z0-9._@-]+)?$", trimspace(var.build_ssh_public_key)))
    error_message = "The build SSH public key must contain one OpenSSH public key."
  }
}

variable "build_ssh_private_key_file" {
  type      = string
  sensitive = true

  validation {
    condition     = length(trimspace(var.build_ssh_private_key_file)) > 0
    error_message = "The build SSH private key file must reference the runtime-injected private key."
  }
}

variable "offline_bundle_dir" {
  type = string
}

variable "artifact_dir" {
  type = string

  validation {
    condition     = length(trimspace(var.artifact_dir)) > 3
    error_message = "Artifact_dir must reference a host-local build staging directory."
  }
}

variable "vm_cpus" {
  type = number

  validation {
    condition     = var.vm_cpus >= 1 && var.vm_cpus <= 64
    error_message = "Vm_cpus must be between 1 and 64."
  }
}

variable "vm_memory_mib" {
  type = number

  validation {
    condition     = var.vm_memory_mib >= 2048 && var.vm_memory_mib <= 262144
    error_message = "Vm_memory_mib must be between 2048 and 262144."
  }
}

variable "vm_disk_mib" {
  type = number

  validation {
    condition     = var.vm_disk_mib >= 16384 && var.vm_disk_mib <= 1048576
    error_message = "Vm_disk_mib must be between 16384 and 1048576."
  }
}

variable "vm_firmware" {
  type = string

  validation {
    condition     = var.vm_firmware == "bios"
    error_message = "Vm_firmware must be bios."
  }
}

variable "vm_partition_table" {
  type = string

  validation {
    condition     = var.vm_partition_table == "gpt"
    error_message = "Vm_partition_table must be gpt."
  }
}

variable "vm_bios_boot_mib" {
  type = number

  validation {
    condition     = var.vm_bios_boot_mib >= 1 && var.vm_bios_boot_mib <= 16
    error_message = "Vm_bios_boot_mib must be between 1 and 16."
  }
}

variable "vm_boot_mib" {
  type = number

  validation {
    condition     = var.vm_boot_mib >= 2048 && var.vm_boot_mib <= 16384
    error_message = "Vm_boot_mib must be between 2048 and 16384."
  }
}

variable "vm_root_min_mib" {
  type = number

  validation {
    condition     = var.vm_root_min_mib >= 10240 && var.vm_root_min_mib <= 1048576
    error_message = "Vm_root_min_mib must be between 10240 and 1048576."
  }
}

variable "vm_root_filesystem" {
  type = string

  validation {
    condition     = var.vm_root_filesystem == "xfs"
    error_message = "Vm_root_filesystem must be xfs."
  }
}

variable "vm_ssh_timeout_seconds" {
  type = number

  validation {
    condition     = var.vm_ssh_timeout_seconds >= 1800 && var.vm_ssh_timeout_seconds <= 7200
    error_message = "Vm_ssh_timeout_seconds must be between 1800 and 7200."
  }
}

variable "image_profile" {
  type    = string
  default = "rke2"

  validation {
    condition     = contains(["rke2", "admin-qualification"], var.image_profile)
    error_message = "Image_profile must be rke2 or admin-qualification."
  }
}
