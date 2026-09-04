variable "bucket_name" {
  description = "Preserved private Hetzner bucket used only for encrypted backups, evidence archives and the retained S3 lock diagnostic."
  type        = string

  validation {
    condition = (
      length(var.bucket_name) >= 3 &&
      length(var.bucket_name) <= 63 &&
      can(regex("^[a-z0-9][a-z0-9-]*[a-z0-9]$", var.bucket_name))
    )
    error_message = "bucket_name must contain 3-63 lowercase letters, digits, or hyphens, and must start and end with a letter or digit."
  }
}

variable "runtime_privacy_gate" {
  description = "Read the live bucket policy and versioning status during the explicitly authorized privacy gate."
  type        = bool
  default     = false
}

variable "management_principal_arn" {
  description = "Hetzner S3 principal ARN allowlisted for encrypted archives and the retained lock diagnostic; it is not a Terraform backend credential."
  type        = string
  sensitive   = true

  validation {
    condition     = can(regex("^arn:aws:iam:::user/p[0-9]+:[A-Za-z0-9]+$", var.management_principal_arn))
    error_message = "management_principal_arn must be a single Hetzner Object Storage principal ARN."
  }
}
