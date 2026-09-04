# This data source is disabled during bootstrap. The privacy gate enables it in
# a read-only refresh plan after the bucket exists. Reading through a data
# source avoids relying on the managed bucket resource's refresh behaviour.
locals {
  runtime_expected_bucket_policy = jsondecode(templatefile(
    "${path.module}/management-bucket-policy.json.tftpl",
    {
      bucket_name          = var.bucket_name
      management_principal = var.management_principal_arn
    },
  ))
}

data "minio_s3_bucket" "runtime_privacy_gate" {
  count  = var.runtime_privacy_gate ? 1 : 0
  bucket = var.bucket_name

  lifecycle {
    postcondition {
      condition     = self.versioning_enabled
      error_message = "Privacy gate failed: bucket versioning is not enabled."
    }

    # Fail closed on every wildcard Principal, including a custom policy that
    # the provider cannot classify as a canned public policy. The approved
    # archive policy uses only explicit Hetzner principal ARNs.
    postcondition {
      condition = (
        try(trimspace(self.policy), "") == "" ||
        !can(regex("(?s)\\\"Principal\\\"[[:space:]]*:[[:space:]]*\\\"\\*\\\"", self.policy)) &&
        !can(regex("(?s)\\\"Principal\\\"[[:space:]]*:[[:space:]]*\\{[^}]*\\\"\\*\\\"", self.policy))
      )
      error_message = "Privacy gate failed: the live bucket policy contains a wildcard Principal."
    }

    postcondition {
      condition = (
        try(jsonencode(jsondecode(self.policy)) == jsonencode(local.runtime_expected_bucket_policy), false)
      )
      error_message = "Privacy gate failed: the live bucket policy does not exactly match the archive principal and reviewed legacy/probe/backup objects."
    }
  }
}
