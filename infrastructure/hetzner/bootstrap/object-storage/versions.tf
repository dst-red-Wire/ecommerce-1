terraform {
  required_version = "= 1.15.5"

  required_providers {
    minio = {
      source  = "aminueza/minio"
      version = "3.38.5"
    }
  }
}

locals {
  object_storage_endpoint = "nbg1.your-objectstorage.com"
  object_storage_region   = "nbg1"
}

# Credentials are deliberately omitted. The provider reads MINIO_USER and
# MINIO_PASSWORD from the process environment.
provider "minio" {
  minio_server   = local.object_storage_endpoint
  minio_region   = local.object_storage_region
  minio_ssl      = true
  s3_compat_mode = true

  request_timeout_seconds = 30
  max_retries             = 4
  retry_delay_ms          = 1000
}
