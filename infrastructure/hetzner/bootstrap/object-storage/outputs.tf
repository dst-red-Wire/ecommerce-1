output "bucket_name" {
  description = "Name of the preserved private backup and evidence archive bucket."
  value       = minio_s3_bucket.terraform_state.bucket
}

output "s3_endpoint" {
  description = "HTTPS S3 endpoint to use in downstream backend configurations."
  value       = "https://${local.object_storage_endpoint}"
}

output "region" {
  description = "Hetzner Object Storage location and SigV4 signing region."
  value       = local.object_storage_region
}

output "legacy_management_state_key" {
  description = "Read-only legacy key retained for the future state-source inspection gate."
  value       = "ecommerce/management/terraform.tfstate"
}

output "postgresql_backup_prefix" {
  description = "Archive prefix for encrypted PostgreSQL backend dumps."
  value       = "ecommerce/backups/postgresql/"
}

output "bootstrap_state_backup_prefix" {
  description = "Archive prefix for encrypted terraform-state bootstrap state backups."
  value       = "ecommerce/backups/bootstrap-terraform-state/"
}

output "archive_bucket_policy_managed" {
  description = "Confirms that the backup/archive bucket policy is part of the bootstrap state."
  value       = minio_s3_bucket_policy.terraform_state.id != ""
}
