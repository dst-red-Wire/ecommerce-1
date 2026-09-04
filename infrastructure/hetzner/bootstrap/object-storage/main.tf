resource "minio_s3_bucket" "terraform_state" {
  bucket        = var.bucket_name
  acl           = "private"
  force_destroy = false

  lifecycle {
    prevent_destroy = true
  }
}

resource "minio_s3_bucket_versioning" "terraform_state" {
  bucket = minio_s3_bucket.terraform_state.bucket

  versioning_configuration {
    status            = "Enabled"
    excluded_prefixes = []
  }

  lifecycle {
    prevent_destroy = true
  }
}

# Hetzner credentials are project-wide by default. This explicit principal is
# allowlisted only for encrypted backup/evidence archives, authenticated reads
# of any legacy management object, and the retained S3 locking diagnostic. It
# is never used as the authoritative management Terraform backend credential.
resource "minio_s3_bucket_policy" "terraform_state" {
  bucket = minio_s3_bucket.terraform_state.bucket
  policy = templatefile("${path.module}/management-bucket-policy.json.tftpl", {
    bucket_name          = var.bucket_name
    management_principal = var.management_principal_arn
  })

  depends_on = [minio_s3_bucket_versioning.terraform_state]

  lifecycle {
    prevent_destroy = true
  }
}
