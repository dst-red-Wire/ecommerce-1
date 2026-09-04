terraform {
  required_version = "= 1.15.5"

  # Retained audit-only contention probe for the known INCOMPATIBLE backend.
  # All common S3 parameters and the bucket are supplied at runtime. This root
  # is never an activation prerequisite for the PostgreSQL management backend.
  backend "s3" {
    key          = "ecommerce/lock-tests/terraform.tfstate"
    use_lockfile = true
  }
}
