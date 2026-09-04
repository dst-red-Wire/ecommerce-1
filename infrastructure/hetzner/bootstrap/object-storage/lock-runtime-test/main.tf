# This built-in resource gives the lock harness a non-trivial apply plan. The
# harness pauses at confirmation, positively reads the live S3 .tflock object,
# and always answers `no`; no provider-managed resource is ever created.
resource "terraform_data" "lock_probe" {
  input = "terraform-1.15.5-hetzner-s3-lock-contention"
}
