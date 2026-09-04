terraform {
  # Partial configuration only. Bucket, region, endpoint, and credentials are
  # deliberately supplied out of band after the backend decision is approved.
  backend "s3" {}
}
