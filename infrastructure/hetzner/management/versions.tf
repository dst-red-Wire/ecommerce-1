terraform {
  required_version = "= 1.15.5"

  required_providers {
    hcloud = {
      source  = "hetznercloud/hcloud"
      version = "~> 1.68.0"
    }

    cloudns = {
      source  = "ClouDNS/cloudns"
      version = "1.1.0"
    }
  }
}

# Both providers read credentials from their documented environment variables.
# No credential is accepted as a Terraform variable or persisted in this root.
provider "hcloud" {}
provider "cloudns" {}
