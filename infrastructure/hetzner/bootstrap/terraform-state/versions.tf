terraform {
  required_version = "= 1.15.5"

  required_providers {
    hcloud = {
      source  = "hetznercloud/hcloud"
      version = "~> 1.68.0"
    }
  }
}

# HCLOUD_TOKEN is read only from the runtime environment. This bootstrap root
# accepts no credential as an input variable.
provider "hcloud" {}
