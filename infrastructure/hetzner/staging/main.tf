terraform {
  required_version = ">= 1.6.0"

  required_providers {
    hcloud = {
      source  = "hetznercloud/hcloud"
      version = "~> 1.68.0"
    }
  }
}

provider "hcloud" {}

resource "hcloud_ssh_key" "dev" {
  name       = "ecommerce-staging-dev"
  public_key = file(pathexpand("~/.ssh/id_ed25519.pub"))
}

resource "hcloud_firewall" "staging" {
  name = "ecommerce-staging"

  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "22"
    source_ips = ["45.140.208.62/32"]
  }

  rule {
    direction  = "in"
    protocol   = "icmp"
    source_ips = ["0.0.0.0/0", "::/0"]
  }
}

resource "hcloud_server" "staging" {
  name        = "ecommerce-staging"
  server_type = "ccx33"
  image       = "ubuntu-24.04"
  location    = "nbg1"

  ssh_keys     = [hcloud_ssh_key.dev.id]
  firewall_ids = [hcloud_firewall.staging.id]

  labels = {
    environment = "staging"
    managed_by  = "terraform"
    project     = "ecommerce"
  }
}

output "server_ipv4" {
  value = hcloud_server.staging.ipv4_address
}

output "server_ipv6" {
  value = hcloud_server.staging.ipv6_address
}
