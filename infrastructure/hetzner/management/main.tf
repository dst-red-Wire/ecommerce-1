data "hcloud_ssh_key" "management" {
  name = var.ssh_key_name
}

locals {
  common_labels = {
    environment = "integration"
    managed_by  = "terraform"
    plane       = "management"
    project     = "ecommerce"
  }

  private_ips = {
    gitea  = cidrhost(var.subnet_cidr, 10)
    harbor = cidrhost(var.subnet_cidr, 20)
    data   = cidrhost(var.subnet_cidr, 30)
  }

  public_source_cidrs = ["0.0.0.0/0", "::/0"]

  network_first_octets = [for octet in split(".", cidrhost(var.network_cidr, 0)) : tonumber(octet)]
  network_last_octets  = [for octet in split(".", cidrhost(var.network_cidr, -1)) : tonumber(octet)]
  subnet_first_octets  = [for octet in split(".", cidrhost(var.subnet_cidr, 0)) : tonumber(octet)]
  subnet_last_octets   = [for octet in split(".", cidrhost(var.subnet_cidr, -1)) : tonumber(octet)]

  network_first_number = sum([for index, octet in local.network_first_octets : octet * pow(256, 3 - index)])
  network_last_number  = sum([for index, octet in local.network_last_octets : octet * pow(256, 3 - index)])
  subnet_first_number  = sum([for index, octet in local.subnet_first_octets : octet * pow(256, 3 - index)])
  subnet_last_number   = sum([for index, octet in local.subnet_last_octets : octet * pow(256, 3 - index)])
}

resource "hcloud_network" "management" {
  name              = "ecommerce-management"
  ip_range          = var.network_cidr
  delete_protection = true

  labels = local.common_labels

  lifecycle {
    prevent_destroy = true
  }
}

resource "hcloud_network_subnet" "management" {
  network_id   = hcloud_network.management.id
  type         = "cloud"
  network_zone = var.network_zone
  ip_range     = var.subnet_cidr

  lifecycle {
    precondition {
      condition = (
        local.subnet_first_number >= local.network_first_number &&
        local.subnet_last_number <= local.network_last_number
      )
      error_message = "The management subnet must be fully contained in the management network."
    }
  }
}

resource "hcloud_firewall" "gitea" {
  name = "gitea-mgmt"

  rule {
    direction   = "in"
    protocol    = "tcp"
    port        = "22"
    source_ips  = var.ssh_allowed_cidrs
    description = "SSH from explicitly approved public CIDRs"
  }

  rule {
    direction   = "in"
    protocol    = "tcp"
    port        = "2222"
    source_ips  = var.ssh_allowed_cidrs
    description = "Gitea built-in SSH from explicitly approved CIDRs"
  }

  rule {
    direction   = "in"
    protocol    = "tcp"
    port        = "80"
    source_ips  = local.public_source_cidrs
    description = "Public HTTP endpoint"
  }

  rule {
    direction   = "in"
    protocol    = "tcp"
    port        = "443"
    source_ips  = local.public_source_cidrs
    description = "Public HTTPS endpoint"
  }

  labels = merge(local.common_labels, { role = "gitea" })
}

resource "hcloud_firewall" "harbor" {
  name = "harbor-mgmt"

  rule {
    direction   = "in"
    protocol    = "tcp"
    port        = "22"
    source_ips  = var.ssh_allowed_cidrs
    description = "SSH from explicitly approved public CIDRs"
  }

  rule {
    direction   = "in"
    protocol    = "tcp"
    port        = "80"
    source_ips  = local.public_source_cidrs
    description = "Public HTTP endpoint"
  }

  rule {
    direction   = "in"
    protocol    = "tcp"
    port        = "443"
    source_ips  = local.public_source_cidrs
    description = "Public HTTPS endpoint"
  }

  labels = merge(local.common_labels, { role = "harbor" })
}

resource "hcloud_server" "gitea" {
  name        = "gitea-mgmt"
  server_type = var.gitea_server_type
  image       = "ubuntu-24.04"
  location    = var.location
  ssh_keys    = [data.hcloud_ssh_key.management.id]

  public_net {
    ipv4_enabled = true
    ipv6_enabled = true
  }

  firewall_ids = [hcloud_firewall.gitea.id]
  labels       = merge(local.common_labels, { role = "gitea" })

  delete_protection  = true
  rebuild_protection = true

  lifecycle {
    prevent_destroy = true
  }
}

resource "hcloud_server" "harbor" {
  name        = "harbor-mgmt"
  server_type = var.harbor_server_type
  image       = "ubuntu-24.04"
  location    = var.location
  ssh_keys    = [data.hcloud_ssh_key.management.id]

  public_net {
    ipv4_enabled = true
    ipv6_enabled = true
  }

  firewall_ids = [hcloud_firewall.harbor.id]
  labels       = merge(local.common_labels, { role = "harbor" })

  delete_protection  = true
  rebuild_protection = true

  lifecycle {
    prevent_destroy = true
  }
}

resource "hcloud_server" "data" {
  name        = "data-mgmt"
  server_type = var.data_server_type
  image       = "ubuntu-24.04"
  location    = var.location
  ssh_keys    = [data.hcloud_ssh_key.management.id]

  public_net {
    ipv4_enabled = false
    ipv6_enabled = false
  }

  network {
    subnet_id = hcloud_network_subnet.management.id
    ip        = local.private_ips.data
    alias_ips = []
  }

  labels = merge(local.common_labels, { role = "data" })

  delete_protection  = true
  rebuild_protection = true

  lifecycle {
    prevent_destroy = true
  }

  # hcloud 1.68.0 documents an API concurrency risk unless server creation is
  # explicitly ordered after the subnet, even when the inline network is used.
  depends_on = [hcloud_network_subnet.management]
}

resource "hcloud_server_network" "gitea" {
  server_id = hcloud_server.gitea.id
  subnet_id = hcloud_network_subnet.management.id
  ip        = local.private_ips.gitea
  alias_ips = []
}

resource "hcloud_server_network" "harbor" {
  server_id = hcloud_server.harbor.id
  subnet_id = hcloud_network_subnet.management.id
  ip        = local.private_ips.harbor
  alias_ips = []
}
