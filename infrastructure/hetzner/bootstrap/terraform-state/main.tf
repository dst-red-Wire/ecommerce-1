data "hcloud_ssh_key" "terraform_state" {
  name = var.ssh_key_name
}

locals {
  common_labels = {
    component  = "terraform-state"
    managed_by = "terraform-bootstrap-local"
    plane      = "bootstrap"
    project    = "ecommerce"
  }
}

resource "hcloud_firewall" "terraform_state" {
  name = "terraform-state-mgmt"

  rule {
    direction   = "in"
    protocol    = "tcp"
    port        = "22"
    source_ips  = var.ssh_allowed_cidrs
    description = "SSH and PostgreSQL tunnel from explicitly approved IPv4 CIDRs"
  }

  labels = local.common_labels
}

resource "hcloud_server" "terraform_state" {
  name        = "terraform-state-mgmt"
  server_type = var.server_type
  image       = var.image
  location    = var.location
  ssh_keys    = [data.hcloud_ssh_key.terraform_state.id]

  public_net {
    ipv4_enabled = true
    ipv6_enabled = false
  }

  firewall_ids = [hcloud_firewall.terraform_state.id]
  labels       = local.common_labels

  delete_protection  = true
  rebuild_protection = true

  lifecycle {
    prevent_destroy = true
  }
}

# PostgreSQL data is separated from the VM root disk. Hetzner Volumes are
# triple-replicated block storage, but have no native snapshot/backup service;
# encrypted off-host backups therefore remain mandatory.
resource "hcloud_volume" "postgresql" {
  name              = "terraform-state-mgmt-postgresql"
  location          = var.location
  size              = var.postgresql_volume_size_gb
  format            = "ext4"
  delete_protection = true
  labels            = local.common_labels

  lifecycle {
    prevent_destroy = true
  }
}

resource "hcloud_volume_attachment" "postgresql" {
  volume_id = hcloud_volume.postgresql.id
  server_id = hcloud_server.terraform_state.id
  automount = false
}
