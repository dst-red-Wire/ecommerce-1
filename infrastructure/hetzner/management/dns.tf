# deployfrance.com already exists as a master zone. nameserver_type is a
# creation-only ForceNew selector that the provider does not restore on read,
# so it must not be managed for this imported zone.
resource "cloudns_dns_zone" "management" {
  domain = var.dns_zone
  type   = "master"

  lifecycle {
    prevent_destroy = true
  }
}

import {
  to = cloudns_dns_zone.management
  id = var.dns_zone
}

check "distinct_management_dns_names" {
  assert {
    condition     = var.git_dns_name != var.registry_dns_name
    error_message = "Gitea and Harbor DNS labels must remain distinct."
  }
}

resource "cloudns_dns_record" "git" {
  zone  = cloudns_dns_zone.management.id
  type  = "A"
  name  = var.git_dns_name
  value = hcloud_server.gitea.ipv4_address
  ttl   = 300
}

resource "cloudns_dns_record" "registry" {
  zone  = cloudns_dns_zone.management.id
  type  = "A"
  name  = var.registry_dns_name
  value = hcloud_server.harbor.ipv4_address
  ttl   = 300
}
