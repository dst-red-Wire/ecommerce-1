data "hcloud_ssh_key" "preproduction" {
  name = var.ssh_key_name
}

locals {
  common_labels = {
    campaign_id = var.campaign_id
    environment = "preproduction"
    ephemeral   = "true"
    managed_by  = "terraform"
    owner       = var.owner
    project     = "ecommerce"
  }
  control_planes = {
    for index in range(var.control_plane_count) :
    format("control-plane-%02d", index + 1) => {
      role        = "control-plane"
      server_type = var.control_plane_server_type
    }
  }
  workers = {
    for index in range(var.worker_count) :
    format("worker-%02d", index + 1) => {
      role        = "worker"
      server_type = var.worker_server_type
    }
  }
  nodes = merge(local.control_planes, local.workers)
}

resource "hcloud_placement_group" "preproduction" {
  name = "${var.cluster_name}-spread"
  type = "spread"

  labels = local.common_labels
}

resource "hcloud_network" "preproduction" {
  name     = var.cluster_name
  ip_range = var.network_cidr

  labels = local.common_labels
}

resource "hcloud_network_subnet" "nodes" {
  network_id   = hcloud_network.preproduction.id
  type         = "cloud"
  network_zone = var.network_zone
  ip_range     = var.subnet_cidr
}

resource "hcloud_firewall" "nodes" {
  name = "${var.cluster_name}-nodes"

  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "22"
    source_ips = var.ssh_allowed_cidrs
  }

  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "6443"
    source_ips = [var.subnet_cidr]
  }

  rule {
    direction  = "in"
    protocol   = "tcp"
    source_ips = [var.subnet_cidr]
  }

  rule {
    direction  = "in"
    protocol   = "udp"
    source_ips = [var.subnet_cidr]
  }

  rule {
    direction  = "in"
    protocol   = "icmp"
    source_ips = [var.subnet_cidr]
  }

  labels = local.common_labels
}

resource "hcloud_server" "nodes" {
  for_each = local.nodes

  name               = "${var.cluster_name}-${each.key}"
  server_type        = each.value.server_type
  image              = "ubuntu-24.04"
  location           = var.location
  ssh_keys           = [data.hcloud_ssh_key.preproduction.id]
  placement_group_id = hcloud_placement_group.preproduction.id

  firewall_ids = [hcloud_firewall.nodes.id]

  labels = merge(local.common_labels, {
    cluster = var.cluster_name
    role    = each.value.role
  })
}

resource "hcloud_server_network" "nodes" {
  for_each = hcloud_server.nodes

  server_id  = each.value.id
  network_id = hcloud_network.preproduction.id

  depends_on = [hcloud_network_subnet.nodes]
}

resource "hcloud_load_balancer" "api" {
  name               = "${var.cluster_name}-api"
  load_balancer_type = "lb11"
  location           = var.location

  algorithm {
    type = "round_robin"
  }

  labels = local.common_labels
}

resource "hcloud_load_balancer_network" "api" {
  load_balancer_id        = hcloud_load_balancer.api.id
  network_id              = hcloud_network.preproduction.id
  enable_public_interface = false

  depends_on = [hcloud_network_subnet.nodes]
}

resource "hcloud_load_balancer_target" "control_planes" {
  for_each = {
    for name, server in hcloud_server.nodes : name => server
    if local.nodes[name].role == "control-plane"
  }

  type             = "server"
  load_balancer_id = hcloud_load_balancer.api.id
  server_id        = each.value.id
  use_private_ip   = true

  depends_on = [
    hcloud_load_balancer_network.api,
    hcloud_server_network.nodes,
  ]
}

resource "hcloud_load_balancer_service" "kubernetes_api" {
  load_balancer_id = hcloud_load_balancer.api.id
  protocol         = "tcp"
  listen_port      = 6443
  destination_port = 6443
  proxyprotocol    = false

  health_check {
    protocol = "https"
    port     = 6443
    interval = 10
    timeout  = 5
    retries  = 3

    http {
      domain       = var.api_server_dns_name
      path         = "/readyz"
      status_codes = ["200"]
      tls          = true
    }
  }
}
