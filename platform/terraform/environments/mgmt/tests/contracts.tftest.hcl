mock_provider "hcloud" {}

variables {
  hcloud_location            = "fsn1"
  hcloud_network_zone        = "eu-central"
  hcloud_ssh_key_ids         = [123]
  hcloud_access_server_types = { wireguard-gateway = "cx22" }
  hcloud_image               = "rocky-9-pinned-test-fixture"
  hcloud_server_types = {
    rke2-cp     = "cpx31"
    rke2-worker = "cpx51"
  }
}

run "canonical_mgmt_contract_plans_without_provider_mutation" {
  command = plan

  assert {
    condition     = length(module.hcloud_mgmt.servers) == 6
    error_message = "The canonical MGMT plan must contain exactly six RKE2 nodes."
  }
}

run "reject_ipv4_default_route" {
  command = plan
  variables { bootstrap_ssh_allowed_cidrs = ["0.0.0.0/0"] }
  expect_failures = [var.bootstrap_ssh_allowed_cidrs]
}

run "reject_ipv4_host_bits_default_route" {
  command = plan
  variables { bootstrap_ssh_allowed_cidrs = ["1.2.3.4/0"] }
  expect_failures = [var.bootstrap_ssh_allowed_cidrs]
}

run "reject_ipv6_default_route" {
  command = plan
  variables { bootstrap_ssh_allowed_cidrs = ["::/0"] }
  expect_failures = [var.bootstrap_ssh_allowed_cidrs]
}

run "reject_ipv6_host_bits_default_route" {
  command = plan
  variables { bootstrap_ssh_allowed_cidrs = ["2001:db8::1/0"] }
  expect_failures = [var.bootstrap_ssh_allowed_cidrs]
}

run "reject_malformed_cidr" {
  command = plan
  variables { bootstrap_ssh_allowed_cidrs = ["invalid"] }
  expect_failures = [var.bootstrap_ssh_allowed_cidrs]
}

run "accept_restricted_bootstrap_sources" {
  command = plan
  variables {
    bootstrap_ssh_allowed_cidrs        = ["198.51.100.4/32", "2001:db8::4/128"]
    bootstrap_ssh_enabled              = true
    bootstrap_ssh_human_gate_confirmed = true
  }
}

run "reject_missing_ssh_keys" {
  command = plan
  variables { hcloud_ssh_key_ids = [] }
  expect_failures = [var.hcloud_ssh_key_ids]
}

run "reject_zero_ssh_key" {
  command = plan
  variables { hcloud_ssh_key_ids = [0] }
  expect_failures = [var.hcloud_ssh_key_ids]
}

run "reject_fractional_ssh_key" {
  command = plan
  variables { hcloud_ssh_key_ids = [1.5] }
  expect_failures = [var.hcloud_ssh_key_ids]
}
