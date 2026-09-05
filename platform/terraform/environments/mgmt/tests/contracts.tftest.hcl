mock_provider "hcloud" {}

run "canonical_mgmt_contract_plans_without_provider_mutation" {
  command = plan

  variables {
    hcloud_location = "fsn1"
    hcloud_image    = "rocky-9-pinned-test-fixture"
    hcloud_server_types = {
      rke2-cp     = "cpx31"
      rke2-worker = "cpx51"
    }
  }

  assert {
    condition     = length(module.hcloud_mgmt.servers) == 6
    error_message = "The canonical MGMT plan must contain exactly six RKE2 nodes."
  }
}
