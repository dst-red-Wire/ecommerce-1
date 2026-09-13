check "restricted_ssh_sources" {
  assert {
    condition     = !contains(var.qualification_ssh_allowed_cidrs, "0.0.0.0/0") && !contains(var.qualification_ssh_allowed_cidrs, "::/0")
    error_message = "Qualification SSH must remain restricted to trusted controller CIDRs."
  }
}

check "ubuntu_2404_image_contract" {
  assert {
    condition     = can(regex("^ubuntu-24\\.04(?:-[a-z0-9.-]+)?$", var.qualification_image))
    error_message = "Qualification requires an Ubuntu 24.04 x86_64 provider image."
  }
}
