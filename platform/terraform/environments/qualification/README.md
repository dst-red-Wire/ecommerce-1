# M1 qualification VM Terraform handoff

This independent state root defines one disposable Hetzner Cloud VM and one
ingress firewall. It does not share the persistent MGMT network or state. The
VM has public IPv4 for bootstrap egress but no private-network attachment, cloud
role, managed identity, provider token, controller credential, or secret user
data. Hetzner firewalls filter IPs/ports rather than DNS names, so this slice
does not claim domain-level egress restriction.

Supply `qualification_image` as the Hetzner Ubuntu 24.04 public image name
(`ubuntu-24.04`), an explicit x86 server type sized for Docker, PostgreSQL
Testcontainers, Go race-enabled tests, and `make ci`, an existing provider-side
public SSH key ID, and trusted controller CIDRs. Plan/apply resolves the image
to an x86 provider image ID; `qualification_image_identity` records that exact
resolution. Image names are provider-managed aliases, not invented immutable
digests, so capture this output with qualification evidence.

Static review is limited to `terraform init -backend=false`, validation, and a
read-only plan. A plan describes one billable `hcloud_server` if applied; it is
never apply authorization.

After a separately authorized apply, write `qualification_inventory_host_line`
to an external inventory under a `[qualification_runners]` group. Authenticate
the SSH host key out of band as required by the canonical runner documentation,
then invoke `platform/ansible/qualification-runner.yml`. Terraform deliberately
does not invoke Ansible. Destroy the consumed VM only in a separately authorized
runtime task; a later apply recreates the same declared host contract.
