# Persistent MGMT Terraform root

This root consumes canonical MGMT inventory, access-gateway, and network YAML.
It is static IaC only until a human authorizes the deferred cloud qualification.

First provisioning deliberately uses Terraform's local backend on an encrypted,
operator-controlled workstation. Do not commit state, plans, backend credentials,
provider mappings, or runtime output. After MGMT exists and the governed
SeaweedFS S3 state service is independently ready, a human-reviewed backend
migration may be performed as described in `docs/architecture/MGMT_BOOTSTRAP_V1.md`.
There is intentionally no committed backend block that would make first creation
depend on MGMT itself.

Required runtime inputs are the provider location/network zone, a pinned Rocky
Linux 9 image, and explicit reviewed mappings from canonical compute profiles to
Hetzner server types. No defaults guess provider identifiers or silently resize
the canonical intent.
