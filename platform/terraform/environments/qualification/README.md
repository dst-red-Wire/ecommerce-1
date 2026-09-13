# M1 qualification Terraform handoff

This independent state root declares two disposable Ubuntu 24.04 x86_64
servers: a private-only qualification runner and a dedicated public
Squid/SSH gateway. Both attach only to the qualification network
(`10.248.0.0/24` by default), which is separate from PREPROD, PROD, MGMT,
Kubernetes, storage, and backup networks. Operators changing its RFC1918 CIDR
must check for collision with every routed environment.

The runner has no public IPv4 or IPv6 and its provider firewall permits outbound
TCP only to Squid on the gateway. It permits inbound SSH only from the gateway.
Consequently runner root cannot create a direct public or DNS bypass: Squid
resolves destinations on the separately administered gateway. The gateway's
public SSH is restricted to `qualification_ssh_allowed_cidrs`; port 3128 is
accepted only from the runner private `/32` and is never publicly exposed.

Gateway cloud-init installs the exact `qualification_squid_version` from the
immutable Ubuntu snapshot, holds and verifies it, writes a committed explicit
hostname policy, and starts Squid. HTTP is limited to ports 80/443, CONNECT to
443, destination IP literals do not match the hostname ACL, and the final rule
denies everything else. Local Squid access logs record timestamp, runner source,
destination, and allow/deny status. The gateway never receives repository code
or guest secrets. The allowlist covers the #78 Ubuntu snapshot, GitHub source
and pinned release assets, Go proxy/checksum downloads, and Docker Hub registry,
authentication, and image CDN endpoints used by the audited qualification flow.

Supply explicit runner and gateway server types, the Ubuntu image name, an
existing provider-side public SSH key ID, and trusted controller CIDRs. After a
separately authorized apply, use `qualification_inventory_host_line` for the
canonical Ansible playbook and export the bounded `qualification_proxy_environment`
for runner package/source/container tools. Authenticate both SSH host keys out
of band and retain `ProxyJump`; no private key is output.

Static validation is not apply authorization. This root describes two billable
servers, one network/subnet, and two firewalls if applied. Terraform does not
invoke Ansible or provisioners. Apply, destroy, and every real provider mutation
require a separate human-authorized runtime task.
