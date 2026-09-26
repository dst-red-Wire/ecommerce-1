# Local management services

The canonical identities and endpoint profile are in
[architecture.lock.yaml](../../architecture.lock.yaml) under
`local_management_services`. The public defaults are in `endpoints.env.example`. Consumers use `GITEA_HTTPS_URL`,
`GITEA_ACCOUNT`, `HARBOR_URL`, `HARBOR_PROJECT`, and
`HARBOR_AUTOMATION_ACCOUNT`. Changing from local to remote endpoints changes
only URLs and credentials, never logical identities or API contracts.

On Windows, all repository operations run from the native WSL2 checkout.
The host needs at least 4 GiB assigned to WSL for Harbor; the tested
workstation uses 6 GiB. From the WSL checkout:

```text
make local-services-up
make local-services-provision
make local-gpg-register
make local-services-proof
```

`local-gpg-register` fails closed until
`.context/reboot-proof/result.json` proves a real Windows reboot,
a fresh unattended signature and the exact automation fingerprint.
The registration targets only `ecommerce-automation`. The human
`dst-red-Wire` account is separate. Harbor creates a private
`ecommerce` project with project-scoped `ecommerce-ci` robot
(`robot$ecommerce+ecommerce-ci` as the registry login name).
The robot has only repository pull/push permissions and a 90-day lifetime.

Gitea 1.27.3 and Caddy 2.10.2 are pinned by image digest.
Harbor 2.15.2 uses its official online installer pinned by SHA-256, and
all generated Harbor image references are replaced with the digests in
`harbor-images.lock.json` before startup.
After the first pull, Docker keeps the images locally. The bootstrap
creates a local CA and server certificate, credentials, installer,
data, and runtime evidence only in ignored `.context/local-services/`
and `.context/runtime/` on ext4. TLS keys and credentials have mode 0600.

WSL DNS maps the two `.ecommerce.local` names to 127.0.0.1 in
`/etc/hosts` and persists the mapping with
`/etc/wsl.conf: generateHosts=false`. The local CA is trusted by WSL.
The rootless Docker edge binds port 443 with a WSL-only
`net.ipv4.ip_unprivileged_port_start=0` setting. The Windows host does not
have these DNS or CA settings; access the endpoints from WSL. The edge
terminates TLS and forwards Harbor through TLS to its installer-managed
nginx endpoint.

The runtime proof writes `.context/runtime/local-services.json` without
secrets. Re-running provision and registration is idempotent. On a fresh
machine, keep the same contract and restore the ignored credential state
from a secure store or generate new local credentials.
