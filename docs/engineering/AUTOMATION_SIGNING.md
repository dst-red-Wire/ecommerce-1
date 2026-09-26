# Repository automation signing

The canonical contract is `architecture.lock.yaml#repository_governance.automation_signing`.
The current workstation implementation uses the `dev` account in `Ubuntu-24.04` WSL.
Run every repository operation from the native Linux checkout at `/home/dev/ecommerce-1`. The Git for Windows GPG installation has
a separate empty keyring and is not qualified for this signing configuration.

Before each automated commit, run `make signing-check` from this repository in WSL. It
checks the exact repository path, local and global Git settings, both private key
protection states, signing capability, expiration, revocation certificate, public
export, and repository content. The check fails closed. A successful check does not
make the private key cryptographically repository-specific; local Git configuration
and this gate enforce the scope. At 14 days before expiration it warns; at expiry
it blocks. The automation account's private key is still sensitive despite having
no passphrase and must remain protected by the account's filesystem permissions.

The public key is available outside the checkout at
`/tmp/ecommerce-1-automation-signing-public.asc`. `make signing-check` recreates
this public-only export if WSL or Windows restart clears `/tmp`. To display it, run
`cat /tmp/ecommerce-1-automation-signing-public.asc` in WSL. The export must contain
only `BEGIN PGP PUBLIC KEY BLOCK`. Register this public key as a GPG signing key in
GitHub **Settings → SSH and GPG keys → New GPG key** and in the Gitea account's
**Settings → SSH / GPG Keys → Manage GPG Keys**. Registration is a manual step; never
upload the private key.

The revocation certificate is stored at
`/home/dev/.gnupg/revocation/1E017B8EA8721E5B7854D3F4AADEE6601021EBE8.rev`.
In an emergency, remove the leading colon before its armored block in a temporary
copy outside the checkout, import that copy with `gpg --import`, and export the
updated **public** key. Publish the revoked public key to each forge where the old
key was registered, then stop using that key. Keep the certificate outside Git.

Rotate before 2026-12-25: create a new dedicated signing-only key with a fresh
90-day expiration and no passphrase; verify its fingerprint, protection, signing
capability, and revocation certificate; register its public key on both forges;
then update the canonical fingerprint and repository-local `user.signingkey` together.
Run `make signing-check`, a signed test commit, `git verify-commit`, and local gates
before publishing any commit. Never alter the personal key or global Git settings.
