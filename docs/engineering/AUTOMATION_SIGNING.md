# Repository automation signing and rotation

`architecture.lock.yaml#repository_governance.automation_signing` is the sole policy authority. Run all commands in the native WSL checkout `/home/dev/ecommerce-1`. The personal key and global Git configuration are protected; the automation key is repository local.

## Current rotation

| Field | Value |
| --- | --- |
| Active fingerprint | `1E017B8EA8721E5B7854D3F4AADEE6601021EBE8` |
| Pending fingerprint | `D0E9857876048A4E303B4972BA1BD2FFE663316C` |
| Pending expiry, UTC | `2026-12-25T17:33:39Z` |
| Pending public export | `/tmp/ecommerce-1-automation-signing-D0E9857876048A4E303B4972BA1BD2FFE663316C.asc` |
| Pending revocation certificate | `/home/dev/.gnupg/openpgp-revocs.d/D0E9857876048A4E303B4972BA1BD2FFE663316C.rev` |
| Registration | Waiting for GitHub and Gitea |

The pending key has no passphrase, signs only, and remains inactive. The public export contains `BEGIN PGP PUBLIC KEY BLOCK`; no secret key or revocation certificate belongs in the repository. The ignored, mode `0600` rotation journal is `.context/signing-rotation/state.json`.

## Routine checks

`make signing-rotation-status` prints a read-only JSON status. `make signing-rotation-check` fails at seven days or less before expiry unless a replacement has been verified on both forges; it always fails after expiry. `make signing-check`, `make ci`, `make deliver`, and `make finish-pr` include this gate. The date thresholds are 30 days for INFO, 14 for WARN, and seven for BLOCK. `make signing-check` also checks the personal key's passphrase protection, the active key, revocation certificate, local Git settings, and repository content.

## Prepare and register

`make signing-rotate` creates one Ed25519 signing key with 90 day validity and no passphrase, exports only its public key under `/tmp`, records a local journal, and puts a pending fingerprint in the lock. Repeating it reuses a valid pending rotation. The active fingerprint and `git config --local user.signingkey` remain unchanged.

The default publication mode is manual. Add the **public** export to the `dst-red-Wire` GitHub account under **Settings → SSH and GPG keys → New GPG key**, and to the `dst-red-Wire` Gitea account under **Settings → SSH / GPG Keys → Manage GPG Keys**. Do not upload the secret key. `make signing-rotation-verify-remote` queries both forge accounts and records only booleans in the local journal. A missing registration gives `WAITING_FOR_REMOTE_KEY_REGISTRATION`. If an explicitly authorized automated registration workflow is introduced later, it must submit only the same public export and recheck both accounts.

## Activate and retire

After both public registrations are proven, `make signing-rotation-activate` checks the pending fingerprint, local signing capability, certificate, signed Git probe, and a second signed probe after `gpg-agent` is killed. It then switches the repository local signer and canonical active fingerprint. It retains the old key during the maximum seven day overlap. The new signed commit must be published to both forges and independently verified there; on GitHub require `verified=true`, `reason=valid`, and `dst-red-Wire` as author and committer. Gitea must confirm the same signer. Any failure blocks retirement.

`make signing-rotation-retire-old` requires a **real Windows reboot** proof with the new fingerprint, a fresh agent, no passphrase prompt, exact signed commit, new CI PASS, exact SHA delivery PASS, and both forge commit verification results. A mere `gpg-agent` restart is insufficient. Remote public key removal or revocation is a separate operator decision: retaining the old public registration allows historical signature verification. The old secret key is never automatically erased.

If the process is interrupted, rerun `make signing-rotate` before activation or the relevant verification command afterwards. An expired replacement, missing certificate, mismatched fingerprint, partial forge registration, or unsafe journal permissions stops the workflow. Never move the personal key or export any private material. The rotation PR remains open until ChatGPT CODE and SECURITY reviews bind its exact published SHA. `finish-pr` refuses the rotation branch; the owner must decide and perform any merge manually.
