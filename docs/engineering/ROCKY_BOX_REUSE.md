# Rocky VirtualBox box reuse and SSH diagnosis

The native Windows build artifact lives under `C:\ecommerce-lab\artifacts\<build-source-sha>\`. Its `manifest.json`, `SHA256SUMS`, `packer.log`, and `.box` bind the original source SHA, semantic Packer inputs, build log, and box bytes. `make packer-box` accepts an artifact only when its digest and semantic image inputs match the current source. A network, SSH, or Vagrant failure does not change that decision. The timestamp is provenance, not a cache key.

The previous failure path rebuilt Packer after the temporary build SSH key was removed. The new recovery path reuses the same verified box, creates a fresh isolated Vagrant VM, and runs only the network smoke. The lost private key cannot be reconstructed from its public key. A new controller key is authorized at guest boot through NoCloud over VirtualBox NAT; the image itself stays immutable.

Run `make lab-ssh-key` explicitly once. It creates or verifies `C:\ecommerce-lab\identity\id_ed25519` and prints only the public fingerprint. The private key is outside Git, the box, the disposable Vagrant home, and JSON evidence. A complete native cycle uses a protected temporary copy during the smoke, then removes that copy during recovery after the normal boot returns. The original controller identity persists. The guest must prove `packer` ownership, `0700` for `.ssh`, `0600` for `authorized_keys`, public-key SSH authentication, and absence of OpenSSH private keys in `/home/packer` and `/root`.

`make lab-network-smoke` stages an exact-SHA campaign under `C:\ecommerce-lab\network-smoke\<campaign-id>` and prints its native PowerShell command. `BOX_PATH` and `BOX_SHA256` can select a specific verified artifact. `GLOBAL_DEADLINE` controls the one Vagrant boot deadline. `KEEP_FAILED_VM=1` preserves an unsuccessful VM for inspection; the result is `DIAGNOSTIC_PRESERVED`. `RETAIN_VM=1` keeps the VM after success or failure until explicit cleanup. `make lab-network-resume CAMPAIGN_ID=<id>` verifies the retained box, VM identity, and Vagrant state, then repeats only the network, SSH, and Rocky probes. If a host reboot stopped the VM, it starts that same VM with `vagrant up --no-provision` and verifies the VirtualBox ID again. It runs the clean current runner after checking that image inputs still match the box and records the runner SHA; the original stage and prior evidence stay intact. It never invokes Packer or creates a replacement VM. `make lab-clean CAMPAIGN_ID=<id>` destroys only the VM recorded for that campaign. The default cleanup destroys the VM and isolated box cache. Network smoke never invokes Packer.

For a Windows native VT-x boot, run `make lab-network-native-prepare CAMPAIGN_ID=<id>` while WSL is available. It stages the exact-head PowerShell runner and its helper files under `C:\ecommerce-lab\network-smoke\runner-<sha>` and prints the native `Resume` command. After the native run and restoration of WSL, run `make lab-network-import CAMPAIGN_ID=<id>`. Import does not start or mutate the VM; it verifies the exact runner and helper digests, current box identity, guest security, native backend, and campaign ownership before copying the result to `.context/evidence/network-smoke/current.json`. A NEM or stale result is rejected.

## Trusted native UAC boundary

Run the native UAC controller by its absolute path in a clean checkout of the PR's **exact base commit**. The target PR checkout is input data, never the authority that grants Administrator execution. The base controller resolves the unique open PR and exact head, verifies the current qualification and the exact-SHA ChatGPT CODE and SECURITY PASS comments, then verifies a separate repository-owner authorization bound to the campaign, retained VM UUID, and both review comment IDs. It checks the reviewed runner bytes, builds the minimal bootstrap from base-owned code, and only then requests UAC. A changed head, changed runner, revoked review or authorization, or missing base controller blocks elevation. The managed GitHub CLI contract remains `gh == 2.101.0`. The PR-head `make lab-network-native-boot-*` targets deliberately stop; do not use them as an authorization entrypoint.

Before taking the native runtime lock or requesting UAC, the base controller reruns full qualification without evidence reuse and performs a fresh base-owned performance audit. It binds both outputs to a digest carried by the bootstrap. After UAC, the bootstrap invokes base-only `Verify` before copying and immediately before running reviewed scripts; `Verify` rechecks the open PR, qualification digest, runner manifest, CODE, SECURITY, and owner authorization. `Reboot` also hashes all seven protected shadow scripts against the reviewed manifest. Offline `Recover` checks the protected state, runner manifest, and seven local script hashes before execution.

Set these values from independently observed PR and VM facts, then invoke the controller directly. `BASE` must point to the clean exact-base checkout; `TARGET` must point to the clean reviewed PR checkout. `EXPECTED_VM_ID` is the UUID observed before preparation, not read from writable campaign files.

```sh
BASE=/absolute/path/to/clean/exact-base-checkout
TARGET=/absolute/path/to/clean/reviewed-pr-checkout
PR='reviewed-pr-number'
CAMPAIGN_ID='retained-campaign-id'
EXPECTED_VM_ID='independently-observed-vm-uuid'
CONTROLLER="$BASE/scripts/repository_delivery.py"

python3 -I "$CONTROLLER" trusted-native-uac --action SelfTest --target-root "$TARGET" --pr "$PR" --campaign-id "$CAMPAIGN_ID" --expected-vm-id "$EXPECTED_VM_ID"
python3 -I "$CONTROLLER" trusted-native-uac --action Prepare --target-root "$TARGET" --pr "$PR" --campaign-id "$CAMPAIGN_ID" --expected-vm-id "$EXPECTED_VM_ID"
python3 -I "$CONTROLLER" trusted-native-uac --action Reboot --target-root "$TARGET" --pr "$PR" --campaign-id "$CAMPAIGN_ID"
# After Windows returns to its normal loader and WSL is available:
python3 -I "$CONTROLLER" trusted-native-uac --action Recover --target-root "$TARGET" --campaign-id "$CAMPAIGN_ID"
make -C "$TARGET" lab-network-import CAMPAIGN_ID="$CAMPAIGN_ID"
```

The network runner needs a Windows boot where VirtualBox has native VT-x and the Microsoft hypervisor is absent. A normal WSL2 boot reports `BLOCKED_RUNTIME` before starting a VM. `Prepare` validates the retained VM and exact-head runner, creates a protected campaign under `C:\Program Files\EcommerceNativeSmoke\<campaign-id>-<sha>`, installs the copied box into a fresh Vagrant home, verifies the original VirtualBox UUID, checks passwordless S4U access under the VM owner's SID, backs up BCD, and creates a dedicated native entry without rebooting or changing the default loader. `Reboot` is a separate action. The scheduled task runs `Resume` under native VT-x, checks network and guest security on the retained VM, and requests a second reboot to the original normal Windows loader even if Resume fails; a watchdog bounds a hung or missing task. `Recover` verifies cleanup of the owned BCD entry and tasks before import. Import checks the protected result and its boot-state digest. Keep the VM until import passes.

If the exact base does not yet contain `trusted-native-uac`, the native UAC cycle remains blocked. Adding a controller to the target PR does not make that controller trusted for the same PR.

For SSH diagnosis before the native reboot, `DIAGNOSTIC_NEM=1 RETAIN_VM=1` permits a VM under the Microsoft hypervisor. The probes and Rocky runtime facts are recorded, but the campaign remains `BLOCKED_RUNTIME` even if they pass; NEM cannot satisfy the native VT-x gate. The VM remains available for inspection or a later native boot.

The initial diagnostic result is written to `C:\ecommerce-lab\evidence\network-smoke\<campaign-id>\result.json`. The native Resume writes its result under the protected campaign's `evidence\network-smoke\<campaign-id>\result.json`; import verifies its digest against `native-boot.json`. The result records `03-vm-smoke`, `04-network-ssh`, and `05-rocky-runtime` checkpoints and the next resume point. `network_smoke` records VM state, guest IP when observed, NAT address and port, SSH banner, authentication, `vagrant ssh-config`, direct remote command, `/etc/os-release`, timings, and a stage-specific failure code. The 20-second `vagrant ssh -c true` wrapper is retained only as a nonblocking diagnostic. Direct OpenSSH uses the Vagrant endpoint and owned identity with a pinned `known_hosts` file. Without Guest Additions, VirtualBox guestproperty may not expose the guest IP; after successful SSH authentication the runner reads it from the guest. It reports an unobservable IP rather than claiming that no IP was assigned.

Do not merge the stacked branch or #148 until the targeted native network smoke and one complete native qualification have PASS evidence, including digest verification, cleanup, return to normal boot, BCD restoration, and native task removal.
