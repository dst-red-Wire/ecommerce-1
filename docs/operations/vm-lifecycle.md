# Local VirtualBox VM lifecycle

The authoritative policy is `config/contracts/vm-lifecycle-policy.yaml`. The Rocky
10.2 image inputs and responsibility boundary remain in
`config/contracts/machine-image-lock.yaml`. Run one VM at a time with:

```text
python scripts/repoctl.py vm reconcile --config .context/vm-lifecycle/rke2-cp1.json
```

Place the following JSON in the ignored `.context` tree and replace each absolute
path with a path on the current host. All local files must already exist. The
command never downloads an ISO, package, tool, plugin, or Vagrant box.

```json
{
  "vm": "rke2-cp1",
  "image_profile": "rke2",
  "iso": "C:/path/to/ecommerce-1/.context/packer/rocky-10.2-offline/iso/Rocky-10.2-x86_64-dvd1.iso",
  "offline_bundle": "C:/path/to/ecommerce-1/.context/packer/rocky-10.2-offline",
  "output_box": "C:/path/to/ecommerce-1/.context/packer/rocky-10.2-rke2-virtualbox.box",
  "packer_vars": "C:/path/to/ecommerce-1/.context/packer/rocky-10.2.auto.pkrvars.hcl",
  "vagrant_dir": "C:/path/to/ecommerce-1/.context/vm-lifecycle/rke2-cp1",
  "ssh_config": "C:/path/to/ecommerce-1/.context/vm-lifecycle/rke2-cp1/ssh_config",
  "inventory": "C:/path/to/ecommerce-1/.context/vm-lifecycle/rke2-cp1/inventory.ini",
  "vboxmanage": "C:/Program Files/Oracle/VirtualBox/VBoxManage.exe",
  "vagrant": "C:/Program Files/Vagrant/bin/vagrant.exe",
  "vagrant_version": "2.4.9",
  "packer": "packer",
  "ansible_playbook": "ansible-playbook",
  "ssh": "ssh",
  "hostonly_adapter": "VirtualBox Host-Only Ethernet Adapter",
  "guest_ip": "192.168.56.10",
  "cpus": 2,
  "memory_mib": 4096,
  "playbooks": ["platform/ansible/mgmt.yml"],
  "runtime_inputs": [],
  "image_inputs": [],
  "service_probe": "systemctl is-active rke2-server"
}
```

The Vagrantfile must use a local `config.vm.box_url`, the VirtualBox provider,
`config.vm.box_check_update = false`, and `config.vm.communicator = "none"` so
Vagrant never runs its monolithic SSH wait. Configure guest networking and key-only SSH
in that file and the matching `ssh_config` and inventory. The exported Packer image
locks its build user and removes its key. Supply a separately qualified guest
bootstrap before reconciliation; the controller does not create a default SSH user
or inject a key. Keep all VM definitions, identities, keys and evidence under
ignored `.context`. The controller will fail closed if the guest cannot be reached.

The image fingerprint covers the pinned ISO digest, Packer template, Kickstart,
image installer, machine image and toolchain locks, RPM lock, selected profile and
all staged offline bytes. Temporary build SSH keys and the generated evidence
timestamp do not affect it. List any additional image scripts in `image_inputs`.
All Ansible role files are included in the runtime fingerprint so a role change
triggers reprovisioning instead of an image rebuild. List any other runtime inputs
outside the role tree in `runtime_inputs`.

The JSON decision and counters are printed on success and saved in
`.context/vm-lifecycle/<vm>/latest.json` and
`.context/evidence/vm-lifecycle/<vm>.json`. A shared lock prevents simultaneous
VM launches and image builds. Remove a stale lock only after proving the prior
process is gone.
The controller never issues `vagrant destroy`. A changed or corrupt image with an
existing VM stops with `IMAGE_CORRUPT`, preserving that VM for explicit image
replacement and reclone. A preflight failure prevents both Packer build and VM
startup. Runtime checks are required to call a VM qualified.

## Qualification evidence

| Scenario | Baseline runtime wall | Reconciler runtime wall | Static result |
| --- | --- | --- | --- |
| Cold boot | BLOCKED_RUNTIME | BLOCKED_RUNTIME | one clone when absent |
| Reboot | BLOCKED_RUNTIME | BLOCKED_RUNTIME | reload only on reboot marker |
| Temporary SSH failure | BLOCKED_RUNTIME | BLOCKED_RUNTIME | bounded reprobe, no destroy |
| Ansible failure | BLOCKED_RUNTIME | BLOCKED_RUNTIME | two attempts, VM retained |
| Converged second run | BLOCKED_RUNTIME | BLOCKED_RUNTIME | zero rebuild/reload/reprovision in simulated test |

Wall time saved and percentage cannot be asserted without a real qualified Rocky
10.2 VM, offline bundle, guest bootstrap, and full local host prerequisites. The
unit tests demonstrate decisions only; they are not runtime qualification evidence.
