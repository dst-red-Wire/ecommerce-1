# Qualification execution

`config/contracts/qualification-execution-policy.yaml` governs **how** costly
qualifications run. `ExecutionPropertiesPolicy` defines **which** properties their
results must have. The contracts and governance gates load the execution policy
through `scripts/repoctl.py`; `scripts/qualification_steps.py` validates its step
rules and the checkpoint model. The single checkpoint schema is
`config/contracts/qualification-step-evidence.schema.json`.

An expensive step requires a PASS preflight with capacity and environment checks
bound to the same source SHA and qualification input digest. Every declared graph
predecessor needs a compatible checkpoint; runtime predecessors need a present,
digest-verified runtime evidence file. FULL work requires the complete transitive
SMOKE chain. A
PASS declaration alone cannot authorize FULL. A checkpoint records the step,
exact source SHA, input digest, status, timestamps, duration, and executed/reused
metrics. The only reuse status is `SKIPPED_REUSED_VERIFIED`, with a matching
artifact digest and complete `reused_from` provenance. Other statuses are `PASS`,
`FAIL`, and `BLOCKED_RUNTIME`.

The RKE2 VirtualBox M2.5 workflow declares its dependency graph and change
classes in the central policy. `repoctl` writes action checkpoints under the
ignored `.context/mgmt-offline-vm/<name>/step-checkpoints/` directory. Its
preflight precedes VM creation, its VM smoke precedes offline bundle and RKE2
work, and cleanup requires the completed action sequence and retained runtime
result files. The offline artifact role checks the digest-specific target before
transfer; matching content skips the full copy, and transferred bytes are checked
again before installation.
Checkpoint files are diagnostic records. A failed campaign starts over; the
workflow does not reload checkpoints or claim resumable execution. The initial
offline role trial runs before diagnostic RPM installation so it remains cold.

`python3 scripts/repoctl.py qualification-impact --base <sha> --head <sha>`
uses the repository's existing affected-component classifier, then the workflow
path rules and dependency graph. It returns reusable and invalidated steps as
JSON. A docs-only change invalidates no runtime step; an unknown or broad
system impact invalidates the whole graph. Changes to an exact-SHA final candidate need a
new impact decision; previous FULL proof and CODE/SECURITY reviews cannot be
silently applied to the new SHA. The existing ChatGPT review gate enforces that
exact-SHA binding.

Diagnostic VM, box, logs, keys, and metadata remain until final evidence is
captured or the workflow explicitly authorizes cleanup. The Windows native
cycle writes an early progress record and a fail-closed provisional result before
unregistering its running task, so an interrupted attempt remains diagnosable.

For M2.5 transfer diagnostics, the WSL controller gets pinned `iperf3` through
the `developer_toolchain` Ansible role (`m25_transfer_diagnostics` tag). The
disposable Rocky VM gets `iperf3` and `fio` only through the
`platform/ansible/tests/mgmt_offline_vm/main.yml` `diagnostics` action. That
action requires four pinned RPMs in the ignored
`.context/m2.5/diagnostics/rpms/` cache, verifies their source and guest SHA256
and Rocky signatures, and installs them with every remote repository disabled.
The cache can be populated from the pinned Rocky 10.2 image using:

```bash
mkdir -p .context/m2.5/diagnostics/rpms
docker run --rm --network bridge \
  -v "$PWD/.context/m2.5/diagnostics/rpms:/out" \
  rockylinux/rockylinux:10.2 \
  dnf -y --setopt=install_weak_deps=False --downloadonly --downloaddir=/out \
  install iperf3-3.17.1-6.el10_2.1 fio-3.36-5.el10
```

The diagnostic action reuses guest RPMs with matching digests. `fio` remains a
VM tool because the requested storage measurement is on the guest disk.
