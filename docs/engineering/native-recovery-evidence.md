# Native host recovery evidence

The registered producer is `scripts/native_recovery_evidence.py:validate`.
Its canonical output is `.context/evidence/native-recovery/current.json`.
This host proof is separate from M2.5 LAB readiness and cannot establish a
persistent deployment or satisfy the roadmap deployment exit gate.

## Adoption scope

This change adopts only the reader, current and historical validation, and their
consumers. It does not change the native runner, shadow selection, VM lifecycle,
or any host setting. The runner in the base does not produce the required
prospective records; existing shadows therefore remain unprovable. Unit fixture
results establish validator behavior, not runtime qualification.

## Observations and authority

A future exact-source native runner captures BCD output, the retained VM identity
and powered-off state, the three owned task names, and private shadow key absence
before shadow initialization. It exports BCD and seals the protected capture
before probe tasks or BCD changes. Recovery records the resources actually
removed, finalizes `native-boot.json`, and makes a fresh read-only observation.

The protected records are `recovery/capture.json`, `recovery/restore.json`, and
`recovery/verification.json`. They are written once. Historical states lacking a
prospective capture are cleaned up safely but are never completed retrospectively.
Observation failures cannot prevent the existing guarded host cleanup. They leave
an explicit protected error and no accepted recovery proof. Interrupted or partial
write-once receipts remain blocked; retries do not rewrite history or invent the
missing observation.

The validator derives capture, restoration and restoration verification from
these observations. It checks ordering, raw BCD inventory/readback, all three
task names, private key absence, retained VM UUID, exact HEAD/tree/campaign,
the approved box, native VT-x result and runner bytes. It rejects NEM, failed or
unexecuted runs, redirected or multiply linked files, writable protected ACLs,
changed bytes, and a caller-supplied `recovery` verdict.

Current verification has a 24-hour limit. Historical verification requires the
original exact bundle digest and source inputs; it does not turn old evidence
into authority for another HEAD.

## Produce evidence after a future authorized cycle

The native entry point remains the trusted controller at the current exact PR
base. Its `Prepare`, `Reboot` and `Recover` actions must pass their existing
qualification, review and owner gates. The retained campaign and VM identity
must remain bound; a new campaign creates another VM.

After a successful cycle and `Recover`, from the clean exact published checkout:

```text
.venv/qualification/bin/python scripts/native_recovery_evidence.py \
  --campaign-id <retained-campaign-id> \
  --vm-id <independently-observed-retained-vm-uuid>
```

Add `--check-only` to validate without writing the canonical output. Missing
observations produce `BLOCKED_RUNTIME` and no PASS file. No BCD, task, VM, key,
image, or cloud mutation is performed by this command.

For the retained campaign `20260929T163821Z-9da62296f3d5`, the observed UUID is
`e80d60f3-a12e-4734-a654-0cd24dce0fa1`. Its existing historical shadow has zero
boot attempts and lacks the prospective recovery records. It cannot qualify
a later commit.

## Base-controller boundary

Registration becomes trusted only after this adoption has passed its own exact-base
qualification, independent reviews, owner authorization, and merge gates. A
candidate registration cannot authorize itself or another unmerged change.

A later runner change must integrate the approved main, obtain new exact-base
qualification and reviews, and produce prospective observations bound to its own
published source. Historical shadows cannot be completed retrospectively.
