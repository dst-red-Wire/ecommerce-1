# Independent runner authority

The canonical policy is `config/contracts/qualification-execution-policy.yaml#runner_authority`.
The GitHub PR head is untrusted input. The trusted control plane is a reviewed,
owner-authorized merge on `main`, its immutable Harbor runner image, its pinned
validator and policy bytes, and runtime proofs verified outside the PR workload.
The PR checkout cannot provide or approve any of these inputs.

## Current state

This change prepares the local pinned runtime, the immutable image recipe, and
fail-closed identity and policy checks. There is no independent runtime proof
verifier or approved merged authority yet. The image must not be published
before the dedicated PR is approved and merged. The local RBAC assessment is
machine-readable but is not an authority proof; no workload run has been
observed. The legacy remote Tekton proof is blocked until a trusted publisher
exists. Runner authority therefore remains NOT_ACTIVE and PR #185 cannot
receive formal exact-SHA qualification through the legacy transition.

## Bootstrap

1. Create the runner-authority PR from current `main`. Existing exact-base
   qualification and independent ChatGPT CODE, then SECURITY, then applicable
   repository-owner authorization govern that PR. Its own tests do not make
   its new runner an authority.
2. Merge only through repository gates. Read the resulting GitHub `main` SHA.
3. Build the runner image from that exact merged SHA, publish to the local Harbor
   project, resolve the registry digest, pull by digest, inspect the pulled image,
   and run a minimal command. Require expected = registry = pulled digest.
4. Prove aggregate CPU/memory, wall/subprocess timeouts, concurrency and
   descendant cleanup against the actual workload runtime. A Python rlimit
   smoke test alone is insufficient.
5. Apply the dedicated runner identities in a dedicated namespace and execute
   the live ALLOWED/DENIED RBAC matrix. The PR workload ServiceAccount has no
   mounted API token. Any extra permission blocks activation.
6. The independent verifier checks all three complete machine-readable proofs
   and referenced evidence. A missing, stale, incompatible or PR-supplied proof
   leaves `runner_authority=NOT_ACTIVE`.

A runner name, mutable tag, local manifest, unit-test fixture or old readiness
result is never a trust identity or runtime proof. The pre-existing Tekton trigger
readiness is a separate seven-prerequisite gate and its three similarly named
checks do not activate this runner.

The authority fingerprint binds the approved source SHA, Harbor image digest,
policy digest, validator digest and available toolchain digest. Each proof binds
the repository, PR, exact target SHA, campaign, fingerprint, timestamp and
content-addressed evidence references. An activated control plane must resolve the current
GitHub PR HEAD itself and check it against the requested and checked-out SHA
before and after execution. A changed HEAD must abort the campaign as STALE_SHA.
A target SHA equal to the source SHA is rejected when a PR would validate itself.

Credentials for GitHub, Harbor publishing, Kubernetes administration, signing,
and status publication must remain in the control plane. PR code must receive
an explicit minimal environment, no inherited stdin, no owner HOME, and no
secret mount. It must not be able to write the trusted validator, policy,
authority proofs or verdict.
CODE and SECURITY review authority remains ChatGPT exact-SHA under
`config/contracts/review-policy.yaml`; the owner authorization comment remains
an independent repository-owner action.

## Reproducible local prerequisites

The one-command local bootstrap reconciles the hash-locked Ansible seed,
local Harbor and Gitea, and the isolated Tekton fixture:

```text
make runner-authority-local
```

The playbook installs Kind and kubectl using the exact versions and SHA256
values in `config/contracts/toolchain-lock.json`. Its Kubernetes node
image and Tekton release manifest are also digest pinned in
`platform/ansible/runner-authority-local.yml`. The playbook verifies the
upstream Tekton manifest checksum, renders the exact local
`disable-creds-init=true` override before applying it, and checks the live
ConfigMap. This prevents Tekton from copying ServiceAccount secrets into PR
steps in the local fixture.

It stores its kubeconfig in ignored `.context/runtime/runner-authority/` with
mode 0600. Re-running the playbook verifies the same node image and a Ready
node without creating a second cluster. This local fixture is useful for live
RBAC testing. It does not represent the six-node management plane and does not
turn a future runner image or qualification proof into PASS.

The playbook also applies `platform/tekton/authority/local` with the dedicated
namespace, quota, limits and RBAC. Run the read-only assessor from the trusted tree:

```text
KUBECONFIG=.context/runtime/runner-authority/kubeconfig python3 scripts/runner_rbac.py --context kind-ecommerce-runner-authority --namespace ecommerce-runner
```

The assessor emits an assessment, not a formal authority-bound proof. Keep raw
runtime outputs under ignored `.context`; only the verifier can promote
independently observed and digest-checked evidence.
