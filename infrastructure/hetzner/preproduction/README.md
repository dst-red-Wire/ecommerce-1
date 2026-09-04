# Ephemeral preproduction infrastructure

This Terraform root declares, but does not create, a production-like kubeadm
topology:

- three control-plane/stacked-etcd VMs;
- at least two worker VMs;
- one private Hetzner network;
- a spread placement group;
- a private-interface HTTPS load balancer checking `/readyz` for the Kubernetes
  API;
- explicit SSH CIDRs and private-only node/API traffic;
- campaign owner, ID, expiration and cost metadata.

No variable file with real addresses or credentials belongs in Git. The
existing SSH key is read by name rather than imported into this state.

Only `terraform fmt`, `terraform validate` and a reviewed `terraform plan` are
authorized by the current mission. `backend.tf` declares a partial S3 backend;
`backend.contract.json` fixes a preproduction-only state key and native S3
lockfile strategy. Bucket, endpoint, region and credential source remain an
external decision, so backend initialization is `NOT PROVEN`. Creation and
later destruction require separate explicit approval. Never reuse or edit the
staging state for this stack.

After an approved apply, `inventory_contract` is transformed deterministically
with `scripts/render-preproduction-inventory.sh`. The API DNS name must resolve
to the private load-balancer address and both must be kubeadm certificate SANs.
The intended next phase installs containerd, kubeadm/kubelet/kubectl at the
version pinned in `versions.mk`, initializes the first control plane, joins the
other nodes with short-lived tokens, installs Cilium, and bootstraps Flux. That
bootstrap is not implemented or tested yet; its status is `NOT PROVEN`. Join
tokens, certificate keys and kubeconfigs are runtime secrets and must never
enter Git.

The load balancer public interface is disabled. Operators need an explicitly
managed VPN/bastion path into the private network; this stack does not create
one. Node port `6443` accepts only the private subnet. The HTTPS `/readyz`
health check proves API readiness only after kubeadm exists and must be tested
with the selected certificates.

Expiration never implies automatic destruction. The state lineage/serial,
reviewed destroy-plan digest and separate authorization contract are defined by
`lifecycle.schema.json` and `docs/runbooks/preproduction-lifecycle.md`.
`scripts/validate-preproduction-lifecycle.py` can compare a supplied approval
with an independently read backend ID, lineage and serial; it never invokes
Terraform and is not itself authorization to destroy.
