# Preproduction campaign lifecycle

`ephemeral=true` is classification only; it is not a TTL and authorizes no
destruction.

## Creation order

1. Assign a lowercase `campaign_id`, named `owner`, RFC3339 `expires_at` and
   `cost_center`.
2. Approve the external S3 backend decision, then initialize with the partial
   backend in `backend.tf`, the exact state key from `backend.contract.json`,
   and native `use_lockfile=true`. Never reuse the staging bucket/key or state.
3. After separately authorized apply, render inventory from the locked state
   with `scripts/render-preproduction-inventory.sh`.
4. Verify DNS resolves the API name to the private load-balancer address and
   that the name/IP are kubeadm certificate SANs.
5. Run the read-only Ansible preflight, then a separately approved bootstrap.
   Containerd, kubeadm joins, stacked etcd, Cilium and Flux are currently not
   implemented or proven by this scaffold.

## Expiration and destruction

Expiration creates an alert and blocks campaign extension; it does not run
`terraform destroy`. Before any destroy, compare campaign ID/owner/backend ID
with the locked state lineage and serial, prove that no retained evidence
depends on the cluster, generate a destroy plan, review its SHA-256 and obtain
a separate signed approval matching `lifecycle.schema.json`. The confirmation
must literally bind campaign, lineage, and serial. Re-read the state under lock
immediately before execution and reject any serial change. Destruction is
outside the current mission.

Lifecycle automation, cost alerts and recovery are `NOT PROVEN` until exercised
against an authorized real campaign.
