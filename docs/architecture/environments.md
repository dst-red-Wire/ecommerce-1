# Environment model

## Integration

- Existing Hetzner CCX33 at `178.104.138.200`.
- Permanent and economical.
- Native Docker Engine with a three-node Kind cluster.
- Kubernetes `v1.33.4`, Cilium, Flux, Tekton, Kyverno, Tetragon and the current
  observability stack.
- Fast integration and staging-lite feedback; not a production topology.

## Preproduction

- Ephemeral and created only for a validation campaign.
- Three real kubeadm control-plane VMs with stacked etcd and at least two real
  worker VMs on a private Hetzner network.
- Hetzner load balancer in front of the Kubernetes API.
- Containerd with systemd cgroups; no Docker Engine and no Kind.
- Cilium, Flux, policies and observability aligned with production.
- Receives the exact digest already validated in integration.
- Destroyed only through an explicit, separately authorized Terraform action.

Kubeadm is retained because it exposes the same control-plane, etcd, networking
and upgrade concerns as a self-managed production cluster while remaining
portable. K3s and Kind would hide or change too many production failure modes.

## Production

- Real HA cluster on multiple failure domains.
- Protected Git reconciliation from `main`.
- Same application bases, policies and OCI digests as preproduction.
- No image build, security attack or direct Tekton deployment against the
  production cluster.
