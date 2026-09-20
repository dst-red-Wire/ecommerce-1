# MGMT RKE2 local VirtualBox evidence

This page records the bounded local result obtained on 2026-09-20 and points to
the Git-owned reproduction path. It is evidence for the local functional fixture,
not acceptance of the six real MGMT nodes.

## Result

The run used Windows VirtualBox 7.2.18, isolated Vagrant 2.4.9 and the official
Rocky 9.8 box pinned by
`platform/ansible/tests/mgmt_offline_vm/contract.yml`. The disposable target had
its own Rocky kernel `5.14.0-687.10.1.el9_8.0.1.x86_64`, systemd running and
SELinux `Enforcing`.

The cold preflight had two CPUs, no IPv4 or IPv6 default route, public connection
failure `ENETUNREACH`, output/forward nftables policy `drop`, and no prior RKE2
package or path. It then completed the actual `mgmt_offline_artifacts` role with
36 successful tasks, 14 changes and no failure in 12 minutes 47 seconds.

The bundle result was:

- RKE2 `v1.37.0+rke2r1`;
- approved manifest SHA256
  `738a5cd2aa1be1eb93b08247193c1585574ad1668650993226eafe3f3cfa0bad`;
- 180 exact signed RPMs;
- core and Cilium image archives with 41 validated image identities;
- Rancher signer `C8CFF216455126E9B9C918BE925EA29AE257814A`;
- Rocky signer `21CB256AE16FC54C6E652949702D426D350D275D`.

An independent offline reconstruction from the Git lock produced the same
manifest SHA256, 180 RPM records and 41 image identities.

The owned VM was then restarted with four online CPUs and 4,004,920 KiB guest
memory. The actual `rke2_server` role started RKE2 without target Internet
access. The bounded functional probe reported:

- node `localhost.localdomain` Ready;
- Cilium daemonset 1/1 Ready;
- CoreDNS available;
- every created deployment with at least one available replica;
- 22 pods observed;
- public TCP connection timed out under the canonical default-deny policy;
- SELinux remained `Enforcing`.

One pod remained Pending:
`kube-system/cilium-operator-75c86f48d9-s8bx4`. This is the second operator
replica, which required anti-affinity cannot place on the same single node. The
first replica was available.

## Findings corrected by the run

The official 10 GiB box entered `DiskPressure` while it held controller transfer
bytes, image import archives and imported containerd content simultaneously. The
fixture now removes its disposable transfer directory and already imported tar
archives only after verified installation and the first successful service start.

CoreDNS and metrics-server also proved that the canonical host firewall was
missing two workload-to-host paths. The canonical
`mgmt-private.xml.j2` now grants the canonical pod CIDR TCP 6443 to control
planes and TCP 10250 to Kubernetes nodes. The zone target remains `DROP`; no
parallel local whitelist was added.

## Reproduction

The authoritative procedure is
`platform/ansible/tests/mgmt_offline_vm/README.md`. Git owns:

- the complete artifact lock and independent manifest approval;
- the deterministic bundle builder;
- the Rocky/VirtualBox/Vagrant fixture contract;
- create, resize, artifact, RKE2 server and destroy actions;
- the resource, cold-target and RKE2 functional probes;
- unit tests for bundle integrity and canonical firewall rendering.

Raw logs, VM disks, bundle bytes, SSH keys and the RKE2 token remain below
`.context` and are excluded from Git.

On this workstation only, two unrelated registered VirtualBox machines returned
`E_ACCESSDENIED` during Vagrant's global port enumeration. The isolated Vagrant
copy used a local guarded change in `version_5_0.rb` from SHA256
`5a42c2ccd7eaf9f80ae6035ba25d351ca39994a4602a6cf422a44c09944d5346` to
`3bc0f100081ecb212971d89677d8d9aa4d358fad97ee9701429fc1e1e89cb18d`,
limited to ignoring access-denied VMs while reading used ports. That host-specific
change is not part of the repository fixture and must not be inferred as a general
Vagrant requirement.

## Remaining acceptance

This run does not validate multi-node joining, three-member etcd quorum, workers,
node loss, rolling behavior, simultaneous platform capacity, real internal
DNS/NTP/artifact services, or the six target machines. Those gates remain pending
on the authorized real environment.
