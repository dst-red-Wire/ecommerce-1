# PROD TOPOLOGY V2 — EXACT

Status: `EXACT`

This document is the authoritative physical/logical PROD topology for build and certification. It supersedes older planning references to five physical hosts per site. The later locked certification decision and current topology use six final/equivalent physical hosts total: three independent physical failure domains in PROD-A and three in PROD-B.

## Sites

- PROD-A: `a-host-01`, `a-host-02`, `a-host-03`
- PROD-B: `b-host-01`, `b-host-02`, `b-host-03`

Each physical host is an independent failure domain. Hardware must meet or exceed the certified BOM used in M8. Any material change to BOM, storage allocation, worker topology or certified capacity invalidates the hardware certificate and triggers recertification.

## RKE2 logical layout per site

Each site runs:

- 3 control-plane VMs: one per physical host;
- 3 data-worker VMs: one per physical host;
- 2 general-worker VMs: placed on different physical hosts;
- total: 3 control planes + 5 workers.

### Deterministic placement PROD-A

| Physical host | VMs |
|---|---|
| a-host-01 | `a-cp-01`, `a-data-01`, `a-general-01`, `a-gw-01`, edge role 1 |
| a-host-02 | `a-cp-02`, `a-data-02`, `a-general-02`, `a-gw-02`, edge role 2 |
| a-host-03 | `a-cp-03`, `a-data-03`, reserve capacity for failure/rebalance and site services |

### Deterministic placement PROD-B

| Physical host | VMs |
|---|---|
| b-host-01 | `b-cp-01`, `b-data-01`, `b-general-01`, `b-gw-01`, edge role 1 |
| b-host-02 | `b-cp-02`, `b-data-02`, `b-general-02`, `b-gw-02`, edge role 2 |
| b-host-03 | `b-cp-03`, `b-data-03`, reserve capacity for failure/rebalance and site services |

The third host intentionally retains more headroom so loss/rebalancing tests are not designed around 100% steady-state saturation.

## Worker classes

### Data workers — 3/site

Baseline VM profile:

- 16 vCPU
- 64 GiB RAM
- dedicated raw/local NVMe data devices according to storage contract
- one per physical failure domain

Data workers preferentially host CNPG, Kafka brokers, SeaweedFS volume servers and other stateful workloads using node affinity/anti-affinity.

### General workers — 2/site

Baseline VM profile:

- 8 vCPU
- 32 GiB RAM
- application/general platform workloads

Critical workloads still use PDB, anti-affinity and topology spread. General worker loss must not remove site control-plane quorum or authoritative data replicas.

## Control planes

Baseline profile:

- 8 vCPU
- 16 GiB RAM
- 100 GiB OS disk
- one per physical host

Do not co-locate multiple control-plane VMs on one physical failure domain.

## Gateways

Two gateway VMs/site:

- Linux
- WireGuard
- FRR
- nftables

GW is a distinct role from Edge. `gw-01` and `gw-02` are strictly anti-affine.

## Edge

Two edge instances/site provide the approved public chain roles required by the routing design. They are strictly anti-affine and attach to EDGE-DMZ and internal routing networks as required.

API path:

`Internet -> DNS/GSLB -> HAProxy -> Caddy+Coraza -> Kong -> Istio Gateway -> services`

Web/CDN:

- `www -> ATS -> Storefront`
- `cdn -> ATS -> SeaweedFS S3/assets`

## Stateful per site

- CNPG/PostgreSQL: local site clusters, single-writer authority by aggregate/home_site; no global multi-writer.
- Kafka: Strimzi KRaft, 3 controllers + 3 brokers/site, RF=3, minISR=2 for critical topics.
- RabbitMQ: 3-node Quorum Queue topology/site.
- Redis Cluster: local/site, non-authoritative.
- OpenSearch: rebuildable search/read models.
- SeaweedFS: 3 masters, 3 volume servers across the 3 data workers, >=2 filers, >=2 S3 gateways.

MirrorMaker2 carries approved Kafka replication between sites. Object replication/backup follows the storage/DR contract. Replication never grants write authority.

## Multi-site write authority

Every write-owned aggregate has `home_site` authority. Site failover requires:

`health evidence -> quorum/fencing -> write authority decision -> stateful promotion/recovery -> application routing -> DNS/GSLB change`.

DNS/GSLB must never lead the failover sequence.

## M8 hardware certification scenario

The six physical hosts above, or six strictly equivalent reserved hosts, are the certification target.

Required sequence includes:

1. baseline all six hosts;
2. fence Site A;
3. drive full target load on Site B;
4. lose the most-loaded physical host in Site B;
5. validate continuity/capacity/data integrity;
6. reconstruct;
7. execute symmetric scenario with B fenced and A surviving.

External load generators and temporary performance workers do not count toward the certified minimum.

## Supersession

Historical planning references to `5 hosts/site` are `SUPERSEDED` by this exact six-host certification topology. They may remain in historical documents only when clearly marked superseded.
