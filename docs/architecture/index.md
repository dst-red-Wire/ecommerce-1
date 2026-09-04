# Architecture index

La source de gouvernance canonique est
[`governance/controls.yaml`](../../governance/controls.yaml). Les diagrammes
Markdown/Mermaid sont des vues versionnées ; aucun `.drawio` n'est une source
de vérité unique.

## Vues

- [System context et trust boundaries](system-context.md)
- [DevSecOps delivery](devsecops-delivery.md)
- [Environment model](environments.md)
- [Terraform PostgreSQL backend](terraform-state-backend.md)
- [Threat model global](threat-model.md)
- [ADR production HTTP/3 / QUIC](adr-http3-production-edge.md)
- [Security governance](../security/governance.md)

## Runtime proof matrix

Cette matrice est verrouillée par le validator. Les preuves `PROVEN_RUNTIME`
préexistent au milestone repository-only ; leur artifact est conservé hors Git.

| capability | status |
|---|---|
| remote identity | `PROVEN_RUNTIME` |
| volume attachment | `PROVEN_RUNTIME` |
| volume mount | `PROVEN_RUNTIME` |
| PostgreSQL | `PROVEN_RUNTIME` |
| TLS | `PROVEN_RUNTIME` |
| SCRAM | `PROVEN_RUNTIME` |
| PGDATA | `PROVEN_RUNTIME` |
| Ansible idempotence | `PROVEN_RUNTIME` |
| Terraform PG backend | `PROVEN_RUNTIME` |
| Terraform PG locking | `PROVEN_RUNTIME` |
| reboot persistence | `PROVISIONAL_RUNTIME_PASS` |
| HTTP/3 production edge | `NOT_PROVEN_RUNTIME` |
| Management backend | `NOT_MIGRATED` |

Le contrôle `OBS-002` interdit de déduire une preuve runtime d'une compatibilité
documentaire ou d'une validation statique.
