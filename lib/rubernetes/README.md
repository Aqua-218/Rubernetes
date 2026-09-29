# Production Ruby Module Boundaries

> **Audience:** Implementers and reviewers

Production policy, state machines, resource ownership, codecs, controllers, schedulers,
and node lifecycle logic live below this directory. Dependency direction is enforced by
the project-structure specification and may not be inverted for convenience.

| Directory | Responsibility |
|---|---|
| `bootstrap/` | Process configuration, dependency assembly, lifecycle, signal handling |
| `schema/` | Schema DSL, registry, compiler, validation, defaulting, codecs |
| `api/` | HTTP routing, authn/authz, admission, patch/apply, discovery, watch |
| `storage/` | Store contract, memory store, durable object persistence |
| `consensus/` | Raft log, replication, membership, snapshot and recovery |
| `watch/` | Watch cache, informer, indexes, work queues |
| `controller/` | Controller DSL and built-in reconcilers |
| `scheduler/` | Scheduling framework, plugins, binding and preemption |
| `node/` | Node registration, Pod SyncLoop, probes, restart and eviction |
| `image/` | OCI distribution, verification, unpack and layer cache |
| `runtime/` | Runtime contract plus `native/` and `microvm/` backends |
| `network/` | Netlink, IPAM, datapath, policy and DNS |
| `proxy/` | Service proxy with eBPF and nftables backends |
| `volume/` | Volume lifecycle, projected data, PV/PVC and CSI compatibility |
| `security/` | Identity, policy, audit and secret-handling primitives |
| `observability/` | Structured events, metrics, traces and evidence export |
| `platform/linux/` | Typed Linux UAPI adapters over the native extension boundary |
| `support/` | Shared primitives with no domain-policy ownership |

## Related

- [Project structure](../../spec/delivery/project-structure.md)
- [Architecture](../../spec/foundation/architecture.md)
- [Coding standards](../../spec/delivery/coding-standards.md)

