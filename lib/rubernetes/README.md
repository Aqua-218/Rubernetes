# Production Ruby Module Boundaries

For implementers and reviewers.

The production code lives below this directory: policy, state machines,
resource ownership, codecs, controllers, schedulers and node lifecycle
logic. The project-structure specification fixes the direction of
dependencies between these directories. Do not invert it for convenience.

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
| `transport/` | HTTP/1.1 and HTTP/2 server and socket adapters for the API process boundary |
| `client/` | Kubernetes API client, kubeconfig loading and output formatting |
| `rubectl/` | The `rubectl` command line |
| `manifest/` | Ruby Manifest DSL builder and the sandbox that evaluates it |
| `dra/` | Dynamic Resource Allocation: the structured allocator and its CEL device selectors |
| `metrics_server/` | The `metrics.k8s.io` API and its storage |

## Related

- [Project structure](../../spec/delivery/project-structure.md)
- [Architecture](../../spec/foundation/architecture.md)
- [Coding standards](../../spec/delivery/coding-standards.md)

