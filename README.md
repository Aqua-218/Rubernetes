# Rubernetes

Rubernetes is an independent, Ruby-first implementation of Kubernetes
v1.36.2 for Linux: the API server, the Raft datastore, the controllers,
the scheduler, the node agent with its own container runtime, the Pod
network, the service proxy, cluster DNS and the volume path are all
project-owned Ruby. Kubernetes code is used only as a pinned test oracle,
never as a dependency. A cluster speaks the Kubernetes API unchanged, so
`kubectl`, Helm, client-go and upstream charts work against it as they are.

| | |
|---|---|
| Kubernetes contract | v1.36.2 (`status.nodeInfo.kubeletVersion` reports it) |
| Latest full Conformance run | 459 / 459 passed, 2026-09-30, `linux-amd64-ipv4-native`, unmodified `registry.k8s.io/conformance` image via Hydrophone |
| Target | Linux x86_64, cgroup v2, root. Ruby 3.4.11 |
| Size | about 220 k lines of Ruby and C under `lib/` and `ext/`, 100 k lines of tests |
| License | Apache-2.0 |

The normative specification lives in [`spec/`](spec/README.md) (Japanese);
this README is the practical entry point.

## What is in the box

| Rubernetes process | Stands in for | Notes |
|---|---|---|
| `rubernetes-apiserver` | kube-apiserver + etcd | Full v1.36.2 default API surface and discovery, JSON/YAML/Protobuf, watch, patch, server-side apply with field managers, admission (plugins from the pinned corpus, webhooks, CEL policies), authn/authz, API Priority and Fairness, audit, encryption at rest, CRDs, API aggregation, feature gates and `--runtime-config`. Storage is the built-in Raft datastore (`lib/rubernetes/consensus/`): CRC-32C WAL, snapshots, joint consensus, pre-vote, ReadIndex, mutual TLS. |
| `rubernetes-controller-manager` | kube-controller-manager | The upstream controller set (workloads, GC, namespace, endpoints and EndpointSlice, service accounts and tokens, node lifecycle, CSR approval, PV/PVC, quota, …) on an informer/work-queue framework with leader election. |
| `rubernetes-scheduler` | kube-scheduler | The scheduling framework with the default plugin set, preemption, async binding, scoring. |
| `rubernetes-agent` | kubelet + CRI runtime + CNI | Pod sync loop, probes, eviction, graceful node shutdown, device plugins, CPU/memory/topology managers, DRA, kubelet API (`exec`, `logs`, `/metrics*`, `/configz`, …). Runtimes: **native** (clone3, cgroup v2, namespaces, OCI images pulled and verified in Ruby), **microvm** (Firecracker with jailer, dm-verity rootfs, vsock supervisor) and an opt-in **CRI** backend. Networking is a built-in bridge datapath with dual-stack IPAM, NetworkPolicy (nftables or eBPF), egress NAT and an in-process cluster DNS. |
| `rubernetes-proxy` | kube-proxy | Service, EndpointSlice, NodePort, session affinity, traffic policies; **iptables**, **nftables** and **eBPF** datapaths with the upstream chain layout and metrics. |
| `rubectl` | kubectl (subset) | `get`, `create`, `apply`, `patch`, `delete`, `watch`, `raw`; a Ruby Manifest DSL compiled from the schema corpus. Any real `kubectl` works too. |
| `apps/dashboard` | Kubernetes dashboard + Prometheus | A Rails application: cluster browser, its own Prometheus-shaped time-series store, PromQL, recording and alerting rules, a Prometheus-compatible HTTP API. See [its README](apps/dashboard/README.md). |

Everything a cluster needs at runtime is Ruby plus one small C shim
([`ext/rubernetes_linux`](ext/README.md)) for the syscalls that cannot be
made safely from a forking Ruby VM.

## Quick start

Requirements: Linux x86_64 with cgroup v2, root, `nft` and `iptables`
installed, Ruby 3.4.11 (the Gemfile pins it), outbound access to pull
images, and a `kubectl` v1.36.2 at `build/tools/kubectl-v1.36.2` (its
checksum is in `test/compatibility/clients/matrix.yml`). KVM is only needed
for the `microvm` RuntimeClass.

```sh
git clone <this repository> && cd 2026
bundle install
rake abi:compile                    # builds the C shim under build/

# A 3 control-node + 3 worker cluster on this host, with PKI, bootstrap
# per-component identities, cluster DNS and a kubeconfig, all under /srv/rbn-dev:
sudo -E ruby tools/conformance/cluster.rb up --profile linux-amd64-ipv4-native --root /srv/rbn-dev

export KUBECONFIG=/srv/rbn-dev/linux-amd64-ipv4-native/kubeconfig
kubectl get nodes
kubectl create deployment web --image=nginx --replicas=3
kubectl expose deployment web --port=80 --type=NodePort
kubectl get pods -o wide

sudo ruby tools/conformance/cluster.rb status --root /srv/rbn-dev
sudo ruby tools/conformance/cluster.rb down   --root /srv/rbn-dev
```

`cluster.rb` is also what the conformance runs use, so it is the reference
for a correct configuration (`<root>/<profile>/cluster.json` lists every
process, port and file). Two things to know before running it on a shared
host: `up` kills workloads under `<RUBERNETES_M8_CGROUP_ROOT>/rubernetes`
(default `/sys/fs/cgroup/rubernetes`), removes stale `rbn*` bridges and
`rbn-*` network namespaces in its network namespace, and refuses
to start while another cluster from a different root is alive in the same
network namespace. To run several clusters on one host, give each its own
network namespace with `tools/conformance/netns_env.sh`; the recipe is in
[tools/conformance/README.md](tools/conformance/README.md).

For a long-lived installation from release artifacts (systemd units, PKI,
upgrade, backup and restore procedures) read
[deploy/cluster/README.md](deploy/cluster/README.md). Each daemon takes one
YAML file (`--config`, validated by `--check-config`) and nothing from the
environment; `config/defaults/` holds the versioned defaults.

### Dashboard and metrics

```sh
cd apps/dashboard && bundle install
RUBERNETES_KUBECONFIG=$KUBECONFIG bin/rails server -p 3000
```

Open `http://localhost:3000`. The dashboard scrapes every API server,
kubelet endpoint and annotated Pod/Service into its own store, so it is also
a Prometheus data source for Grafana (`/api/v1/query` and friends).

## Repository layout

| Path | Contents |
|---|---|
| [`lib/rubernetes/`](lib/rubernetes/README.md) | Production code, one directory per subsystem (`api/`, `consensus/`, `controller/`, `scheduler/`, `node/`, `runtime/`, `network/`, `proxy/`, `volume/`, `security/`, `schema/`, `observability/`, …) |
| [`exe/`](exe/README.md) | The six executables; they parse options and hand over to `lib/rubernetes/bootstrap` |
| [`ext/rubernetes_linux/`](ext/README.md) | The C ABI shim (`clone3` + exec, typed syscalls); no policy lives here |
| `schema/` → `generated/` | The imported Kubernetes v1.36.2 schema, OpenAPI and defaults corpus, and the reproducible Ruby types, RBS, codecs and Manifest DSL compiled from it. `generated/` is never hand-edited |
| [`spec/`](spec/README.md) | The normative specification and design documents |
| [`test/`](test/README.md) | Unit, property, integration, e2e, chaos, security and compatibility suites, plus the conformance harness profiles |
| [`tools/`](tools/README.md) | Ruby automation: schema import and generation, conformance (`cluster.rb`, lanes, Hydrophone), milestone probes and gates, formal verification runners, release artifacts, the commit recorder |
| [`verification/`](verification/README.md) | TLA+ and Lean models (Raft, runtime lifecycle, bounded framing, KV sequential spec) and trace schemas |
| [`third_party/locks/`](third_party/locks/README.md) | Every upstream source, image, runner binary and build input, pinned by commit and digest |
| [`deploy/`](deploy/cluster/README.md) | systemd units and operator procedures |
| [`apps/dashboard/`](apps/dashboard/README.md) | The Rails dashboard / metrics server |
| `benchmarks/`, `artifacts/` | Benchmarks and (ignored) evidence bundles |

## Development

```sh
bundle install
rake abi:compile                 # once, and after touching ext/
rake test:parallel               # whole suite, one process per file; JOBS=n sets the width (~6 min)
rake test                        # the serial run the evidence gates use (~1 h)
ruby -Ilib -Itest test/unit/some_test.rb -n /pattern/
rake lint                        # RuboCop, strict Layout/Style, 140 columns, double quotes
rake lint:fix                    # safe autocorrect only; re-run the tests afterwards
rake rbs:validate                # hand-authored RBS baseline
```

Conventions that matter:

- **The schema corpus is the source of truth for types.** Do not hand-write
  Kubernetes types; change the importer or generator under `tools/schema/`
  and regenerate. Generated output must be byte-reproducible.
- **Behaviour is checked against upstream, not against our own reading of
  it.** New API, controller, scheduler or kubelet behaviour gets a
  differential or oracle test against the pinned Kubernetes binaries or
  images where one is possible, and otherwise a test derived from the
  upstream test it mirrors.
- **No silent skips.** A missing adapter, kernel feature or external runner
  is reported as `INCOMPLETE` or an error, never as a pass. Waivers are
  recorded by name and reason (see the kernel waiver in
  [tools/milestones/README.md](tools/milestones/README.md)).
- **Duck typing is deliberate.** Several RuboCop cops that assume a concrete
  receiver type are disabled in `.rubocop.yml` with the reason; historical
  offenses are parked in `.rubocop_todo.yml` and burned down by hand.
  Format-only commits are listed in `.git-blame-ignore-revs`.
- **After adding a `require` under `lib/`, load the whole library once**
  (`ruby -Ilib -e 'require "rubernetes"'`); a bad `require_relative` only
  shows up in the process that needs it.
- **Commits are recorded, not written.** `rake repo:commit` (or
  `ruby tools/repo/auto_commit.rb --cycle <name> --status 0`) turns the work
  tree into one commit per contiguous edit, named after the declaration it
  lands in, sources before tests before docs, published with a
  compare-and-swap on HEAD. It commits unstaged changes as well, so stash
  what should not land. No trailers are added beyond the author.

## Verification

Four layers, each with its own tooling:

1. **Tests** (`rake test`): about 3,400 test cases across unit, property,
   integration, chaos and security suites, plus Go-oracle differentials for
   codecs, validation, server-side apply, controllers and the scheduler.
2. **Kubernetes Conformance and compatibility lanes**
   ([tools/conformance](tools/conformance/README.md)): K0 input integrity,
   K1 the official Conformance suite through Hydrophone, K2 Sonobuoy
   certified-conformance, K3 the full e2e inventory under the selection
   ledger (`test/compatibility/api/selection-ledger.json`, 7,579 specs
   classified), K4 node conformance, K5 differential against a real
   kube-apiserver, K6 a corpus of 32 pinned upstream Helm charts and
   operators, K7 cluster lifecycle. Profiles: IPv4, IPv6 and dual-stack,
   three control nodes and three workers each
   (`test/conformance/kubernetes/profiles.yml`).
3. **Formal models** ([verification/](verification/README.md)): Raft and the
   runtime lifecycle in TLA+ (TLC, Apalache) and Lean, tied to the
   implementation by traces replayed from the production journals, and a
   linearizability checker over real client histories.
4. **Milestone evidence gates** ([tools/milestones](tools/milestones/README.md)):
   M0 (executable foundation) through M9 (release) each produce a
   content-addressed bundle that a strict gate re-checks; the chain is
   cumulative and any source change invalidates it. `rake m<n>:evidence`,
   `rake m<n>:verify`.

## Status and known limitations

Honest list, as of 2026-10-01:

- **Platform.** Linux x86_64 only. arm64 is untested. Kernel 6.8+ is
  exercised; one M4 check (an SCTP CRC32c helper) wants 6.12 and is waived
  explicitly on older kernels.
- **Networking.** The Pod network is the built-in bridge datapath; external
  CNI plugins are not executed. IPv6-only clusters have no NAT64. There are
  no cloud-provider integrations (LoadBalancer Services stay pending unless
  something external programs them, as on bare metal).
- **Scale.** Everything that has been measured ran as a multi-node cluster
  on one host (three control nodes, three workers). Multi-host operation is
  configured through the same YAML but has not been exercised end to end.
- **Metrics.** Component `/metrics` mirror the upstream families, including
  cadvisor and kube-proxy ones. 27 apiserver and 2 kubelet families that
  describe Go runtime internals or features Rubernetes has no equivalent
  of are registered with an explicit "not implemented" help string and are
  always empty, so a dashboard built for upstream still loads.
- **Alpha APIs** are served only when enabled through `--runtime-config`,
  as upstream. Most alpha feature gates have no behaviour behind them.
- **Evidence bundles** on disk predate the latest source changes and are
  therefore stale by construction; the gates and the Conformance suite have
  been re-run on the current tree, but a release candidate must re-capture
  the whole M0–M9 chain.
- **Lint debt.** About 3,000 historical RuboCop offenses remain in
  `.rubocop_todo.yml` (mostly line length); new code must be clean.

## Documentation

- [Specification index](spec/README.md) and [architecture](spec/foundation/architecture.md)
- [Milestones and completion gates](spec/delivery/milestones.md)
- [Kubernetes compatibility contract](spec/verification/kubernetes-compatibility.md)
- [Coding standards](spec/delivery/coding-standards.md) and [project structure](spec/delivery/project-structure.md)
- [Operating a cluster](deploy/cluster/README.md)
- [Conformance tooling](tools/conformance/README.md) and [milestone gates](tools/milestones/README.md)

## License

Apache License 2.0. See [LICENSE](LICENSE).
