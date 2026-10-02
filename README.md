# Rubernetes

English | [日本語](README.ja.md)

Rubernetes is a reimplementation of Kubernetes v1.36.2 in Ruby. It runs on
Linux. A real `kubectl`, Helm, client-go and upstream charts work against it
unchanged.

Every program in a cluster is Ruby code from this repository: the API
server, the Raft datastore, the controllers, the scheduler, the node agent,
the container runtime, the Pod network, the service proxy, cluster DNS and
the volume path.

How it relates to Kubernetes itself:

- Nothing from Kubernetes runs inside a cluster.
- Kubernetes binaries and images are used only as the reference that tests
  compare against. Their versions are pinned.
- The API schema is imported from upstream. Some algorithms (server-side
  apply, CEL type checking, the DRA allocator, the device cgroup filter and
  others) are Ruby ports of the upstream Go code. [`NOTICE`](NOTICE) lists
  each port with its origin and license.

| | |
|---|---|
| Compatibility target | Kubernetes v1.36.2 |
| Official Conformance | 459 of 459 passed (2026-09-30, IPv4 profile) |
| Target environment | Linux x86_64, cgroup v2, root, Ruby 3.4.11 |
| Size | about 220 k lines of Ruby and C under `lib/` and `ext/`, 100 k lines of tests |
| License | Apache-2.0 |

The Conformance result comes from the unmodified `registry.k8s.io/conformance`
image, run through Hydrophone against the `linux-amd64-ipv4-native` profile.

This README is the practical entry point. The specification and design
documents are in [`spec/`](spec/README.md) (Japanese).

## Components

There are six executables, plus a dashboard.

| Executable | Kubernetes counterpart |
|---|---|
| `rubernetes-apiserver` | kube-apiserver and etcd |
| `rubernetes-controller-manager` | kube-controller-manager |
| `rubernetes-scheduler` | kube-scheduler |
| `rubernetes-agent` | kubelet, a CRI runtime and CNI |
| `rubernetes-proxy` | kube-proxy |
| `rubectl` | a subset of kubectl |
| `apps/dashboard` | Kubernetes dashboard and Prometheus |

At runtime a cluster needs Ruby and one small C extension. Some syscalls
cannot be made safely from a forking Ruby VM, and
[`ext/rubernetes_linux`](ext/README.md) makes those.

### rubernetes-apiserver

Serves the whole default API surface and discovery of v1.36.2:

- JSON, YAML and Protobuf
- watch, patch, and server-side apply with field managers
- admission plugins, webhooks and CEL policies
- authentication and authorization, API Priority and Fairness, audit,
  encryption at rest
- CRDs and API aggregation
- feature gates and `--runtime-config`

Data is stored in the built-in Raft datastore under
`lib/rubernetes/consensus/`. It has a CRC-32C WAL, snapshots, joint
consensus, pre-vote, ReadIndex and mutual TLS.

### rubernetes-controller-manager

Runs the upstream controller set: workloads, garbage collection, namespaces,
Endpoints and EndpointSlice, service accounts and tokens, node lifecycle,
CSR approval, PV and PVC, quota and the rest. The controllers sit on an
informer and work-queue framework with leader election.

### rubernetes-scheduler

Implements the scheduling framework with the default plugin set, including
preemption, asynchronous binding and scoring.

### rubernetes-agent

Does the kubelet's job: the Pod sync loop, probes, eviction, graceful node
shutdown, device plugins, the CPU, memory and topology managers, and DRA. It
also serves the kubelet API (`exec`, `logs`, `/metrics`, `/configz` and so
on).

There are three container runtimes:

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
rake lint                        # RuboCop, strict Layout/Style, 160 columns, double quotes
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
- **Duck typing is deliberate.** Every RuboCop cop that is off is listed in
  `.rubocop.yml` with the reason, most of them because their autocorrect
  assumes a concrete receiver type (`grep` on a Struct, `partition` on a
  Hash, `empty?` on a `File::Stat`). `rake lint` must stay clean; there is
  no todo file. Format-only commits are listed in `.git-blame-ignore-revs`.
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
- **Lint.** `rake lint` runs clean over the whole tree with no todo file;
  the cops that are off are listed in `.rubocop.yml` with the reason
  (mostly ones whose autocorrect assumes a concrete receiver type).

## Documentation

- [Specification index](spec/README.md) and [architecture](spec/foundation/architecture.md)
- [Milestones and completion gates](spec/delivery/milestones.md)
- [Kubernetes compatibility contract](spec/verification/kubernetes-compatibility.md)
- [Coding standards](spec/delivery/coding-standards.md) and [project structure](spec/delivery/project-structure.md)
- [Operating a cluster](deploy/cluster/README.md)
- [Conformance tooling](tools/conformance/README.md) and [milestone gates](tools/milestones/README.md)

## License

Apache License 2.0. See [LICENSE](LICENSE).
