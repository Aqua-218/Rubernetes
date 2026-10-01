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

## Dashboard (apps/dashboard)

A Rails 8 application that is both the cluster's web UI and its Prometheus:
it browses nodes, namespaces, workloads, Pods (logs, YAML, delete, scale,
rollout restart), events and alerts, and it scrapes every API server, every
kubelet endpoint (`/metrics`, `/metrics/cadvisor`, `/metrics/resource`,
`/metrics/probes`), Pods and Services annotated `prometheus.io/scrape`, and a
built-in kube-state exporter into its own time-series store.  The store is
Prometheus-shaped (Gorilla-compressed chunks, a write-ahead log, 2h blocks,
time-based retention, a SQLite label index) and the query language is PromQL
(selectors with offset/@, range vectors, subqueries, the aggregation and
function set, vector matching with on/ignoring/group_left/right, set
operators).  Recording and alerting rules use the Prometheus rule-file format
(`apps/dashboard/config/rules.yml`), with pending/firing/resolved state,
`ALERTS` series and Alertmanager-style webhook notifications.  The HTTP API is
Prometheus-compatible (`/api/v1/query`, `query_range`, `series`, `labels`,
`targets`, `rules`, `alerts`, `metadata`, `status/*`), so Grafana can point at
it.

```sh
cd apps/dashboard && bin/rails test                     # 69 tests
RUBERNETES_KUBECONFIG=/srv/rbn-app/linux-amd64-ipv4-native/kubeconfig bin/rails server -p 3000
```

`apps/dashboard/deploy/` holds a systemd unit, its environment file and an
Ingress manifest that publishes the host-run dashboard through the cluster's
ingress controller.  Configuration is entirely environment variables
(`DASHBOARD_PASSWORD`, `DASHBOARD_RETENTION`, `DASHBOARD_SCRAPE_INTERVAL`,
`DASHBOARD_RULES`, `DASHBOARD_ALERT_WEBHOOK`, `DASHBOARD_ALLOW_WRITES`, ...);
see `apps/dashboard/lib/dashboard/config.rb`.
