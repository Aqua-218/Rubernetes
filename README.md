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

M3 and M4 verification are cumulative. M3 requires COMPLETE M0, M1, and M2 bundles captured from
the same source inventory; M4 additionally requires COMPLETE M3. Source changes invalidate the
previous digest and force a fresh evidence chain.

```bash
RUBERNETES_M3_M2_MANIFEST=artifacts/milestones/M2/<run-id>/manifest.json rake m3:verify
RUBERNETES_M4_M3_MANIFEST=artifacts/milestones/M3/<run-id>/manifest.json rake m4:verify
```

`rake m3:evidence` writes controller/scheduler/leader/watch reports below
`artifacts/milestones/M3/`; `rake m4:evidence` writes network/policy/proxy/volume/mount reports
below `artifacts/milestones/M4/`. Both runners record host/kernel/Ruby identity, timestamps,
commands, result counts, artifact digests, source-input stability, and a zero Git-metadata check.

## Project Boundaries

- [`lib/rubernetes/`](lib/rubernetes/README.md) owns production Ruby policy and state machines.
- [`ext/rubernetes_linux/`](ext/README.md) is limited to ABI shims that Ruby FFI cannot express safely.
- [`schema/`](schema/README.md) is compiler input; [`generated/`](generated/README.md) is reproducible output and is never hand-edited.
- [`test/`](test/README.md) separates unit, integration, upstream Conformance, compatibility, chaos, security, and performance evidence.
- [`verification/`](verification/README.md) contains TLA+, Lean, and implementation-trace artifacts.
- [`tools/`](tools/README.md) contains Ruby-first schema, conformance, verification, and release automation.
- [`third_party/locks/`](third_party/locks/README.md) pins every upstream source, runner, binary, and image by digest.
- [`exe/`](exe/README.md) reserves thin process entry points without shipping false-success stubs.

## Related

- [Specification entry](spec.md)
- [Architecture](spec/foundation/architecture.md)
- [Coding standards](spec/delivery/coding-standards.md)

## M8 — Kubernetes compatibility

`tools/conformance/run.rb` executes the K0–K7 lanes from
[the compatibility contract](spec/verification/kubernetes-compatibility.md) and
writes a run manifest per profile. A lane whose prerequisites are missing
reports `INCOMPLETE` with the reason; it never substitutes a mock or reuses
another run's result, and the M8 gate rejects any `INCOMPLETE` lane.

- `test/compatibility/api/selection-ledger.json` classifies all 7 579 upstream
  e2e specs (5 644 required, 992 platform-inapplicable, 924 provider-private,
  19 implementation-internal) with zero unclassified and zero unlinked external
  contracts, generated from a real Ginkgo dry-run by
  `tools/conformance/build_selection_ledger.rb`.
- `test/compatibility/projects/corpus.yml` pins 32 upstream projects (32 Helm
  charts, 21 operators, 19 with CRD+webhook, 12 with StatefulSet+PVC) covering
  all nine required domains; every chart carries the SHA-256 of the archive
  pulled and all 78 images are pinned by registry digest.
- `test/compatibility/clients/matrix.yml` pins kubectl v1.35.8, v1.36.2 and
  v1.37.0 by their published checksums, covering the whole supported skew.

`rake m8:lanes` runs the lanes, `rake m8:evidence` captures the bundle and
`rake m8:verify` gates it.

## M9 — Release

`tools/release/` produces the release evidence: `sbom.rb` (CycloneDX 1.5,
deterministic), `release_manifest.rb` (binds the source inventory digest),
`loc_report.rb` (Ruby ratio, counting the native extension), `reproduce.rb`
(byte-identical rebuild), `security_report.rb` (advisories, unpinned inputs,
claim levels, undated markers), `benchmark.rb` (against a Kubernetes v1.36.2
oracle) and `soak.rb` (72 hours, append-only journal).

A soak shorter than 72 hours, a benchmark with no oracle, or a missing
clean-host reproduction is reported as not satisfied rather than passed.
`rake m9:artifacts` generates the artifacts, `rake m9:verify` gates them.

## Repository recording

The work tree is recorded into commits by `tools/repo/auto_commit.rb`, a
recorder that never asks for a message: every contiguous edit becomes one
commit named after the declaration it lands in (`feat(node): extend start`),
a new or deleted file becomes one commit, and generated records report their
status transition and headline field changes.  Sources are committed before
tests, tools, docs and generated output.  The snapshot is taken once into a
scratch index, written as a single `git fast-import` stream and published with
a compare-and-swap on HEAD, so a run that overlaps another commit retries
instead of clobbering, and an interrupted run leaves the repository untouched.
The author is whoever `git var GIT_AUTHOR_IDENT` names; no other trailer is
added.

```sh
rake repo:commit                              # record everything, one commit per edit
AUTO_COMMIT_ARGS="--granularity file" rake repo:commit
rake "repo:record[test:parallel]"             # run the task, then record with Cycle: trailers
ruby tools/repo/auto_commit.rb --dry-run -v   # preview the commits without making them
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
