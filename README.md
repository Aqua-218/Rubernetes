# Rubernetes

> **Status:** M0 through M7 are implemented and content-addressed evidence-gated for the x86_64 release target. Cumulative completion is established only by the latest M7 bundle that passes every M0–M7 gate on one identical source input with all required real adapters and external runners; the single host-bound exception (Linux >= 6.12) is recorded as an explicit waiver in the M4 bundle it carries.

Rubernetes specifies an independent, Ruby-first implementation of the externally observable
Kubernetes v1.36.2 contract for Linux clusters. The implementation boundary assigns the
control plane, node agent, native container runtime, network, service proxy, and volume path
to project-owned code; Kubernetes implementation code is permitted only as a pinned test oracle.

## Source of Truth

- [Normative specification](spec/README.md)
- [Milestones and completion gates](spec/delivery/milestones.md)
- [Annotated project structure](spec/delivery/project-structure.md)
- [Kubernetes compatibility test contract](spec/verification/kubernetes-compatibility.md)

## Current Implementation

The source tree contains substantial M0 executable-foundation, M1 schema/API-core, M2 Native-Pod,
M3 control-loop, and M4 workload-data-plane implementation. M1 imports the
pinned Kubernetes v1.36.2 schema corpus, generates the registry, Ruby types, RBS, OpenAPI, codecs,
patch metadata, and Manifest DSL, and provides a single-node API with MVCC storage, CRUD, watch,
patch, server-side apply, discovery, and `rubectl` kubeconfig/raw REST/apply paths. Generated output
is reproducible and the JSON/Protobuf codecs, API behavior, and CLI paths are checked against pinned
Kubernetes oracles. M2 adds verified OCI pull/extraction and digest pinning, the Native runtime state
machine and ownership journal, Node registration/sync/lifecycle policy, recovery reconciliation,
subresource service contracts, formal lifecycle models, and strict evidence adapters. Host-capable
profiles require explicit kernel-effect adapters and fail before readiness when those capabilities
are unavailable; unit or fake-I/O success is never promoted to L3 evidence. M3 adds the built-in
controller registry, reconcile idempotency, scheduler framework/oracles, leader-election fencing,
and informer/queue properties. M4 adds dual-stack IPAM/topology/DNS, NetworkPolicy, service-proxy
backend parity, volume lifecycle and projected-volume atomicity, plus descriptor-relative mount
attack checks. These modules are measured by production-module probes; an unavailable adapter
remains INCOMPLETE rather than becoming a successful skip.
M5 adds the durable Raft datastore (`lib/rubernetes/consensus/`): a CRC-32C write-ahead log
with explicit torn-tail recovery, verified snapshots, joint-consensus membership changes,
pipelined and batched replication, pre-vote, ReadIndex linearizable reads, snapshot transfer,
a mutually authenticated TLS transport whose peer identity comes from the certificate, a
RaftStore that implements the Store contract for the API server (`datastore: {type: raft}`),
backup/restore, and a durable client-side operation journal that distinguishes request loss
from response loss at every effect point.
Formal completion is determined only by the evidence gates in the milestone specification.

## 2026-09-04/05 Verification Note

An independent audit on 2026-09-04 found the 2026-08-23 `COMPLETE` bundles rejected by the
current gates. Over 2026-09-04 and 2026-09-05 the following were fixed and verified on this tree:

- M1: the Kubernetes validation oracle maps every generated type (770/770) to an executable
  upstream REST strategy, the round-trip probe reports zero mismatches, and the API differential
  against the pinned kube-apiserver/etcd covers all 22 required operations including the virtual
  endpoints (TokenReview, SelfSubjectReview, SelfSubjectRulesReview, SubjectAccessReview,
  ComponentStatus, Pod eviction).
- M2: Pod lifecycle observables (init ordering, probe thresholds, restart back-off, graceful
  termination) match the real Kubernetes v1.36.2 node oracle (kind node image built from the
  pinned source) with zero differences. The RuntimeLifecycle formal claim is now discharged on a
  trace replayed from the production Native runtime's hash-chained ownership journal (one real L3
  lifecycle plus one real effect-point failure injection, kernel facets from the procfs/mountinfo/
  fdinfo observer), checked by the Ruby trace verifier, TLC, Apalache (safety) and Lean under a
  deterministic proof profile (`verification/proof-profile.json`, regenerated with
  `tools/verification/m2_proof_profile.rb`). The Native runtime now records `Stopping` only after
  every workload process is confirmed dead and keeps process ownership until cleanup in `Stopped`,
  exactly as `RuntimeLifecycle.tla` specifies.
- M3: the workload differential runs all 20 cases (Deployment, StatefulSet, DaemonSet, Job,
  CronJob × rollout/rollback/scale/delete) through the production ControllerManagerService against
  the pinned kube-controller-manager oracle with zero differences, the scheduler differential
  matches the pinned scheduler, and the leader-loss and queue/informer chaos runners prove Lease
  hand-over with live process generations. Production bugs found: list items carry no TypeMeta
  (as in kube-apiserver), so the bootstrap resource source now restores each item's kind and
  apiVersion from the list envelope the way client-go's typed decoding does; status-subresource
  writes are journaled as their own semantic effect. Gate/probe contract defects fixed on the way:
  effect-checkpoint binding, ledger cycle kinds, oracle stdin binding, observable digests, chaos
  recovery record shape, generator temp-directory exclusion shared by every milestone.
- M4: every data-plane probe passes with independent external runners: the volume observation and
  crash runners (private mount namespaces, SIGKILL at every effect boundary, snapshot integrity),
  a Go CSI plugin oracle driven by the production CSI client over gRPC, the mount-attack
  observation runner, a network observation runner that keeps a live network namespace and packet
  capture alive for the gate, a NetworkPolicy oracle that boots the pinned kind node image with
  kindnetd enforcement, and the proxy parity runner (41/41 corpus cases on both the eBPF and the
  nftables datapath, zero connection loss across backend switches). Production bugs found by these
  runners were fixed (device-mapper table load, unmount descriptor pinning, crash recovery of lost
  mounts, IPv6 handling and NodePort masquerade in the eBPF program, conntrack-mark masquerade and
  fragment guard in nftables, identical Jenkins backend hashing on both datapaths).

The complete M0 → M4 chain was produced on 2026-09-05 on one source identity (`bundle exec rake
m0:evidence` … `m4:evidence` with the runner commands above exported); every manifest is
`COMPLETE`. Two flaky measurements were made deterministic rather than retried: the L3 runtime
smoke treats `pidfd_open` EINVAL on an already-exited short workload as the documented exit race,
and the graceful-termination oracle derives "killed after the grace period" from the harness's
measured delete-to-DELETED interval instead of second-granularity API timestamps. The network
observation runner now cleans up failed observations and `--reap` waits, escalates and sweeps
orphaned host links, because two live keepers on 10.253.7.1/30 broke IPv4 for each other.

The only requirement that is not met on this host is the Linux >= 6.12 kernel expected by the
M4 gate for the SCTP CRC32c helper path. The host runs 6.8.0-138 and cannot be rebooted; the
project owner waived the requirement on 2026-09-04. The waiver is recorded explicitly in the M4
manifest (`waivers`) through `RUBERNETES_M4_KERNEL_WAIVER_REASON` and echoed by the gate; it is
never a silent skip, and everything that does not depend on the 6.12-only helper is verified on
6.8. CRD serving and aggregation are delivered by M6 (below) and are outside the M0–M4 scope.

The external runner commands used for evidence capture are:

```bash
RUBERNETES_M4_VOLUME_OBSERVATION_COMMAND="ruby test/conformance/kubernetes/m4_volume_observation/runner.rb --mode observation"
RUBERNETES_M4_SNAPSHOT_RECOVERY_COMMAND="ruby test/conformance/kubernetes/m4_volume_observation/runner.rb --mode crash"
RUBERNETES_M4_CSI_ORACLE_COMMAND="ruby test/conformance/kubernetes/m4_csi_oracle/runner.rb"
RUBERNETES_M4_MOUNT_OBSERVATION_COMMAND="ruby test/conformance/kubernetes/m4_volume_observation/runner.rb --mode observation"
RUBERNETES_M4_NETWORK_OBSERVATION_COMMAND="ruby test/conformance/kubernetes/m4_network_observation/runner.rb"
RUBERNETES_M4_NETWORK_POLICY_ORACLE_COMMAND="ruby test/conformance/kubernetes/m4_policy_oracle/runner.rb"
RUBERNETES_M4_KERNEL_WAIVER_REASON="<owner-granted reason>"
```

The network observation runner leaves a daemon holding the observed namespace alive for the
gate; `ruby test/conformance/kubernetes/m4_network_observation/runner.rb --reap` stops it.

## M5 Durable High Availability

M5 is verified by six probes, each run by `rake m5:evidence` and checked by
`tools/milestones/m5_gate.rb` on top of the complete M0–M4 chain:

- `m5_linearizability_probe.rb` drives the production Raft node in a deterministic simulation
  with partitions, asymmetric partitions, reordering, duplication, loss, crash/restart and clock
  jumps, and checks every client history with `tools/verification/linearizability.rb`; the Ruby
  sequential model is first compared with the Lean reference `verification/lean/KVSequential.lean`.
- `m5_fault_matrix_probe.rb` runs real worker processes over TLS, SIGKILLs one of three and two of
  five nodes while writes are acknowledged, kills the leader during a joint-consensus membership
  change and during a snapshot install, and requires zero lost commits, zero split brain and
  identical replicas after restart.
- `m5_corruption_probe.rb` damages real WAL and snapshot files (bit flips, torn and zero-filled
  tails, oversized lengths, truncation), fills a size-limited tmpfs to provoke ENOSPC, injects short
  writes and fsync failures at the device boundary, and requires every case to fail closed while the
  acknowledged prefix survives; it also round-trips a backup and rejects a tampered one.
- `m5_rto_rpo_probe.rb` starts three real `rubernetes-apiserver` processes on the Raft datastore
  and a real `rubernetes-controller-manager`, kills two API servers, verifies that no write is
  acknowledged and `/readyz` fails during the outage, restores quorum and measures the time until
  reads, writes and the Deployment control loop resume (bound: 60 s; RPO: 0 objects).
- `m5_ownership_probe.rb` replays every durable effect journal (Raft store, Native runtime,
  controller, volume, network) after a crash before and after the effect and requires exactly-once
  re-execution with the request-loss / response-loss distinction recorded.

```bash
RUBERNETES_M5_M4_MANIFEST=artifacts/milestones/M4/<run-id>/manifest.json rake m5:verify
```

## M6 Complete Kubernetes API Surface

M6 completes the API server: the request pipeline (request ID, authentication, authorization,
API Priority and Fairness, mutating and validating admission, storage, audit) in
`lib/rubernetes/security/`, the pinned-corpus admission plugin registry (41 plugins including
PodSecurity, NodeRestriction, ResourceQuota, webhooks and CEL policies), the CEL engine, encryption
at rest (AES-GCM envelope and KMS v2), CustomResourceDefinitions with structural schemas,
defaulting, pruning, CEL rules, None/Webhook conversion and OpenAPI publishing
(`lib/rubernetes/api/crd/`), API aggregation with the kube-aggregator availability controller
(`lib/rubernetes/api/aggregator.rb`), feature gates and `--runtime-config` modelling from the
v1.36.2 default corpus (`schema/kubernetes/v1.36.2-defaults/`), and the upstream OpenAPI v3
documents (`schema/kubernetes/v1.36.2-openapi-v3/`). It is verified by six probes, run by
`rake m6:evidence` and checked by `tools/milestones/m6_gate.rb` on top of the complete M0–M5 chain:

- `m6_api_coverage_probe.rb` compares every served discovery document, verb, OpenAPI v3
  operation and protobuf descriptor with the pinned corpus and requires zero missing items.
- `m6_feature_gate_probe.rb` compares the served API surface with the oracle discovery captured
  under the default, `AllBeta=true` and alpha-API profiles and requires zero differences.
- `m6_crd_differential_probe.rb` runs one CRD/aggregation script (structural validation messages,
  defaulting, pruning, multi-version serving, status subresource, OpenAPI publish, APIService
  availability, cleanup finalizer) against the pinned kube-apiserver in Docker and against the
  production server, and requires identical normalized observations.
- `m6_webhook_differential_probe.rb` registers the same admission webhooks on both servers
  (timeouts with Fail/Ignore policy, mutation and warnings, reinvocation policy, match policy,
  match conditions, AdmissionReview version negotiation, dry-run side effects, object selectors)
  and requires identical outcomes.
- `m6_security_pipeline_probe.rb` records the stage order of the production pipeline and checks
  error disclosure (401 before 403 before 404, no internal detail, audit of every outcome).
- `m6_fuzz_probe.rb` drives malformed, oversized, duplicate-key, path and content-negotiation
  inputs (seeded, reproducible) and requires zero panics, hangs and policy bypasses.

```bash
RUBERNETES_M6_M5_MANIFEST=artifacts/milestones/M5/<run-id>/manifest.json rake m6:verify
```

## M7 MicroVM Isolation

M7 adds the `rubernetes-firecracker` and `rubernetes-firecracker-restricted` runtime handlers
(RuntimeClasses `microvm` and `microvm-restricted`, Pod overhead 50m CPU / 128Mi) in
`lib/rubernetes/runtime/microvm/`: one Pod is one Firecracker 1.16.1 process launched through the
jailer (dedicated UID/GID, private PID/mount/network namespaces, cgroup v2 limits, the built-in
default-deny seccomp filter, chroot), a pinned guest kernel (Linux 6.1.128 with Landlock, PSI and
dm-verity), a read-only rootfs verified by dm-verity on the host, and the Ruby guest supervisor
(`guest/supervisor.rb`, PID 1 child) that applies the injected identity, keeps the workload gate
closed until the host verifies its signed ACKs, and runs the Pod's containers with the Native L3
backend inside the guest. The host side keeps the strict Firecracker API client, the vsock
`[u32][canonical CBOR]` protocol with its 1 MiB / 128 outstanding / 30 s bounds, the identity
ledger (VM id, subject/capability/request ids, vsock session, entropy, hostname, machine id, MAC,
IP, workspace, credential, policy digest and generation, revocation epoch, jail UID, guest CID —
never reissued), the base snapshot pool (pause ACK before pause, digests verified before every
restore, `SnapshotPauseUnknown` on a lost ACK), the restricted broker (closed operation set,
re-authorized at every effect point, all-answer DNS policy, per-hop redirect re-authorization) and
the runtime multiplexer that routes each Pod to its handler. Guest artifacts are built by
`rake m7:artifacts` (`tools/microvm/build_guest_kernel.sh`, `tools/microvm/build_guest_artifacts.rb`)
and pinned in `third_party/locks/m7-microvm-artifacts.json`. M7 is verified by five probes on the
real KVM host, run by `rake m7:evidence` and checked by `tools/milestones/m7_gate.rb` on top of
the complete M0–M6 chain:

- `m7_kvm_probe.rb` (L4/L5 report): artifact verification, cold-boot and restored Pod lifecycles
  with exec/logs/stats/probes/network and kernel-verified confinement, the `Node::Lifecycle` API
  contract through the multiplexer, and the fault matrix — jailer kill, VMM hang, UDS disconnect,
  vsock disconnect, pause ACK loss — each fail-closed with zero residue.
- `m7_attack_probe.rb`: a live guest attacks the jailer root, host filesystem, another VM's vsock,
  unlisted host ports, another tenant's network and its own rootfs; forged and stale ACKs and
  unknown broker operations are rejected; the restricted class has no NIC.
- `m7_identity_probe.rb`: eight clones of one base snapshot; every rotated identity field is unique
  across clones and the ledger history; stale ACKs and revoked capabilities are refused.
- `m7_snapshot_probe.rb`: the snapshot corruption corpus (bit flips, truncation, re-signed garbage,
  artifact mismatch, missing file) — no corrupt base ever starts a VM.
- `m7_latency_probe.rb`: raw Pod start samples from the cached base; p95 must be <= 1.5 s.

```bash
RUBERNETES_M7_M6_MANIFEST=artifacts/milestones/M6/<run-id>/manifest.json rake m7:verify
```

## Development Baseline

Rubernetes supports Ruby 3.4 or newer. Development and CI are pinned to Ruby 3.4.11 by
`.ruby-version` and the verified source record in `third_party/locks/ruby-3.4.11.json`.
The bootstrap smoke test is:

```bash
rake test
```

The complete local M0 check and the privileged real-kernel profile are:

```bash
rake m0:verify
rake m0:kernel
```

`rake m0:evidence` writes the strict evidence bundle below `artifacts/milestones/M0/`.
It does not require or create a Git repository. It reports `COMPLETE` only when the source input
digest remains stable and the x86_64 real-kernel probe succeeds against that same input.

The cumulative M1 verification and evidence commands are:

```bash
rake m0:evidence
RUBERNETES_M1_M0_MANIFEST=artifacts/milestones/M0/<run-id>/manifest.json rake m1:verify
```

M1 evidence is written below `artifacts/milestones/M1/` and can report `COMPLETE` only when the
referenced M0 bundle was captured from the identical source input.

M2 Native Pod verification is evidence-gated and is not implied by the presence of runtime
directories or by unit-test success. The gate requires COMPLETE M0 and M1 bundles, the x86_64
L0-L3 profile, the OCI attack corpus, lifecycle trace, 1,000-cycle resource ledger, and kernel
object inventory. An unavailable required adapter is recorded as INCOMPLETE; it is never accepted
as a successful skip. ARM support remains optional and is not a milestone or release prerequisite.

```bash
RUBERNETES_M2_M1_MANIFEST=artifacts/milestones/M1/<run-id>/manifest.json rake m2:verify
rake m2:kernel
```

`rake m2:evidence` writes the M2 bundle below `artifacts/milestones/M2/`. It reports `COMPLETE`
only when every required profile and report passes the content-addressed gate for the same source
input as M0 and M1. M2–M4 completion is established by the latest cumulative `COMPLETE` M4 bundle,
not merely by source presence, command availability, or isolated test success.

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
