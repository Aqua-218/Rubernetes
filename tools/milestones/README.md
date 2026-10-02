# Milestone probes and gates

English | [日本語](README.ja.md)

For verification engineers and reviewers.

## How it works

There are ten milestones, M0 to M9. Each one is judged complete in two
steps.

1. `rake m<n>:evidence` runs the checks and collects the results into an
   evidence bundle under `artifacts/milestones/M<n>/<run-id>/`. A bundle is
   identified by the digest of its contents.
2. `rake m<n>:verify` is the gate. It re-checks the bundle.

A bundle is `COMPLETE` only when all of the following hold:

- The digest of the source inventory did not change during the capture.
- Every required real adapter and external runner ran.
- The earlier bundles it refers to were captured from the same source.

A missing adapter, a skipped test or a source change during the capture
makes the bundle `INCOMPLETE`. An `INCOMPLETE` bundle never passes. The
tools here neither require nor create a Git repository.

## The chain of gates

Each gate depends on the one before it. `rake m1:verify` needs a `COMPLETE`
M0 manifest, M2 needs M1, and so on through M9. Pass the previous manifest
in an environment variable.

```bash
rake m0:evidence
RUBERNETES_M1_M0_MANIFEST=artifacts/milestones/M0/<run-id>/manifest.json rake m1:verify
RUBERNETES_M2_M1_MANIFEST=artifacts/milestones/M1/<run-id>/manifest.json rake m2:verify
RUBERNETES_M3_M2_MANIFEST=artifacts/milestones/M2/<run-id>/manifest.json rake m3:verify
RUBERNETES_M4_M3_MANIFEST=artifacts/milestones/M3/<run-id>/manifest.json rake m4:verify
RUBERNETES_M5_M4_MANIFEST=artifacts/milestones/M4/<run-id>/manifest.json rake m5:verify
RUBERNETES_M6_M5_MANIFEST=artifacts/milestones/M5/<run-id>/manifest.json rake m6:verify
RUBERNETES_M7_M6_MANIFEST=artifacts/milestones/M6/<run-id>/manifest.json rake m7:verify
RUBERNETES_M9_M8_MANIFEST=artifacts/milestones/M8/<run-id>/manifest.json rake m9:verify
```

A source change alters the digest and invalidates every captured bundle.
When that happens, re-capture from M0.

The sections below describe what each gate requires.

## M0 Executable foundation

`rake m0:verify` runs four things:

- the gem build
- the test suite
- the `--help` and `--version` checks of every executable
- the native-boundary scan

`rake m0:kernel` runs the privileged x86_64 stage-00 kernel probe.

`rake m0:evidence` reports `COMPLETE` under two conditions: the source
digest stayed stable, and the real kernel probe succeeded on that same
source.

## M1 Schema and API core

The gate requires five real adapters.

| Adapter | Passes when |
|---|---|
| Generation reproducibility | The generated output is reproducible byte for byte |
| Kubernetes validation oracle | All 770 generated types map to an executable upstream REST strategy |
| Round-trip probe | There are zero mismatches |
| API differential | All 22 required operations match a pinned kube-apiserver and etcd |
| kubectl probe | Operations from kubectl succeed |

The 22 API differential operations include TokenReview, SelfSubjectReview,
SelfSubjectRulesReview, SubjectAccessReview, ComponentStatus and Pod
eviction.

## M2 Native Pod

The gate requires:

- the x86_64 Runtime L0–L3 profile
- the OCI attack corpus
- a lifecycle trace
- a resource ledger covering 1,000 cycles
- the kernel object inventory

Pod lifecycle observations are compared with a real Kubernetes v1.36.2 node.
The compared items are init container ordering, probe thresholds, restart
backoff and graceful termination. The reference node uses a kind node image
built from the pinned source.

The formal RuntimeLifecycle claim is decided on traces replayed from the
ownership journal that the production Native runtime writes. The journal is
hash-chained. The deciders are the Ruby trace checker, TLC, Apalache and
Lean. The conditions of the check are fixed in
`verification/proof-profile.json`, which
`tools/verification/m2_proof_profile.rb` loads.

`rake m2:kernel` runs the real-kernel adapter. ARM support is optional and
is not a prerequisite of the gate.

## M3 Control loops

The workload differential runs all 20 cases (Deployment, StatefulSet,
DaemonSet, Job, CronJob × rollout/rollback/scale/delete) through the
production ControllerManagerService against the pinned
kube-controller-manager, the scheduler differential matches the pinned
scheduler, and the leader-loss and queue/informer chaos runners prove Lease
hand-over with live process generations.

## M4 Workload data plane

Every data-plane probe needs its independent external runner: volume
observation and crash runners (private mount namespaces, SIGKILL at every
effect boundary, snapshot integrity), a Go CSI plugin oracle driven by the
production CSI client over gRPC, the mount-attack observation runner, a
network observation runner that keeps a live network namespace and packet
capture alive for the gate, a NetworkPolicy oracle that boots the pinned
kind node image with kindnetd enforcement, and the proxy parity runner
(41/41 corpus cases on the eBPF and nftables datapaths, zero connection loss
across backend switches). The runner commands are exported before
`rake m4:evidence`:

```bash
RUBERNETES_M4_VOLUME_OBSERVATION_COMMAND="ruby test/conformance/kubernetes/m4_volume_observation/runner.rb --mode observation"
RUBERNETES_M4_SNAPSHOT_RECOVERY_COMMAND="ruby test/conformance/kubernetes/m4_volume_observation/runner.rb --mode crash"
RUBERNETES_M4_CSI_ORACLE_COMMAND="ruby test/conformance/kubernetes/m4_csi_oracle/runner.rb"
RUBERNETES_M4_MOUNT_OBSERVATION_COMMAND="ruby test/conformance/kubernetes/m4_volume_observation/runner.rb --mode observation"
RUBERNETES_M4_NETWORK_OBSERVATION_COMMAND="ruby test/conformance/kubernetes/m4_network_observation/runner.rb"
RUBERNETES_M4_NETWORK_POLICY_ORACLE_COMMAND="ruby test/conformance/kubernetes/m4_policy_oracle/runner.rb"
RUBERNETES_M4_KERNEL_WAIVER_REASON="<owner-granted reason>"
```

The network observation runner leaves a daemon holding the observed
namespace alive for the gate; `runner.rb --reap` stops it, escalates and
sweeps orphaned host links.

**Kernel waiver.** The M4 gate expects Linux >= 6.12 for the SCTP CRC32c
helper path. The development host could not be rebooted onto such a kernel
when M4 was captured (2026-09-04) and the project owner waived the
requirement. The waiver is recorded explicitly in the M4 manifest
(`waivers`) through `RUBERNETES_M4_KERNEL_WAIVER_REASON` and echoed by the
gate; it is never a silent skip, and everything that does not depend on the
6.12-only helper is verified on the older kernel.

## M5 Durable high availability

- `m5_linearizability_probe.rb` drives the production Raft node in a
  deterministic simulation (partitions, asymmetric partitions, reordering,
  duplication, loss, crash/restart, clock jumps) and checks every client
  history with `tools/verification/linearizability.rb`; the Ruby sequential
  model is first compared with the Lean reference
  `verification/lean/KVSequential.lean`.
- `m5_fault_matrix_probe.rb` runs real worker processes over TLS, SIGKILLs
  one of three and two of five nodes while writes are acknowledged, kills the
  leader during a joint-consensus membership change and during a snapshot
  install, and requires zero lost commits, zero split brain and identical
  replicas after restart.
- `m5_corruption_probe.rb` damages real WAL and snapshot files (bit flips,
  torn and zero-filled tails, oversized lengths, truncation), fills a
  size-limited tmpfs to provoke ENOSPC, injects short writes and fsync
  failures, and requires every case to fail closed while the acknowledged
  prefix survives; it also round-trips a backup and rejects a tampered one.
- `m5_rto_rpo_probe.rb` starts three real `rubernetes-apiserver` processes on
  the Raft datastore and a real controller manager, kills two API servers,
  verifies that no write is acknowledged and `/readyz` fails during the
  outage, restores quorum and measures the time until reads, writes and the
  Deployment control loop resume (bound 60 s, RPO 0 objects).
- `m5_ownership_probe.rb` replays every durable effect journal (Raft store,
  Native runtime, controller, volume, network) after a crash before and after
  the effect and requires exactly-once re-execution with the request-loss /
  response-loss distinction recorded.

## M6 Complete API surface

- `m6_api_coverage_probe.rb` compares every served discovery document, verb,
  OpenAPI v3 operation and protobuf descriptor with the pinned corpus and
  requires zero missing items.
- `m6_feature_gate_probe.rb` compares the served API surface with the oracle
  discovery captured under the default, `AllBeta=true` and alpha-API
  profiles and requires zero differences.
- `m6_crd_differential_probe.rb` runs one CRD/aggregation script (structural
  validation messages, defaulting, pruning, multi-version serving, status
  subresource, OpenAPI publish, APIService availability, cleanup finalizer)
  against the pinned kube-apiserver in Docker and against the production
  server, and requires identical normalized observations.
- `m6_webhook_differential_probe.rb` registers the same admission webhooks on
  both servers (timeouts with Fail/Ignore policy, mutation and warnings,
  reinvocation policy, match policy, match conditions, AdmissionReview
  version negotiation, dry-run side effects, object selectors) and requires
  identical outcomes.
- `m6_security_pipeline_probe.rb` records the stage order of the production
  pipeline and checks error disclosure (401 before 403 before 404, no
  internal detail, audit of every outcome).
- `m6_fuzz_probe.rb` drives malformed, oversized, duplicate-key, path and
  content-negotiation inputs (seeded, reproducible) and requires zero panics,
  hangs and policy bypasses.

## M7 MicroVM isolation

Guest artifacts are built by `rake m7:artifacts`
(`tools/microvm/build_guest_kernel.sh`, `tools/microvm/build_guest_artifacts.rb`)
and pinned in `third_party/locks/m7-microvm-artifacts.json`. The probes run
on a real KVM host:

- `m7_kvm_probe.rb` (L4/L5 report): artifact verification, cold-boot and
  restored Pod lifecycles with exec/logs/stats/probes/network and
  kernel-verified confinement, the `Node::Lifecycle` API contract through the
  multiplexer, and the fault matrix (jailer kill, VMM hang, UDS disconnect,
  vsock disconnect, pause ACK loss), each fail-closed with zero residue.
- `m7_attack_probe.rb`: a live guest attacks the jailer root, host
  filesystem, another VM's vsock, unlisted host ports, another tenant's
  network and its own rootfs; forged and stale ACKs and unknown broker
  operations are rejected; the restricted class has no NIC.
- `m7_identity_probe.rb`: eight clones of one base snapshot; every rotated
  identity field is unique across clones and the ledger history; stale ACKs
  and revoked capabilities are refused.
- `m7_snapshot_probe.rb`: the snapshot corruption corpus (bit flips,
  truncation, re-signed garbage, artifact mismatch, missing file); no corrupt
  base ever starts a VM.
- `m7_latency_probe.rb`: raw Pod start samples from the cached base; p95
  must be <= 1.5 s.

## M8 Kubernetes compatibility

`tools/conformance/run.rb` executes the K0–K7 lanes from
[the compatibility contract](../../spec/verification/kubernetes-compatibility.md)
and writes a run manifest per profile. A lane whose prerequisites are
missing reports `INCOMPLETE` with the reason; it never substitutes a mock or
reuses another run's result, and the M8 gate rejects any `INCOMPLETE` lane.
`rake m8:lanes` runs the lanes, `rake m8:evidence` captures the bundle and
`rake m8:verify` gates it. See [tools/conformance](../conformance/README.md)
for the cluster bring-up and the day-to-day conformance loop.

## M9 Release

`tools/release/` produces the release evidence: `sbom.rb` (CycloneDX 1.5,
deterministic), `release_manifest.rb` (binds the source inventory digest),
`loc_report.rb` (Ruby ratio, counting the native extension), `reproduce.rb`
(byte-identical rebuild), `security_report.rb` (advisories, unpinned inputs,
claim levels, undated markers), `benchmark.rb` (against a Kubernetes v1.36.2
oracle) and `soak.rb` (72 hours, append-only journal). A soak shorter than
72 hours, a benchmark with no oracle, or a missing clean-host reproduction is
reported as not satisfied rather than passed. `rake m9:artifacts` generates
the artifacts, `rake m9:verify` gates them.

## History

- 2026-09-04: an independent audit found the 2026-08-23 `COMPLETE` bundles
  rejected by the then-current gates. Over 2026-09-04/05 the M1–M4 oracles,
  probes and gate contracts were repaired (TypeMeta restoration from list
  envelopes, status-subresource journaling, effect-checkpoint binding, ledger
  cycle kinds, oracle stdin binding, observable digests, chaos recovery
  record shape, generator temp-directory exclusion) and the full M0 → M4
  chain was re-captured on one source identity with every manifest
  `COMPLETE`. Two flaky measurements were made deterministic rather than
  retried: the L3 runtime smoke treats `pidfd_open` EINVAL on an
  already-exited short workload as the documented exit race, and the
  graceful-termination oracle derives "killed after the grace period" from
  the harness's measured delete-to-DELETED interval instead of
  second-granularity API timestamps.
- 2026-09-06/07: M5, M6 and M7 probes and gates landed; the M5–M7 chain was
  captured on top of the 2026-09-05 M4 bundle.
- 2026-09-30: after the repository-wide RuboCop reformat, the M0/M1 gates
  and probes were re-run clean on the new tree. Bundles captured before a
  source change are, by design, stale for the current tree; a release
  candidate re-captures the whole chain.

## Related

- [Milestones and completion gates](../../spec/delivery/milestones.md)
- [Verification strategy](../../spec/verification/testing.md)
- [Formal verification sources](../../verification/README.md)
