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

There are three kinds of check.

The workload differential has 20 cases: rollout, rollback, scale and delete
for each of Deployment, StatefulSet, DaemonSet, Job and CronJob. The results
of the production ControllerManagerService are compared with those of a
pinned kube-controller-manager.

The scheduler differential confirms that results match a pinned
kube-scheduler.

The chaos runners cause leader loss and queue and informer failures. They
confirm that the Lease is handed over after the process has actually been
replaced.

## M4 Workload data plane

Every data-plane probe needs an independent external runner.

| Runner | What it does |
|---|---|
| Volume observation and crash | Runs in a private mount namespace. Sends SIGKILL at every effect boundary and checks snapshot integrity |
| CSI plugin oracle | A CSI plugin written in Go, driven over gRPC by the production CSI client |
| Mount attack observation | Observes attacks on mounts |
| Network observation | Keeps the network namespaces and packet captures alive while the gate runs |
| NetworkPolicy oracle | Boots the pinned kind node image with kindnetd policy enforcement enabled |
| Proxy parity | All 41 corpus cases match on both the eBPF and nftables datapaths, with zero connection loss on a backend switch |

Export the runner commands before running `rake m4:evidence`.

```bash
RUBERNETES_M4_VOLUME_OBSERVATION_COMMAND="ruby test/conformance/kubernetes/m4_volume_observation/runner.rb --mode observation"
RUBERNETES_M4_SNAPSHOT_RECOVERY_COMMAND="ruby test/conformance/kubernetes/m4_volume_observation/runner.rb --mode crash"
RUBERNETES_M4_CSI_ORACLE_COMMAND="ruby test/conformance/kubernetes/m4_csi_oracle/runner.rb"
RUBERNETES_M4_MOUNT_OBSERVATION_COMMAND="ruby test/conformance/kubernetes/m4_volume_observation/runner.rb --mode observation"
RUBERNETES_M4_NETWORK_OBSERVATION_COMMAND="ruby test/conformance/kubernetes/m4_network_observation/runner.rb"
RUBERNETES_M4_NETWORK_POLICY_ORACLE_COMMAND="ruby test/conformance/kubernetes/m4_policy_oracle/runner.rb"
RUBERNETES_M4_KERNEL_WAIVER_REASON="<owner-granted reason>"
```

The network observation runner leaves a daemon that holds the observed
namespaces. Run `runner.rb --reap` after the gate. It stops the daemon,
kills it if it does not stop, and removes the host links left behind.

### Kernel waiver

The M4 gate expects Linux 6.12 or later for the SCTP CRC32c helper check.
When M4 was captured on 2026-09-04, the development host could not be
rebooted into that kernel, so the project owner waived the requirement.

Pass the reason in `RUBERNETES_M4_KERNEL_WAIVER_REASON`. It is recorded in
the `waivers` field of the M4 manifest and shown in the gate output. Every
check that does not depend on the 6.12-only helper has been run on the older
kernel.

## M5 Durable high availability

There are five probes.

### m5_linearizability_probe.rb

Drives the production Raft node under a deterministic simulation. The
injected faults are partitions, asymmetric partitions, reordering,
duplication, drops, crash and restart, and clock jumps. Every client history
is checked with `tools/verification/linearizability.rb`. The Ruby sequential
model used by the checker is first compared with the Lean reference model,
`verification/lean/KVSequential.lean`.

### m5_fault_matrix_probe.rb

Runs real worker processes over TLS and causes faults while writes are being
acknowledged:

- SIGKILL one node of three, and two of five.
- Stop the leader during a joint-consensus membership change.
- Stop the leader during a snapshot install.

In every case it requires zero lost commits, zero split brain, and replicas
that agree after restart.

### m5_corruption_probe.rb

Corrupts real WALs and snapshots: bit flips, torn tails, zero-filled tails,
oversized lengths and truncation. It also fills a size-limited tmpfs to
cause ENOSPC, and injects short writes and fsync failures.

In every case it requires the process to stop safely and the acknowledged
range of data to survive. It also checks the backup round trip and that a
tampered backup is rejected.

### m5_rto_rpo_probe.rb

Starts three real `rubernetes-apiserver` processes and a real controller
manager on the Raft datastore. It then stops two API servers and checks
that:

- while they are down, writes are not acknowledged and `/readyz` fails
- once quorum is restored, reads, writes and the Deployment control loop
  resume within 60 seconds
- zero objects are lost

### m5_ownership_probe.rb

Covers every durable effect journal: the Raft store, the Native runtime, the
controllers, volumes and the network. It crashes the process before and
after each effect and replays the journal. It records whether the request or
the response was lost, and requires each effect to be re-executed exactly
once.

## M6 Complete API surface

There are six probes.

### m6_api_coverage_probe.rb

Compares the served discovery documents, verbs, OpenAPI v3 operations and
protobuf descriptors with the pinned corpus. It requires zero gaps.

### m6_feature_gate_probe.rb

Compares the served API with discovery captured from the reference
kube-apiserver under three profiles: default, `AllBeta=true` and alpha APIs.
It requires zero differences.

### m6_crd_differential_probe.rb

Runs one script that exercises CRDs and aggregation against both a pinned
kube-apiserver in Docker and the production server. It requires the
normalized observations to match. The script covers:

- structural validation messages
- defaulting and pruning
- serving multiple versions
- the status subresource
- OpenAPI publication
- APIService availability
- the cleanup finalizer

### m6_webhook_differential_probe.rb

Registers the same admission webhooks with both servers and requires the
results to match. It covers:

- timeouts under the Fail and Ignore policies
- mutation and warnings
- the reinvocation policy, match policy and match conditions
- AdmissionReview version negotiation
- side effects on dry run
- object selectors

### m6_security_pipeline_probe.rb

Records the order of the stages in the production request pipeline. It also
checks error disclosure: 401, 403 and 404 are decided in that order, no
internal detail leaks, and every outcome is audited.

### m6_fuzz_probe.rb

Feeds malformed input, oversized input, duplicate keys, paths and
content-negotiation input. A seed reproduces the same input. It requires
zero panics, hangs and policy bypasses.

## M7 MicroVM isolation

Build the guest artifacts with `rake m7:artifacts`, which runs
`tools/microvm/build_guest_kernel.sh` and
`tools/microvm/build_guest_artifacts.rb`. The result is pinned in
`third_party/locks/m7-microvm-artifacts.json`. Run the probes on a real KVM
host.

### m7_kvm_probe.rb

Produces the L4 and L5 reports. It checks:

- artifact verification
- the Pod lifecycle from both a cold boot and a restore: exec, logs, stats,
  probes and network, with confinement verified from the kernel side
- the `Node::Lifecycle` API contract through the multiplexer
- the fault matrix: jailer kill, VMM hang, UDS disconnect, vsock disconnect
  and a lost pause ACK

Every fault must end with a safe stop and nothing left behind.

### m7_attack_probe.rb

Attacks from a running guest. The targets are the jailer root, the host
filesystem, another VM's vsock, unregistered host ports, another tenant's
network and the guest's own rootfs. It also checks that forged ACKs, stale
ACKs and unknown broker operations are rejected, and that a VM of the
restricted class has no NIC.

### m7_identity_probe.rb

Makes eight clones from one base snapshot. The rotated identity fields must
be unique across the clones and across the ledger history. Stale ACKs and
revoked capabilities must be rejected.

### m7_snapshot_probe.rb

Uses a corpus that corrupts snapshots: bit flips, truncation, re-signed
garbage, artifact mismatch and missing files. A VM must never boot from a
corrupt base.

### m7_latency_probe.rb

Starts Pods from a cached base and records the raw samples of the time
taken. The p95 must be 1.5 seconds or less.

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
