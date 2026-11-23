# Formal Verification Sources

`tla/` contains protocol and lifecycle models, `lean/` contains executable definitions and
proofs, and `traces/` contains schemas and replay inputs connecting Ruby executions to the
formal models. Generated reports are written to ignored `artifacts/`, not this source tree.

## M2 RuntimeLifecycle evidence

`tla/RuntimeLifecycle.tla` models the complete M2 resource set (`mount`, `ns`,
`cgroup`, `process`, `pidfd`, and `temp`). `RuntimeLifecycle.cfg` binds that
set exactly, checks ownership/non-reuse and reverse cleanup invariants, and
checks the `EventuallyStoppedOrRemoved` liveness property under the model's
fairness assumptions. The Ruby trace verifier uses the same transition graph
and checks the temporal ownership and cleanup-order observations.

An external proof profile is authoritative only when it binds the selected TLA
source/config, Lean source, and Ruby verifier sources, declares the complete
property sets, and executes pinned TLC, Lean, and Apalache commands. Claimed
stdout, exit codes, or hashes in a profile are never accepted as proof.

`tools/verification/m2_formal_verify.rb` runs external commands in a disposable
temporary working directory, so TLC `states` and Apalache `_apalache-out`
artifacts cannot alter the source inventory. The report retains the exact argv,
version output, source/config bindings, property bindings, and captured output
digests. If any required tool is unavailable or its success parser fails, the
report is `INCOMPLETE` and cannot support an M2 `COMPLETE` gate. This remains a
bounded model/proof report, not a whole-domain guarantee.

## M5 Raft evidence

`tla/Raft.tla` is the Raft protocol model (leader election, log replication,
commit rule 5.4.2, restarts, message loss and duplication) and `Raft.cfg`
binds the scope from the formal-methods specification: 3 servers, terms 0..4,
log length 0..5, 2 clients.  It states `ElectionSafety`, `LeaderAppendOnly`,
`LogMatching`, `LeaderCompleteness`, `StateMachineSafety` and
`CommittedInQuorum`.

No model-checking result backs the M5 Raft claims.  Exhaustive TLC at that
scope was measured infeasible on 2026-09-06: 1.21e9 distinct states with 7.9e8
still queued after four hours and 133 GB of state files, still growing.  The
M5 gate therefore requires no TLC report, and `verification/claims.yml` records
the Raft safety claims at `integration_tested`, backed by the deterministic
fault-injection simulation and the M5 probes.  Apalache symbolic BMC over the
same model at the same scope found no counterexample to depth 3; mutation
testing on the model showed that depth is too shallow to establish the
invariants, and the detection gaps measured at depth 8 are recorded in the
claims' assumptions.

`lean/RaftLog.lean` proves that a contiguous AppendEntries batch on an
uncompacted log preserves the existing LogMatching invariant and that
successful appends preserve committed entries. The executable oracle drives
the Ruby follower's message handler, including partial batches, heartbeats
and conflicts. `lean/KVSequential.lean` is the executable sequential
key/value reference used only as the linearizability oracle (design decision
D4).  `tools/verification/kv_sequential_oracle.rb` compares the Ruby model in
`tools/verification/linearizability.rb` with `lean --run` output on a random
corpus before any history is judged.

## Lean and Ruby implementation checks

Run `ruby tools/milestones/m9_formal_probe.rb` to check the Lean files with
Lean 4.16.0 and run the executable comparisons. Set `RUBERNETES_LEAN` to
the executable if that version is installed outside the default elan location.

| Source | Proven behavior | Ruby verification boundary |
| --- | --- | --- |
| `RaftLog.lean` | LogMatching and commit preservation for a contiguous batch | The uncompacted follower log path through `Node#handle` |
| `Seccomp.lean` | 64-bit argument comparisons and ordered rule branches | Pinned x86_64 and aarch64 syscall tables and the emitted cBPF interpreted in Ruby |
| `RuntimeAlgorithms.lean` | IPAM reservation and subnet disjointness, reverse rollback order, per-field identity freshness, path precedence, ancestry bounds, Filter and Score composition | Production allocator, cleanup executor, identity ledger and scheduler pipeline, plus the OverlayFS and cgroup adapter configuration |
| `SchemaFields.lean` | Exact membership parity accepted by the semantic field-set checker | All pinned schema definitions, independently checked against emitted Ruby, RBS, codec, OpenAPI and patch artifacts |
| `BoundedFraming.lean` | Raft and vsock payload reads stay within the validated frame length | Actual header decoding and requested lengths through instrumented Ruby IO |

The Raft theorem assumes the invariant already holds for both logs and leaves
snapshot installation and leader election to their own tests. Seccomp opcode
layout and action encodings are covered by the interpreter comparison.
Cgroup cap enforcement and overlay rendering rely on the Linux kernel.
The overlay theorem models edits at a single path. Identity checks cover
ledger-issued rotated fields. A released Pod IP can be reused under the
network lease rules. The scheduler proof takes plugin results as inputs and
does not cover plugin termination or randomized tie-breaking. Schema parity
checks semantic names, including fields accessed through the generic Ruby
accessor. The frame bound covers payload bytes and read requests.

Mutation checks detected a changed committed Raft overwrite guard, missing
seccomp accumulator reload, reuse of an unknown IPAM lease, forward rollback,
reuse of a previously issued request ID, reversed filter rejection and ignored
score weights, altered overlay layer order, cgroup limits written to the wrong
level, and an off-by-one frame length check. The schema oracle also rejects
one missing and one extra field on each of the five surfaces.

`claims.yml` is the assurance-level ledger required by section 7.7.

## Related

- [Formal methods](../spec/verification/formal-methods.md)
- [Verification strategy](../spec/verification/testing.md)
- [Verification diagram](../spec/diagrams/08-verification.md)
