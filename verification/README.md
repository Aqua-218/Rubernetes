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

**No model-checking result backs the M5 Raft claims.**  Exhaustive TLC at that
scope was measured infeasible on 2026-09-06: 1.21e9 distinct states with 7.9e8
still queued after four hours and 133 GB of state files, still growing.  The
M5 gate therefore requires no TLC report, and `verification/claims.yml` records
the Raft safety claims at `integration_tested`, backed by the deterministic
fault-injection simulation and the M5 probes.  Apalache symbolic BMC over the
same model at the same scope found no counterexample to depth 3; mutation
testing on the model showed that depth is too shallow to establish the
invariants, and the detection gaps measured at depth 8 are recorded in the
claims' assumptions.  `M5-RAFT-LOG-MATCHING-PROOF` remains `proved` in Lean and
is unaffected.

`lean/RaftLog.lean` proves LogMatching for all log lengths after an accepted
AppendEntries and that committed prefixes are never modified;
`lean/BoundedFraming.lean` proves that the transport never allocates more than
the frame bound; `lean/KVSequential.lean` is the executable sequential
key/value reference used only as the linearizability oracle (design decision
D4).  `tools/verification/kv_sequential_oracle.rb` compares the Ruby model in
`tools/verification/linearizability.rb` with `lean --run` output on a random
corpus before any history is judged.  None of the Lean sources use `sorry`,
`admit` or `native_decide`.

`claims.yml` is the assurance-level ledger required by section 7.7.
