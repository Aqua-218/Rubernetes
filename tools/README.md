# Ruby Engineering Tools

Project automation is implemented in Ruby wherever practical. `schema/` owns import and
generation commands, `conformance/` owns upstream test orchestration and evidence capture,
`verification/` owns model/proof/trace execution, and `release/` owns reproducible packaging
and release-gate aggregation.

`platform/generate_abi_manifest.rb` compiles a C11 probe against the host Linux UAPI headers.
`milestones/` owns the M0 executable, kernel, native-boundary, evidence-capture, and strict gate
commands. The gate deliberately refuses a missing x86_64 kernel profile, test skips, unstable
source inputs, and digest mismatches. Evidence is content-addressed and neither requires nor
creates a Git repository.

`milestones/m5_*_probe.rb` produce the M5 durable-HA reports (linearizability
histories, real-process fault matrix, WAL/snapshot corruption corpus, RTO/RPO report and
resource ownership ledger); `m5_gate.rb` validates them on top of the complete M0–M4 chain.
`verification/linearizability.rb` is the history checker and `verification/kv_sequential_oracle.rb`
compares its sequential model with the Lean executable reference.

`milestones/m6_*_probe.rb` produce the M6 API-surface reports (API coverage ledger, feature-gate
matrix, CRD/aggregation and webhook differentials against the Docker oracle, security pipeline
trace and fuzz summary); `m6_gate.rb` validates them on top of the complete M0–M5 chain.
`schema/import_kubernetes_defaults.rb`, `schema/import_kubernetes_bootstrap.rb` and
`schema/import_kubernetes_openapi_v3.rb` capture the default-flag corpora from the oracle.

`microvm/build_guest_kernel.sh` and `microvm/build_guest_artifacts.rb` build and pin the M7 guest
artifacts (kernel, dm-verity rootfs with the Ruby guest supervisor, Firecracker release binaries);
`milestones/m7_*_probe.rb` produce the M7 reports on the real KVM host (L4/L5 report, attack
matrix, identity ledger, snapshot corruption corpus, startup latency samples) and `m7_gate.rb`
validates them on top of the complete M0–M6 chain.

- [Conformance tooling boundary](conformance/README.md)
- [Milestone probes and gates](milestones/README.md)

## Related

- [Project structure](../spec/delivery/project-structure.md)
- [Kubernetes compatibility](../spec/verification/kubernetes-compatibility.md)
- [Release gate](../spec/delivery/implementation-plan.md#sec-9-3)
