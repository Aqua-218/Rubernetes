# Test Tree

> **Audience:** Implementers, compatibility engineers, and verification engineers

| Directory | Contract |
|---|---|
| `unit/` | Pure class and function behavior |
| `property/` | Generated inputs and invariant checking |
| `integration/` | Multiple in-process or host-process components |
| `e2e/` | Whole Rubernetes cluster behavior |
| `conformance/kubernetes/` | Unmodified upstream Kubernetes test execution |
| `compatibility/api/` | API and wire-level differential corpus |
| `compatibility/clients/` | kubectl, client-go, Helm, and SDK version-skew matrix |
| `compatibility/projects/` | Unmodified real-world chart and Operator corpus |
| `chaos/` | Ruby failure-scenario DSL and deterministic replay |
| `security/` | Abuse cases, isolation escapes, malformed input and fail-closed tests |
| `performance/` | Scale and latency release gates |
| `support/` | Test-only fakes, clocks, trace readers and assertions |
| `fixtures/` | Immutable inputs whose provenance and digest are recorded |

Detailed harness contracts:

- [Kubernetes upstream Conformance harness](conformance/kubernetes/README.md)
- [Compatibility corpora](compatibility/README.md)

M2 Native Pod evidence is emitted by the `tools/milestones/m2_*_probe.rb`
adapters and checked by `tools/milestones/m2_gate.rb`. The gate requires the
x86_64 Runtime L0-L3 profile, fail-closed OCI attack cases, a lifecycle trace,
a 1,000-cycle resource ledger, and a kernel object inventory. ARM hardware is
not a milestone or release prerequisite.

M5 durable-HA evidence is emitted by `tools/milestones/m5_*_probe.rb` and checked by
`tools/milestones/m5_gate.rb`. `support/raft_simulation.rb` is the deterministic
simulation of the production Raft node, `support/raft_linearizability_client.rb`
records client histories for the linearizability checker, and
`conformance/kubernetes/m5_raft_cluster/` runs real worker processes over TLS for the
SIGKILL fault matrix.

M7 MicroVM evidence is emitted by `tools/milestones/m7_*_probe.rb` on a KVM host and checked by
`tools/milestones/m7_gate.rb`; `unit/microvm_protocol_test.rb` covers the CBOR/vsock protocol,
Firecracker API client, identity ledger, snapshot pool, broker and multiplexer in process.

M6 API-surface evidence is emitted by `tools/milestones/m6_*_probe.rb` and checked by
`tools/milestones/m6_gate.rb`; `unit/security_*_test.rb`, `unit/api_security_pipeline_test.rb`
and `unit/api_crd_aggregation_test.rb` cover the security pipeline, admission, CEL,
encryption, CRD and aggregation code in process.

## Related

- [Verification strategy](../spec/verification/testing.md)
- [Kubernetes compatibility](../spec/verification/kubernetes-compatibility.md)
- [Milestones](../spec/delivery/milestones.md)
