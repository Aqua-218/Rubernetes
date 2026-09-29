# Compatibility Corpora

`api/` stores minimized request/response differential cases, `clients/` stores pinned
client matrices, and `projects/` stores the immutable manifest describing unmodified
third-party Charts and Operators. Oracle binaries and downloaded project sources remain
outside the production dependency graph and are cached only under `third_party/cache/`.

No finite project corpus defines Kubernetes compatibility. The corpus verifies composite
usage while the exhaustive external-contract ledger remains authoritative.

## Related

- [Kubernetes compatibility contract](../../spec/verification/kubernetes-compatibility.md)
- [Kubernetes API contract](../../spec/api/kubernetes-api.md)
- [Pinned inputs](../../third_party/locks/README.md)

