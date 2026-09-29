# Kubernetes Upstream Conformance Harness

This directory owns Rubernetes-specific runner profiles and result normalization only.
The Kubernetes v1.36.2 test source, Conformance image, and Conformance definition are
consumed without patches from identities pinned in `third_party/locks/`.

`profiles.yml` is the normative release matrix. Raw logs and JUnit files are written to
ignored `artifacts/`; they are not committed here.

## Related

- [Compatibility test contract](../../../spec/verification/kubernetes-compatibility.md)
- [Milestone M8](../../../spec/delivery/milestones.md#milestone-m8)
- [Pinned inputs](../../../third_party/locks/README.md)

