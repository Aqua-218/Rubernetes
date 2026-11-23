# Schema Inputs

`kubernetes/v1.36.2/` stores normalized, pinned inputs derived from the Kubernetes
v1.36.2 API and discovery contract. `rubernetes/` stores project-owned extension schemas.
Both are compiler inputs; generated Ruby, RBS, OpenAPI, and fixtures belong in `generated/`.

The v1.36.2 compiler also runs the declarative validation importer against a
local checkout of the pinned Kubernetes commit. Set
`RUBERNETES_KUBERNETES_SOURCE` to its path if it differs from
`/tmp/kubernetes-v1.36.2`, and run `ruby tools/schema/generate.rb --check`
with Go available in `PATH` to check all generated files.

## Related

- [Schema compiler](../spec/ruby/schema-compiler.md)
- [Kubernetes API](../spec/api/kubernetes-api.md)
- [Pinned references](../third_party/locks/README.md)

