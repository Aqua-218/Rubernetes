# Kubernetes v1.36.2 declarative validation

Generate the rule data from the locked Kubernetes Git commit.

```sh
go run tools/schema/import_declarative_validation.go /tmp/kubernetes-v1.36.2 generated/schema/declarative_validation.json
bundle exec ruby tools/schema/check_declarative_validation.rb
bundle exec ruby tools/schema/check_declarative_validation.rb --matrix
```

The importer reads upstream `validation-gen` output through the Go AST. The
artifact preserves validation order, maturity markers, early returns, and
feature options. It includes unsupported instructions alongside imported ones.
The Ruby evaluator rejects a program that contains any unsupported reachable
instruction.

The differential runs the pinned Go Scheme validators and compares the ordered
error reasons, field paths, origins, and maturity stages. It also compares
the migration mismatch count against the pinned handwritten validators for
CertificateSigningRequest, PriorityLevelConfiguration, and DRA fixtures. The
coverage matrix lists generated REST resource schemas, their integration
status, and any remaining instruction types.

The Workload, PodGroup, and ResourcePoolStatusRequest strategies enforce
generated standard rules. The two status subresources use the corresponding
generated rules and retain their handwritten checks. The API compares
generated and covered handwritten errors for each row marked shadow
comparison, including ReplicationController Scale, CertificateSigningRequest
approval and status, and ResourceClaim status. A
separate classification identifies generated types whose upstream REST
strategies do not call their generated validators.
