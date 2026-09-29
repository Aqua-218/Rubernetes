# M3 workload differential oracle

`runner.rb` is the external process entrypoint for the M3 workload matrix. It
accepts the exact request stream on stdin and runs it against a clean,
digest-pinned Kubernetes v1.36.2 kube-apiserver/etcd pair plus a
`kube-controller-manager` built from the pinned source checkout. It emits
runner, source, image, input, output, raw-digest, and canonical-digest
provenance on stdout.

The runner does not contain expected resource fixtures. Every expected
observation is read from the independent Kubernetes process after the
transported stream settles. Set `RUBERNETES_M3_KUBERNETES_SOURCE_ROOT` to a
clean checkout at commit `24e2b02af5543d7910c2bb074c7264df5a8f0467` (tag
`v1.36.2`) before execution.

The request and output boundary is documented in `runner_contract.json`.
