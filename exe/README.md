# Executable Boundary

`rubectl`, `rubernetes-apiserver`, `rubernetes-controller-manager`,
`rubernetes-scheduler`, `rubernetes-agent` and `rubernetes-proxy` live here.
Executables only parse process-level options and delegate to
`Rubernetes::Bootstrap`; domain policy remains in `lib/rubernetes/`.

Every daemon implements `--help`, `--version`, `--config PATH` and
`--check-config`. Help and version paths do not read configuration or
assemble dependencies. A daemon reads one YAML file and nothing from the
environment, becomes ready only after its dependencies are assembled and
healthy, and stops cleanly on `SIGINT`/`SIGTERM`. `rubectl` offers `get`,
`create`, `apply`, `patch`, `delete`, `watch` and `raw` against a kubeconfig
or explicit `--server`/credential flags, and loads Ruby manifests only inside
an isolated sandbox (`--allow-code`). Anything not implemented fails with an
error rather than a false success.

```sh
ruby -Ilib exe/rubernetes-apiserver --config /etc/rubernetes/apiserver.yml --check-config
ruby -Ilib exe/rubectl --kubeconfig ~/.kube/config get pods -n kube-system -o yaml
```

## Related

- [Naming](../spec/foundation/naming.md)
- [Project structure](../spec/delivery/project-structure.md)
- [Milestones](../spec/delivery/milestones.md)
