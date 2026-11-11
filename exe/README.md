# Executables

English | [日本語](README.ja.md)

This directory holds six executables:

- `rubectl`
- `rubernetes-apiserver`
- `rubernetes-controller-manager`
- `rubernetes-scheduler`
- `rubernetes-agent`
- `rubernetes-proxy`

An executable only parses its options and hands over to
`Rubernetes::Bootstrap`. The functionality is implemented in
`lib/rubernetes/`.

## Daemons

The five executables other than `rubectl` are daemons. Every daemon accepts
`--help`, `--version`, `--config PATH` and `--check-config`.

- `--help` and `--version` exit without reading configuration or assembling
  dependencies.
- Configuration comes from the one YAML file given with `--config`. Nothing
  is read from the environment.
- A daemon becomes ready only after all its dependencies are assembled and
  working.
- It stops cleanly on `SIGINT` or `SIGTERM`.

## rubectl

Supports `get`, `create`, `apply`, `patch`, `delete`, `watch` and `raw`.
Specify the server with a kubeconfig, or with `--server` and the credential
flags.

`rubectl cluster up` creates a cluster on this host; `start`, `down`,
`status` and `kubeconfig` manage it afterwards. It needs root. See
`rubectl cluster --help` for the options.

`rubectl extension` applies, checks, lists and deletes extensions written in
Ruby. `rubectl console`, `rubectl why` and `rubectl trace` look inside the
processes of a cluster running on this host.

Loading a manifest written in Ruby requires `--allow-code`. The manifest is
evaluated inside an isolated sandbox.

Calling a feature that is not implemented ends with an error. It never
pretends to succeed.

## Examples

```sh
ruby -Ilib exe/rubernetes-apiserver --config /etc/rubernetes/apiserver.yml --check-config
ruby -Ilib exe/rubectl --kubeconfig ~/.kube/config get pods -n kube-system -o yaml
sudo ruby -Ilib exe/rubectl cluster up --ha
```

## Related

- [Naming](../spec/foundation/naming.md)
- [Project structure](../spec/delivery/project-structure.md)
- [Milestones](../spec/delivery/milestones.md)
