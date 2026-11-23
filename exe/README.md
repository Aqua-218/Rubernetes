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
evaluated inside an isolated sandbox. `rubectl render` prints the objects a
manifest declares without contacting a cluster.

Calling a feature that is not implemented ends with an error. It never
pretends to succeed.

## rubectl logs

Use `rubectl logs web-0 -n production -c app --tail 100 -f` to follow a
container's logs. Use `-p` for its previous instance, `--timestamps` for log
timestamps, and either `--since 10m` or `--since-time 2026-11-20T10:00:00Z`
to filter by time. When you omit `-c`, the command uses the Pod's
`kubectl.kubernetes.io/default-container` annotation or the first container.
The command uses the current kubeconfig and requires `get` on `pods` and `pods/log`.

## rubectl disk

Use `rubectl disk web-0 -n production` to see a Pod's measured ephemeral
storage, each container's writable layer and logs, and volume usage by backing
type. The total comes from the kubelet. The individual rows can overlap with
that total. RAM and PVC volumes are shown separately, and volumes with an
undetermined backing type are labeled as unknown.
For an `emptyDir` with a positive `sizeLimit`, the volume row also shows the
configured limit in bytes (`sizeLimitBytes` in JSON), even before the first
kubelet usage sample arrives.

Add `-o json` for byte counts in `ephemeralStorageUsedBytes`, `containers` and
`volumes`. Missing measurements are `null` in JSON and `unknown` in text.
`status` identifies a matched sample (`sampled`), an unscheduled Pod
(`notScheduled`), a missing Pod UID (`missingUID`), or a missing sample for
that UID (`noSample`). The command uses the current kubeconfig and requires
`get` access to the Pod and the node's `nodes/proxy` subresource.

Run `rubectl disk -n production` to rank Pods by ephemeral storage use, with
unmeasured Pods at the end. Use `rubectl disk -A` to rank Pods across all namespaces.
Add `--node worker-1` to limit the ranking to a
single node. The ranking uses `list` access to Pods in that namespace and reads
each relevant node's summary once. With `-o json`, `pods` contains the ranked
Pod identities, node names, statuses, and totals in bytes.

Run `rubectl disk node/worker-1` to see used, available, and total capacity in
bytes for the node root filesystem and the runtime image and container
filesystems. These entries can refer to the same filesystem, so the report
shows each measurement separately. This command reads the named node's summary
once and requires `get` access to `nodes/proxy`. With `-o json`, `filesystems`
contains `fs`, `imageFs`, and `containerFs`, each with `usedBytes`,
`availableBytes`, and `capacityBytes`. Missing measurements are `null` in JSON
and `unknown` in text.

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
