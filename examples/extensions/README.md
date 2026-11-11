# Extension examples

English | [日本語](README.ja.md)

Cluster behaviour added with one Ruby file each. How extensions work and the
rules they follow are in the [specification](../../spec/ruby/extensions.md)
(Japanese).

| File | Adds | What it does |
|---|---|---|
| [team_rules.rb](team_rules.rb) | `validate`, `filter`, `score` | Makes a `team` label mandatory on Pods; keeps `tier: batch` Pods off `workload: interactive` nodes; prefers emptier nodes a little |
| [restart_on_config_change.rb](restart_on_config_change.rb) | `controller` | Rolls every Deployment that reads a ConfigMap when the ConfigMap changes |
| [namespace_defaults.rb](namespace_defaults.rb) | `controller`, `validate` | Gives each new namespace a LimitRange and a ResourceQuota, and refuses their deletion |

## Trying them

Bring up a cluster that loads extensions:

```sh
sudo ruby -Ilib exe/rubectl cluster up --workers 3 --extensions
export KUBECONFIG=/var/lib/rubernetes/clusters/default/kubeconfig
```

Check the files locally, then apply one. `check` sends nothing to the cluster.

```sh
ruby -Ilib exe/rubectl extension check examples/extensions/*.rb
ruby -Ilib exe/rubectl extension apply examples/extensions/restart_on_config_change.rb
```

Create a Deployment that reads a ConfigMap, then change only the ConfigMap:

```sh
kubectl create configmap site --from-literal=MESSAGE=hello
kubectl create deployment site --image=busybox:1.36 -- sh -c 'echo $MESSAGE; sleep 3600'
kubectl set env deployment/site --from=configmap/site
kubectl rollout status deployment/site

kubectl patch configmap site --type merge -p '{"data":{"MESSAGE":"changed"}}'
kubectl rollout status deployment/site    # a rollout, though the Deployment was not touched
kubectl logs -l app=site --prefix          # the new Pod prints "changed"; the old ones linger while they terminate
```

To look at the state and to remove an extension:

```sh
ruby -Ilib exe/rubectl extension list
ruby -Ilib exe/rubectl extension delete restart-on-config-change
```

## When writing one

- Blocks run inside the components' processes. Do not write heavy work or
  work that may never finish; every call has a time limit.
- `filter` and `score` are called for every Pod on every node. Work that
  calls the API belongs in a `controller`.
- A `validate` or `mutate` block that raises refuses the request. Take
  particular care with `"*"`. Deleting the extension itself always goes
  through.
- A top-level `def` or constant is visible to the blocks of the same file
  only.
