# Deploying a Rubernetes cluster

These are the operational procedures for a Rubernetes cluster installed from
release artifacts: install, upgrade, rollback, backup, restore and uninstall.
Every step is expressed as a command an operator runs on the host; nothing
here depends on a Rubernetes cluster already existing.

The layout assumes the release defaults:

| Path | Contents |
|---|---|
| `/usr/local/bin/rubernetes-*` | daemon executables (`apiserver`, `scheduler`, `controller-manager`, `proxy`, `agent`) and `rubectl` |
| `/etc/rubernetes/` | one YAML configuration file per process, plus `pki/` |
| `/var/lib/rubernetes/` | durable state: the Raft log and snapshots, the runtime ledger, volumes |
| `/var/log/rubernetes/` | process logs when not journalled |
| `/etc/systemd/system/rubernetes-*.service` | unit files from `deploy/systemd/` |

A control node runs `apiserver`, `scheduler` and `controller-manager`. A
worker node runs `agent` and `proxy`. A node may be both.

## Install

1. **Verify the artifact.** Every release publishes a manifest of SHA-256
   digests; check the bundle against it before unpacking. An artifact that
   does not match its digest is not installed, it is discarded.

   ```
   sha256sum --check rubernetes-<version>.sha256
   tar --extract --file rubernetes-<version>.tar.gz --directory /
   ```

2. **Create the state and configuration directories.** They hold the Raft
   log and the private keys, so they are owned by root and readable by no one
   else.

   ```
   install --directory --mode 0700 /var/lib/rubernetes /etc/rubernetes/pki
   install --directory --mode 0755 /var/log/rubernetes
   ```

3. **Issue the cluster PKI.** One CA signs the API server's serving
   certificate, the admin client certificate and the service account signing
   key. The serving certificate must carry every address a client dials:
   loopback, the node's advertised address, and the first address of the
   service CIDR, which is what in-cluster clients reach through the
   `kubernetes` Service.

   There is no separate PKI command yet. Issue the certificates with your
   own CA, or let `tools/conformance/cluster.rb` do it: it writes a complete
   `pki/` (CA, serving certificate with the addresses above, admin client
   certificate, service account signing key, per-component identities) and
   is the reference for what a correct PKI looks like.

4. **Write the process configuration.** `config/defaults/` carries a
   versioned default for each daemon; copy it and set the node's own values
   (advertised address, peer list, data directory). The API server needs the
   Raft peer list of every control node; the agent needs the node name and
   the kubeconfig it authenticates with.

5. **Start the control plane, then the nodes.**

   ```
   systemctl daemon-reload
   systemctl enable --now rubernetes-apiserver rubernetes-scheduler rubernetes-controller-manager
   systemctl enable --now rubernetes-agent rubernetes-proxy
   ```

6. **Verify.** The cluster is ready when every node reports `Ready` and the
   `kubernetes` Service answers from inside a Pod.

   ```
   rubectl get nodes
   rubectl get --raw /readyz
   ```

## Cluster DNS

Clusters created by `rubectl cluster up` publish the integrated DNS listeners as
`kube-system/kube-dns`. Applications can use the node resolver from
`/etc/resolv.conf` or resolve `kube-dns.kube-system.svc.cluster.local` and send
queries to the Service on UDP or TCP port 53. An EndpointSlice for each enabled
IP family lists the worker gateways. The Service routes queries to the local
worker. Starting an existing cluster preserves a DNS Service installed by the
operator.

## LoadBalancer Services

### Routed addresses on bare metal

Reserve one or more IPv4 or IPv6 CIDRs for Service addresses. Keep the pool
outside the Pod, ClusterIP and node subnets. Route each CIDR from your router
or clients to a node running an attached Service proxy. For example, on a
Linux router with the node reachable at `192.0.2.10`:

```sh
ip route add 198.51.100.0/28 via 192.0.2.10
```

`rubectl cluster up --load-balancer-pool 198.51.100.0/28` configures the
controller for the local cluster. Repeat the flag for additional pools.
To also serve charts that omit `spec.loadBalancerClass`, opt in when bringing up
a new cluster:

```sh
rubectl cluster up --load-balancer-pool 198.51.100.0/28 --default-routed-load-balancer
```

The `rubernetes.io/routed` class works in either mode.
For a cluster deployed from per-process YAML, apply the controller's RBAC
and add the pool to the controller-manager configuration:

```sh
rubectl apply -f config/addons/routed-load-balancer-rbac.yml
```

```yaml
processes:
  rubernetes-controller-manager:
    load_balancer_pool: [198.51.100.0/28]
    # Enable to also handle classless LoadBalancer Services.
    # default_routed_load_balancer: true
```

Include `service-lb-controller` if you set an explicit `controllers` list.
For an existing local cluster with a routed pool, bring it down, add
`default_routed_load_balancer: true` to `config/controller-manager.yml` in the
cluster directory, and use `rubectl cluster start` to reload the saved settings.
Service classes and ingress already published by other controllers are preserved.

Use the `rubernetes.io/routed` class to request an address for a Service:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: web
spec:
  type: LoadBalancer
  loadBalancerClass: rubernetes.io/routed
  allocateLoadBalancerNodePorts: false
  selector:
    app: web
  ports:
    - port: 80
      targetPort: 8080
```

The controller reserves an address for each available Service address family
and publishes the VIP in `status.loadBalancer.ingress`. `RequireDualStack`
waits for both addresses. A Service can request a particular address with
`spec.loadBalancerIP`. If the pool runs out, the controller reports a warning
event and retries. The node proxy forwards VIP traffic to EndpointSlices and
applies the Service's traffic policy and source ranges. With
`externalTrafficPolicy: Local`, route traffic to nodes that have ready local
endpoints. Static routing owned by the operator provides the path to the node.

Keep the `kube-system/rubernetes-load-balancer-allocations` ConfigMap with the
cluster's state. The controller uses it to preserve reservations across
restarts and to prevent concurrent allocations of the same address. Deleting
a routed Service or changing its type withdraws its ingress and releases its
reservation. Delete or convert routed Services before disabling the controller.

### Cloud load balancers

Deploy the cloud provider's Kubernetes-compatible external Cloud Controller
Manager (CCM) with its own credentials, Kubernetes RBAC and provider-specific
configuration. Point it at the Rubernetes API using the normal in-cluster
credentials or a kubeconfig. A Service with `type: LoadBalancer` and no
`loadBalancerClass` is managed by the external CCM's default Service controller.
Leave `default_routed_load_balancer` disabled when an external CCM manages
classless Services. Explicit `rubernetes.io/routed` Services can still use the
local pool alongside the external CCM.
Use the provider's documented annotations, backend routing and firewall settings.
The provider creates its cloud resources and writes ingress status and the
cleanup finalizer through the Kubernetes Service API.

On a standalone Rubernetes controller manager, set
`cloud_controller_manager: external` to delegate cloud responsibilities. This
setting can be combined with `load_balancer_pool` for classed, routed Services.
The local `rubectl cluster up` profile already excludes cloud-only controllers.

When the external CCM also initializes Nodes, configure each joining agent with
`cloud_provider: external`. It registers the Node with the standard
`node.cloudprovider.kubernetes.io/uninitialized:NoSchedule` taint so the CCM
can initialize it before scheduling. Set `provider_id` if the provider requires
a preconfigured instance ID. Configured InternalIP entries in `addresses`
are sent as the upstream `alpha.kubernetes.io/provided-node-ip` hint. The CCM
owns subsequent updates to Node addresses. For a provider running only the
Service controller, use already initialized cloud nodes with the required
provider IDs and omit the initialization taint.

Set `CloudControllerManagerWatchBasedRoutesReconciliation` and
`CloudControllerManagerWebhook` through the external CCM's `--feature-gates`
flag. Watch-based reconciliation uses the Node API watch to maintain cloud
PodCIDR routes when the provider publishes a Routes implementation and route
management is enabled. A provider webhook also needs a handler registered in
its CCM, a TLS listener reachable by the API server, and the matching webhook
configuration containing its CA bundle.

## Kubelet Pods API

Enable the alpha `PodsAPI` gate on the agent to let local clients use
`v1alpha1.Pods` over the `pods-api/pods-api.sock` Unix socket. By default the
directory is under the agent's kubelet root. Set `pods_api_directory` to an
absolute path to place it elsewhere:

```yaml
processes:
  rubernetes-agent:
    feature_gates:
      PodsAPI: true
    pods_api_directory: /var/lib/rubernetes/pods-api
```

`ListPods` and `GetPod` return each desired local Pod's spec and the latest
status observed by the agent. `WatchPods` streams the initial set in UID order,
an initial-sync marker and subsequent changes. The agent restricts the socket
to its owner. Install the Ruby `grpc` and `google-protobuf` dependencies when
enabling this gate.

## Graceful node shutdown

The agent can delay a host shutdown until it has stopped the node's Pods, as
the kubelet's `GracefulNodeShutdown` does. It is **off by default**
(`shutdownGracePeriod` 0, the upstream default). With no grace period the agent
never connects to systemd-logind, never writes under `/etc/systemd`, and holds
no inhibitor lock. To enable it, set a grace period in the agent's section of
the process configuration:

```yaml
processes:
  rubernetes-agent:
    shutdown:
      grace_period: 30s               # kubelet shutdownGracePeriod
      grace_period_critical_pods: 10s # shutdownGracePeriodCriticalPods (part of the 30s)
      # or, instead of the two above (GracefulNodeShutdownBasedOnPodPriority):
      # grace_period_by_pod_priority:
      #   - {priority: 100000, shutdown_grace_period_seconds: 10}
      #   - {priority: 0, shutdown_grace_period_seconds: 20}
```

The durations must be 0 or at least 1s. `grace_period_critical_pods` must not
exceed `grace_period`. `grace_period_by_pod_priority` cannot be combined with
either of them. The feature gates `GracefulNodeShutdown` and
`GracefulNodeShutdownBasedOnPodPriority` (both on by default) turn the manager
and the per-priority form off.

With a grace period set, the agent does the following:

- It reads logind's `InhibitDelayMaxUSec`. If that is less than the total
  grace period, the agent writes `/etc/systemd/logind.conf.d/99-kubelet.conf`
  (`InhibitDelayMaxSec=<total>`), reloads logind (`SIGHUP` through systemd's
  `KillUnit`) and checks that the value rose.
- It holds a `delay` inhibitor lock for `shutdown` (`systemd-inhibit --list`
  shows `kubelet ... Kubelet needs time to handle node shutdown delay`).
- On logind's `PrepareForShutdown(true)`, the node reports `Ready=False` with
  the message `node is shutting down`, and new Pods are rejected with reason
  `NodeShutdown`. Running Pods are then stopped one priority group at a time,
  lowest priority first. Each Pod gets its group's period, or its own
  `terminationGracePeriodSeconds` if that is shorter. Each stopped Pod ends
  `Failed` with reason `Terminated` and a `DisruptionTarget` condition. The
  agent then releases the lock and the shutdown continues.
  `PrepareForShutdown(false)` (a cancelled shutdown) takes the lock again.
  The start and end times go to `graceful_node_shutdown_state` next to the
  Pod directory (native runtimes)
  and the `kubelet_graceful_shutdown_{start,end}_time_seconds` metrics.

When the agent stops, it releases the lock. It also removes `99-kubelet.conf`,
provided the file still holds the value the agent wrote, and reloads logind.
The upstream kubelet leaves the drop-in in place.

Check the host before enabling this:

- **Drop-ins are applied in file-name order across all logind.conf.d
  directories.** Ubuntu's unattended-upgrades package installs
  `/usr/lib/systemd/logind.conf.d/unattended-upgrades-logind-maxdelay.conf`
  (`InhibitDelayMaxSec=30`). That name sorts after `99-kubelet.conf`, so it
  wins. On such a host, a grace period above 30s cannot take effect. The agent
  then logs `Failed to start node shutdown manager: ... timed out ... waiting
  for logind InhibitDelayMaxSec` once, runs without the feature and does not
  retry (as the kubelet does). Either keep the total at or below the host's
  `InhibitDelayMaxUSec`
  (`busctl get-property org.freedesktop.login1 /org/freedesktop/login1
  org.freedesktop.login1.Manager InhibitDelayMaxUSec`), or override that file
  with an `/etc/systemd/logind.conf.d/` drop-in of the same name.
- Run a single agent with a grace period per host. Several agents on one host
  would share the same drop-in, and the first one to stop would remove it.
- `DBUS_SYSTEM_BUS_ADDRESS` selects the system bus, as for the kubelet; by
  default it is `/run/dbus/system_bus_socket`.

## Upgrade

Upgrades are performed one node at a time and never require a cluster
outage. The control plane is upgraded before the nodes, because a new API
server serves an old agent but not the reverse.

1. Install the new artifact alongside the old one. Keep the previous
   executables: rollback is a symlink swap, not a re-download.

   ```
   tar --extract --file rubernetes-<new>.tar.gz --directory /opt/rubernetes/<new>
   ```

2. For each control node, one at a time:

   ```
   systemctl stop rubernetes-apiserver rubernetes-scheduler rubernetes-controller-manager
   ln --symbolic --force /opt/rubernetes/<new>/bin/* /usr/local/bin/
   systemctl start rubernetes-apiserver rubernetes-scheduler rubernetes-controller-manager
   rubectl get --raw /readyz
   ```

   Wait for the Raft quorum to report the node healthy before moving to the
   next one. Stopping two of three control nodes at once loses quorum.

3. For each worker node, one at a time:

   ```
   rubectl drain <node> --ignore-daemonsets
   systemctl stop rubernetes-agent rubernetes-proxy
   ln --symbolic --force /opt/rubernetes/<new>/bin/* /usr/local/bin/
   systemctl start rubernetes-agent rubernetes-proxy
   rubectl uncordon <node>
   ```

The node agent reconciles its durable ledger on startup: Pods that survived
the restart are adopted rather than recreated, and anything the ledger owns
without a live kernel object is cleaned up.

## Rollback

A rollback is the upgrade procedure with the previous artifact, in the
reverse order: nodes first, then the control plane. The API server's stored
objects are forward compatible within a minor version, so a rollback within
one minor version needs no data migration.

```
ln --symbolic --force /opt/rubernetes/<previous>/bin/* /usr/local/bin/
systemctl restart rubernetes-agent rubernetes-proxy          # on each node
systemctl restart rubernetes-apiserver rubernetes-scheduler rubernetes-controller-manager
```

If the upgrade has already written objects of a version the previous release
does not serve, restore from the backup taken before the upgrade instead.

## Watch history retention

The memory and Raft datastores default to `longer_window`. The store compacts
the oldest consecutive revisions once they fall outside both the last 24
hours and the latest 100,000 revisions. WATCH can replay retained revisions,
and LIST with `resourceVersionMatch=Exact` can use retained snapshots.

Paginated LIST gives each listing five minutes to finish. Every page in
that listing shares the first page's deadline. After the deadline or after
snapshot compaction, the API returns HTTP 410 with a replacement token in
`Status.metadata.continue`. Use that token to resume after the same key
against the latest snapshot, or start from the first page for a consistent
list. Recognized tokens from previous releases also return a replacement
token.

Set `compatibility` to compact history outside either the five-minute window
or the latest 100,000 revisions.

```yaml
processes:
  rubernetes-apiserver:
    datastore:
      history_retention_policy: compatibility
```

To adjust the two history windows, set `watch_history_limit` under
`rubernetes-apiserver` and `compaction_interval_seconds` under `datastore`.
With `longer_window`, set one of these values to `null` to disable that
window. Leaving both unbounded retains all history.

For Raft, configure identical retention settings on every replica, including
joining replicas. The longer window may increase memory use and Raft snapshot
size. History already compacted in a snapshot cannot be recovered by changing
retention settings. Set `compatibility` on upgraded replicas during a rolling
upgrade if the previous release used five-minute history. Set `longer_window`
on all replicas after upgrading.

In an upgraded Raft cluster, the first elected upgraded leader replicates a
signing key used to enforce the five-minute deadline. Until a replica has the
key, it uses the previous cursor format and follows snapshot availability.
Older replicas can read cursors from upgraded replicas. If an older replica
issues the next cursor, an upgraded replica with the key returns HTTP 410
with a replacement cursor because the older cursor carries no deadline.

## Moving from the in-memory datastore to raft

An API server configured with `datastore: {type: memory}` keeps everything in
its process. To move such a cluster to the replicated datastore without
losing an object, a UID or a resourceVersion:

1. Give the API server a console socket (`console: {socket: /run/rubernetes/apiserver.sock}`
   at the top level of its configuration) if it has none, and restart it.
2. Stop the writers (controller manager, scheduler, agents), then export the
   datastore and stop the API server. Writes made after the export are not in
   the file.

   ```sh
   echo 'service.export_datastore("/var/lib/rubernetes/state.json")' | \
     ruby -Ilib exe/rubectl console apiserver --root /var/lib/rubernetes/clusters/NAME
   ```

3. Turn the file into the data directory of the first raft node. The
   directory must be empty.

   ```sh
   ruby -Ilib exe/rubectl cluster seed --state /var/lib/rubernetes/state.json \
     --data-dir /var/lib/rubernetes/data/control-0 --voter control-0
   ```

4. Change the configuration to `datastore: {type: raft, node_id: control-0,
   voters: [control-0], data_dir: ..., pki_dir: ...}` (see Install for the
   raft identity) and start the API server, then the other components.
5. Delete the state file; it holds every Secret in clear text.

The node starts from a snapshot at the revision the memory store had and
goes on from there. For a cluster made by `rubectl cluster up`, further
control nodes are added, or removed, with `rubectl cluster scale --controls N`.

## Backup

The cluster's entire state is the Raft log and its snapshots. A backup is
taken from one control node and is consistent as of the revision it names.

The backup tool is the Ruby module `Rubernetes::Consensus::Backup`; it copies
the latest verified snapshot and the write-ahead log of one control node's
Raft data directory and writes a manifest with their digests. The data
directory is the `datastore.data_dir` of that node's API server
configuration.

```
ruby -I /usr/local/lib/rubernetes -r rubernetes/consensus -e \
  'Rubernetes::Consensus::Backup.create("/var/lib/rubernetes/raft", "/var/backups/rubernetes-$(date +%Y%m%dT%H%M%SZ)")'
```

Back up `/etc/rubernetes/pki/` separately and at least once: without the CA
and the service account signing key, a restored snapshot cannot authenticate
any existing client or validate any issued token.

Take a backup before every upgrade, and on a schedule that matches how much
work the cluster can afford to lose.

## Restore

A restore replaces the state of every control node from one snapshot. All
control nodes must be stopped: restoring into a live quorum produces two
divergent histories.

1. Stop the control plane on every control node.

   ```
   systemctl stop rubernetes-apiserver rubernetes-scheduler rubernetes-controller-manager
   ```

2. On each control node, verify the snapshot and restore it into a fresh
   data directory. The old directory is moved aside rather than deleted, so
   a failed restore can still be examined.

   ```
   mv /var/lib/rubernetes/raft /var/lib/rubernetes/raft.pre-restore
   ruby -I /usr/local/lib/rubernetes -r rubernetes/consensus -e \
     'Rubernetes::Consensus::Backup.restore("/var/backups/<backup>", "/var/lib/rubernetes/raft")'
   ```

   `restore` re-verifies the manifest digests and the framing of every file
   before it writes, and refuses a target directory that is not empty. The
   same sequence is what the K7 lifecycle lane runs as its `backup_restore`
   stage (`tools/conformance/k7_cluster_driver.rb`).

3. Start one control node, confirm it becomes leader and serves reads, then
   start the rest.

   ```
   systemctl start rubernetes-apiserver
   rubectl get --raw /readyz
   systemctl start rubernetes-scheduler rubernetes-controller-manager
   ```

4. Restart the node agents. Each one reconciles its ledger against the
   restored API state and reports what it actually runs.

Pods created after the snapshot are gone from the API but may still run on
their nodes. The agents' startup reconciliation removes them, because the
API no longer owns them.

## Uninstall

```
rubectl drain <node> --ignore-daemonsets      # on each node: the agent stops and releases every Pod
systemctl disable --now rubernetes-agent rubernetes-proxy \
  rubernetes-apiserver rubernetes-scheduler rubernetes-controller-manager
rm --recursive --force /var/lib/rubernetes /var/log/rubernetes /etc/rubernetes
rm --force /etc/systemd/system/rubernetes-*.service /usr/local/bin/rubernetes-* /usr/local/bin/rubectl
systemctl daemon-reload
```

Drain every node while its agent is still running: the agent is what
releases the sandboxes, bind mounts and network interfaces it created, and
its ledger under `/var/lib/rubernetes` is what names them. Deleting the state
directory under a stopped agent leaves that kernel state behind with nothing
to identify it (there is no separate cleanup command yet).
