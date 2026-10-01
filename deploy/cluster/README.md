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

Run the agent cleanup before removing the state directory. The ledger is what
names the sandboxes, bind mounts and network interfaces the agent created;
deleting it first leaves that kernel state behind with nothing to identify
it.
