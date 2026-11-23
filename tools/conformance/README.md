# Conformance tooling

English | [日本語](README.ja.md)

Ruby commands for checking compatibility with Kubernetes. They:

- verify the pinned upstream inputs
- bring up a cluster with the same topology as a release
- run the pinned Hydrophone and Sonobuoy binaries and the upstream
  `e2e.test`
- normalize JUnit and Ginkgo output
- classify the upstream e2e inventory
- emit the M8 evidence manifests

The tooling only invokes upstream executables. It must not modify their
source, focus expression, skip expression or result. An upstream run that
fails or ends early stays a failure.

## Commands

| Command | Purpose |
|---|---|
| `lock.rb` | Reads `third_party/locks/` and returns the Kubernetes commit, the Conformance image digest and the runner artifacts |
| `install_tools.rb` | Installs Hydrophone and Sonobuoy into `build/conformance/bin`, checking each archive against the lock. Run with `rake m8:tools` |
| `build_e2e.rb` | Builds the upstream `e2e.test` from the pinned checkout. Run with `rake m8:e2e_build` |
| `cluster.rb up\|start\|down\|delete\|status` | Manages a cluster of 3 control nodes and 3 workers under `--root`. It uses the real `exe/rubernetes-*` processes and sets up the PKI, a kubeconfig and cluster DNS |
| `netns_env.sh up\|down\|exec` | Gives each cluster its own network namespace with an uplink, NAT and a resolver |
| `round.sh` | Runs one Hydrophone Conformance round inside a namespace and prints the JUnit totals and the names of failed specs |
| `run.rb` | Runs lanes K0 through K7 and writes a run manifest per profile. Run with `rake m8:lanes` |
| `build_selection_ledger.rb` | Rebuilds the K3 selection ledger from a Ginkgo dry run. Run with `rake m8:selection_ledger` |
| `k3_observations.rb` | Indexes exact selected upstream JUnit results across test fixtures by ledger ID and source file |
| `resolve_image_digests.rb` | Resolves the image tags used by the corpus to digests for the lock |

The lanes are implemented in `k0_input_integrity.rb`, `k5_differential.rb`,
`k6_corpus.rb`, `k7_lifecycle.rb` and `lanes.rb`.

K0 uses a clean Git worktree of the locked Kubernetes release. It verifies
the pinned runner and conformance images and uses the vendored Go source to
list upstream test images. The run records the resolved digests in
`k0/resolved-images.json` and binds that file to the run in `k0/inputs.json`
before any cluster lane starts. When an oracle kubeconfig is supplied, K0
compares configured servers and static credentials without accessing the
clusters. The runner checks the upstream image tags again after execution.

The K6 kubectl matrix creates and removes a separate workload namespace for
each client version. The cluster needs working Pod streaming, access to the
pinned BusyBox image and a serving `metrics.k8s.io` API for `kubectl top`.
The SDK probes need Go and the pinned client-go modules. The Helm and
Kustomize binary paths and checksums are in
`test/compatibility/clients/matrix.yml`.

The Cilium project uses a dedicated QEMU guest with one Rubernetes worker.
Boot a fresh guest with writable CNI directories, the CNI `loopback` binary
in `/opt/cni/bin`, mounted cgroup v2 and bpffs, and a writable guest root
filesystem such as ext4 that can back the workload overlay mounts under
`/srv`. The guest needs access to the pinned
chart and image registries. Set `SSL_CERT_FILE` if the guest's OpenSSL
trust store requires an explicit path. Inside that guest, set
`RUBERNETES_K6_CILIUM_GUEST` to its boot ID and run
`ruby tools/conformance/k6_cilium_guest.rb /path/to/evidence`.
Cilium assigns the Pod IPs and programs the datapath. Rubernetes serves
Kubernetes Services using its kube-proxy component. The smoke checks both
Pods in Cilium's endpoint table and makes HTTP requests to the server's Pod
IP and ClusterIP from the separately attached client Pod. The operator
owns a host-network health port, so the scale stage tests one replica down
to zero and back to one. The topology covers traffic within one guest.

## K3 portable Linux e2e

The runner groups at most 32 selected specs per invocation. It waits for every ordinary chunk to finish before executing the upstream `Serial` specs one chunk at a time. Each chunk has its own JUnit report.

After the upstream process exits, K3 compresses complete XML reports as
`junit_*.xml.gz` and records the SHA-256 of the original XML. Use `gzip -dc`
to read the report. The verifier also reads earlier plain XML reports.
Each completed chunk publishes its command record immediately. Its stdout and stderr
are streamed to the gzip files named in that record.

Collect observation history for targeted runs with their exact selections,
pinned binary digest, and raw Ginkgo JUnit files. The index keeps the
fixture and report paths for each outcome and counts current required IDs
by upstream source file. Pass a fixture directory or the `k3` output
directory from `run.rb`.

```sh
ruby tools/conformance/k3_observations.rb --output observations.json /path/to/fixture-a /path/to/fixture-b
jq -r '.specs[] | select(.observed_pass == false) | .id' observations.json
```

The K3 lane determines release acceptance from the complete live run and
replacement checks on the selected cluster profile.

For stock K3 HPA resource tests, put the pinned Helm and kubectl binaries
from `test/compatibility/clients/matrix.yml` at their listed paths and
provision a dedicated cluster with `cluster.rb up --with-hpa-metrics`.
This installs the chart and image pinned in the K6 corpus, verifies the
APIService, and writes live CPU and memory samples from every worker to
`logs/hpa-node-metrics.json`. Isolated workers use kubelet TLS by default.
For shared workers, set `RUBERNETES_M8_COMPONENT_IDENTITIES=1` when
provisioning the fixture. Run the K6 metrics-server project on its own
cluster so it can install and uninstall its APIService.

The mapped provider storage tests run the corresponding pinned
upstream suite cases against Kubernetes HostPath, NFS, and Rook Ceph RBD CSI drivers. The fixture
uses a local Linux amd64 worker, the upstream checkout, and `skopeo` to fetch
digest-pinned driver and sidecar binaries on the first run. Use a short fixture
root under `/srv` so the worker's registration socket fits in the Linux Unix
socket address. K3 keeps Ginkgo and JUnit reports, driver logs, and storage
cleanup observations in `csi-replacements/`. Completed reports use lossless
gzip. The execution record identifies the stored files and the SHA-256 of
their original bytes. Historical uncompressed reports remain verifiable.
HostPath raw block cases use Linux loop devices. The block stress test uses the pinned
ten Pods and ten restarts per Pod. Its 64 GiB sparse filesystem lets the driver
reserve its block volumes without allocating their full size on the test host.
Cases that name XFS, ext4 or ext3 need kernel support and the corresponding
`mkfs` utility. The fixture mounts a sparse image in the worker's mount namespace
and records both the image superblock and the kernel's reported filesystem.
HostPath expansion tests use the pinned CSI resizer. The NFS expansion-policy
test uses a running Pod and verifies that the API rejects a resize request when
its StorageClass disallows expansion.
The snapshot cases also use the pinned VolumeSnapshot CRDs and official
snapshot controller and CSI snapshotter. Their cleanup report records
remaining VolumeSnapshotContents for the fixture driver.
Topology cases need at least two Ready workers. Each worker registers its own
official CSI driver endpoint and a node-local provisioner. The ledger can
associate several exact upstream origins with one shared public test, when
their pinned drivers declare the same requirements.
The shared filesystem cases need two Ready workers with `mount.nfs` and a
dedicated writable NFSv4.1 export reachable by both. Set
`RUBERNETES_K3_NFS_SERVER` and `RUBERNETES_K3_NFS_SHARE` to that test export.
The Azure File subPath cases use that same driver for the pinned file,
directory, read-only and mount-cleanup assertions.
Cross-node RBD cases use a dedicated Rook Ceph test cluster with the Linux
RBD kernel driver. Set `RUBERNETES_K3_RBD_STORAGE_CLASS` to the StorageClass
for `rook-ceph.rbd.csi.ceph.com`. The Ready workers must register distinct
CSI node IDs and use separate mount namespaces. The cases verify data after
reattaching filesystem, raw block, and mixed-mode volumes to a different worker.
The lane then verifies that PVs, VolumeAttachments, and mapped RBD devices are
released.
The recovery cases stop and restart the fixture's node agent. They record
the Pod identity, agent PIDs, kernel publication and observed data or cleanup.
The subPath deletion cases also record the CSI staging directory before the
restart and compare the full staging inventory after the old Pod is gone.
The unused-volume cases use the native mount table and a mounted control Pod
to verify that a declared but unreferenced PVC has no publication.

The kubelet authorization specs call each worker's advertised IP on TCP
10250 directly from a Pod. Provision TLS and webhook authentication and
authorization on the worker endpoint. The single-host fixture can use
`RUBERNETES_M8_COMPONENT_IDENTITIES=1` and forward each worker IP's TCP 10250
to its assigned loopback kubelet port inside the test network namespace.

## K4 Node Conformance

Build the upstream node test binary and Ginkgo from the pinned, clean Kubernetes checkout.

```sh
ruby tools/conformance/build_e2e.rb --node --source-root /path/to/kubernetes-v1.36.2
```

Run K4 as root on a dedicated amd64 Linux test node with real cgroups and network namespaces. Expose that node's filesystem at `/rootfs` for upstream system validation. The test cluster needs exactly one Ready node and a test kubeconfig with a bearer token that can call the API and node proxy.

Configure the agent's `device_plugins.directory` and `pod_resources.directory` as `/var/lib/kubelet/device-plugins` and `/var/lib/kubelet/pod-resources` for the upstream tests that connect to those sockets directly.
The upstream runner probes the agent at `http://127.0.0.1:10248/healthz`. Set `healthz_port: 10248` if provisioning assigned another port.
Set `read_only_port: 10255` for the upstream stats and metrics cases. This listener uses the agent's streaming addresses and serves diagnostics without authentication.
Run the test agent as a discoverable `kubelet-*` systemd unit for cases that stop and restart the node agent. These cases call `sudo systemctl` directly.

```sh
ruby tools/conformance/run.rb --lanes K4 --node-conformance-node worker-0 --kubeconfig /path/to/test/kubeconfig
```

The lane compares the upstream `NodeConformance` dry-run inventory with the Ginkgo report and records missing, failed, and skipped selected specs.
Execution uses the upstream node runner's 24-hour suite timeout. It reads the DNS domain and CRI endpoint from the test node's `/configz`. The DNS domain falls back to `cluster.local` when unavailable.

K4 stores validated Ginkgo JSON, completed JUnit XML, and the redacted execution records as lossless `.gz` files. The lane result records the stored file's `sha256` plus the original content's `uncompressed_sha256` and `uncompressed_bytes`. Use `gzip -dc` to read an archive. The K4 reader also accepts raw files from earlier runs. Invalid reports and any raw files whose archives could not be verified remain available for diagnosis.

## K7 lifecycle

Use a disposable cluster with its own network namespace and cgroup root.
Run `cluster.rb up --k7-bootstrap` to start with one MemoryStore control
node. The K7 runner migrates it to Raft, grows it to three voters, and
checks acknowledged writes across those transitions. Run `run.rb --lanes K7`
with the cluster kubeconfig and a separate Kubernetes v1.36.2 oracle
kubeconfig. Build the pinned upstream smoke test binary with `rake m8:e2e_build`.
Before running K7, wait for a long-running workload Pod to become Ready and
for its CSI VolumeAttachment to report `status.attached: true`. K7 checks
that the Pod keeps its identity and returns to Ready after each transition,
and that the volume stays attached.

For release upgrade and rollback, set `RUBERNETES_K7_PREVIOUS_BIN_DIR` and
`RUBERNETES_K7_TARGET_BIN_DIR` to the installed daemon directories for the
previous release and 1.0.0. Start the bootstrap cluster with
`cluster.rb up --k7-bootstrap --bin-dir /path/to/previous/bin`. Each
installed daemon executable must load its own release and expose its version.

For a worker reboot, join a worker VM to the test cluster and set
`RUBERNETES_K7_REBOOT_NODE` to its Node name. Set
`RUBERNETES_K7_WORKER_REBOOT` to an executable that takes the Node name and
its current kernel boot ID, then resets that VM. The driver verifies the
worker's new boot ID, unchanged Node UID and renewed lease. A worker sharing
the driver's kernel boot ID does not qualify for this stage.

## Day-to-day runs

```bash
export PATH=/opt/rubies/3.4.11/bin:$PATH
rake m8:tools                                               # install hydrophone and sonobuoy, once
tools/conformance/netns_env.sh up conf4 --v4 3 --v6 e7      # one namespace per cluster
RUBERNETES_M8_CGROUP_ROOT=/sys/fs/cgroup/conf4 \
  tools/conformance/netns_env.sh exec conf4 -- \
  ruby tools/conformance/cluster.rb up --profile linux-amd64-ipv4-native --root /srv/rbn-conf4
setsid nohup tools/conformance/round.sh conf4 /srv/rbn-conf4/linux-amd64-ipv4-native \
  /srv/rbn-conf4/rounds/01 --parallel 4 > /srv/rbn-conf4/rounds/01.out 2>&1 &
```

A full run at `--parallel 4` takes about 40 minutes on one host.

For the K1 lane, run `run.rb --lanes K1` with the target kubeconfig and the
pinned Kubernetes checkout via `--source-root`. The runner verifies the
digest of the upstream conformance definition and joins the original JUnit
and Ginkgo JSON reports by codename. The recorder streams the Ginkgo JSON
from Hydrophone's output container as `ginkgo-report.json.gz`.
`ginkgo-join.json` records the SHA-256 of the original JSON bytes and the
results of comparing the cases, outcomes, and seed with JUnit.
The command record points to `hydrophone.stdout.gz` and `hydrophone.stderr.gz`.
Use `gzip -dc` to read either stream. They preserve the runner's exact output,
including diagnostics from failed runs.

For a fresh isolated native fixture with its own `RUBERNETES_M8_CGROUP_ROOT`,
add `--retirable-image-cache` to `cluster.rb up`. After a complete K1 pass,
run `cluster.rb down --root FIXTURE_ROOT --retire-images-after /path/to/manifest.json`
in the fixture namespace. The command verifies the K1 evidence and releases
the opted-in worker image caches once the processes, workloads and mounts
have stopped. It reports the allocated bytes removed. Ordinary `down`
keeps the caches and can be used after a failed run to preserve its debug data.

Read the result from `junit_01.xml`. Hydrophone prints nothing for a spec
that passes, so a log that looks stuck does not mean the run has stopped.

Use `--focus` to re-run after a fix. A `--focus` run counts as a separate
run and never replaces the result of a full run.

The upstream Job tests use hostPath volumes under `/tmp/job-e2e`. If `/tmp`
is a separate mount on the host, start the fixture's daemons in a private
mount namespace and expose the root filesystem's `/tmp` there. Rubernetes
validates hostPath volumes without crossing mount boundaries.

```bash
RUBERNETES_M8_CGROUP_ROOT=/sys/fs/cgroup/conf4 \
  tools/conformance/netns_env.sh exec conf4 -- \
  unshare --mount --propagation private sh -c \
    'umount /tmp && exec ruby tools/conformance/cluster.rb up --profile linux-amd64-ipv4-native --root /srv/rbn-conf4'
```

### External CNI on the IPv4 profile

To exercise the agent's external CNI path, pass `--external-cni-bin-dir` to
`cluster.rb up --profile linux-amd64-ipv4-native`. The directory must contain
the reference `bridge`, `host-local` and `loopback` plugins. The provisioner
writes a per-worker CNI conflist using a separate bridge, subnet and IPAM
directory. Its cluster descriptor records the versions and hashes of the
executed binaries and the hashes of the rendered conflists. The normal
Hydrophone command and conformance selection apply to this cluster as well.

Give the fixture a dedicated network namespace, cgroup root, and private
`/run/netns` mount when other clusters share the host.

The provisioner binds DNS to each worker's gateway. Its agent config points ClusterFirst Pods at
that address through `dns.cluster_dns`. External CNI installations can set
`dns.cluster_dns` to an existing resolver and leave the agent DNS server off.

The 2026-11-18 UTC IPv4 native run passed all 446 cases in the pinned
v1.36.2 conformance definition with zero skips and zero flakes. Seven suite
hooks are recorded separately.

## IPv6 and dual-stack profiles

`test/conformance/kubernetes/profiles.yml` defines three profiles. Each one
builds 3 control nodes and 3 workers on one host.

| Profile | Addresses |
|---|---|
| `linux-amd64-ipv4-native` | IPv4 only |
| `linux-amd64-ipv6-native` | IPv6 only. Pod CIDRs are `fd00:d8:<n>::/48` and the service CIDR is `fd00:d8:5::/112` |
| `linux-amd64-dualstack-native` | Both. IPv4 is primary because the profile lists it first |

`cluster.rb` derives the rest from the profile:

- When the profile has IPv6, the API servers bind `::`. They advertise an
  address of the primary family.
- The `kubernetes` Service and its endpoints follow the primary family.
- Every node publishes one `InternalIP` per family. The value is the first
  address of its Pod bridge: `10.24n.0.1` and `fd00:d8:n::1`.
- The serving certificates carry the addresses of both families.

Each cluster runs in a network namespace of its own, so its Pod bridges,
nftables tables, NodePorts and routes never collide with the host's or
another cluster's.

The three native release profiles isolate their workers by default. Each worker gets its own host network namespace,
Pod bridge, uplink and kube-proxy. `hostNetwork` Pods can bind the same ports
on different workers. The control namespace routes Pod CIDRs to their workers,
and the API server reaches kubelets through authenticated TLS on their node IPs.
Each kubelet listens on its node IP at port 10250 and serves its loopback
health check on port 10248.
On each isolated worker, kube-proxy serves `/healthz` and `/livez` on port
10256. Its loopback listener on port 10249 serves `/proxyMode` and `/metrics`.
Cluster daemons bypass the inherited HTTP proxy for cluster addresses and preserve
the caller's existing exclusions. Use `--shared-worker-network` for fixtures with
a shared worker network. The external CNI and K7 modes keep their existing topology.
After an isolated run, `cluster.rb down` retains the topology for `start`. Use
`cluster.rb delete` within the control namespace to remove the worker networks.

Pass `cluster.rb up --resolv-conf FILE` to give every worker the same
fixture-owned resolver configuration. The cluster descriptor records its
path and SHA-256 digest. For fixtures without external DNS access, omit
external search domains so a failed lookup there cannot prevent clients
from trying the cluster-local name.

```bash
export PATH=/opt/rubies/3.4.11/bin:$PATH            # the Ruby the Gemfile pins
export RUBERNETES_M8_CGROUP_ROOT=/sys/fs/cgroup/lanes   # one cgroup root per cluster
tools/conformance/netns_env.sh up lanes6 --v4 1 --v6 e6   # veth uplink, NAT, resolv.conf
tools/conformance/netns_env.sh exec lanes6 -- \
  ruby tools/conformance/cluster.rb up \
  --profile linux-amd64-ipv6-native --root /srv/rbn-lanes
tools/conformance/round.sh lanes6 /srv/rbn-lanes/linux-amd64-ipv6-native \
  /srv/rbn-lanes/rounds/ipv6-01 --parallel 4          # start it with setsid nohup
```

### netns_env.sh

`netns_env.sh up <name> --v4 <n> --v6 <hex>` does the following:

- Creates an uplink from the namespace to the host, with the addresses
  `10.250.<n>.0/30` and `fd00:1a:<hex>::/64`.
- Inside the namespace, masquerades Pod traffic to the uplink address.
- On the host, masquerades traffic from the uplink outwards and enables
  forwarding.
- Writes `/etc/netns/<name>/resolv.conf`, because the host's stub resolver
  at `127.0.0.53` cannot be reached from inside the namespace.

`exec` remounts cgroup2 on `/sys/fs/cgroup`. `ip netns exec` mounts a fresh
sysfs, which hides cgroup2.

For a second cluster, use another `<n>` and `<hex>` and another
`RUBERNETES_M8_CGROUP_ROOT`. `cluster.rb up` removes stale workloads only
inside the given cgroup root, so clusters with separate roots never remove
each other's Pods.

`cluster.rb up` first stops any cluster still running under the same
`--root`, because the agents' streaming ports are fixed per worker.

### round.sh

`round.sh` runs Hydrophone inside the namespace with the pinned images that
`lock.rb` returns. It keeps only the tail of Hydrophone's standard output.
When the run ends, it prints the totals and the names of failed specs from
`junit_01.xml`. Judge the result from the JUnit file, not from Hydrophone's
standard output.

To watch progress during a run:

```bash
kubectl -n conformance logs e2e-conformance-test -c conformance-container
```

### run.rb

When the environment variable `RUBERNETES_M8_NETNS=<name>` is set, `run.rb`
works inside that namespace. Every runner command and the kubeconfig
reachability check run under `ip netns exec <name>`.

### Reaching a cluster from the host

From the host, a cluster is reachable at the uplink address. The URL is
`https://10.250.<n>.2:<port>`, and the port is in `cluster.json`.

In the shell on the development host, `http_proxy` applies to every
destination except loopback. Set `NO_PROXY=10.250.<n>.2` or use
`curl --noproxy '*'`. Otherwise requests go to the proxy and fail.

### Differences between profiles

Known as of 2026-09-27.

The IPv6-only conformance profile runs without a NAT64 gateway. Test Pods
in this profile cannot reach IPv4 destinations. The node agent pulls
images over the host uplink, which has both address families.

In the dual-stack profile, the `kubernetes` Service is SingleStack in the
primary family, the same as the Service kube-apiserver creates. The node
agents publish `InternalIP`s of both families. The cluster DNS `nameserver`
given to a Pod is the bridge address of the primary family only. The
kubelet's `clusterDNS` is an explicit list, whereas Rubernetes uses the
node's gateway addresses in profile order.

One difference applies to every profile. The `kubernetes` Endpoints of the
API servers list one entry per API server, with different ports on the same
uplink address, because three replicas run on one host. A cluster made with
kubeadm lists different addresses.

## Related

- [Kubernetes compatibility contract](../../spec/verification/kubernetes-compatibility.md)
- [Milestone evidence rules](../../spec/delivery/milestones.md)
- [Pinned runner inputs](../../third_party/locks/conformance-runners.json)
