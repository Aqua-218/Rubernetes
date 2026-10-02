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
| `lock.rb` | Read-only view of `third_party/locks/` (Kubernetes commit, Conformance image digest, runner artifacts) |
| `install_tools.rb` (`rake m8:tools`) | Install Hydrophone and Sonobuoy into `build/conformance/bin`, verifying each archive against the lock |
| `build_e2e.rb` (`rake m8:e2e_build`) | Build the upstream `e2e.test` binary from the pinned checkout |
| `cluster.rb up\|down\|status` | Bring up / tear down a 3 control-node + 3 worker cluster of real `exe/rubernetes-*` processes with PKI, kubeconfig and cluster DNS under `--root` |
| `netns_env.sh up\|down\|exec` | Give one cluster instance its own network namespace with an uplink, NAT and resolver |
| `round.sh` | One Hydrophone Conformance round inside a namespace; prints the JUnit totals and failed spec names |
| `run.rb` (`rake m8:lanes`) | The official K1–K7 lane runner that writes the per-profile run manifest |
| `k0_input_integrity.rb`, `k5_differential.rb`, `k6_corpus.rb`, `k7_lifecycle.rb`, `lanes.rb` | Lane implementations |
| `build_selection_ledger.rb` (`rake m8:selection_ledger`) | Rebuild the K3 selection ledger from a Ginkgo dry-run |
| `resolve_image_digests.rb` | Resolve the image tags of the project corpus to digests for the lock |

## Day-to-day loop

```bash
export PATH=/opt/rubies/3.4.11/bin:$PATH
rake m8:tools                                               # hydrophone + sonobuoy, once
tools/conformance/netns_env.sh up conf4 --v4 3 --v6 e7      # one namespace per cluster instance
RUBERNETES_M8_CGROUP_ROOT=/sys/fs/cgroup/conf4 \
  tools/conformance/netns_env.sh exec conf4 -- \
  ruby tools/conformance/cluster.rb up --profile linux-amd64-ipv4-native --root /srv/rbn-conf4
setsid nohup tools/conformance/round.sh conf4 /srv/rbn-conf4/linux-amd64-ipv4-native \
  /srv/rbn-conf4/rounds/01 --parallel 4 > /srv/rbn-conf4/rounds/01.out 2>&1 &
```

A full round at `--parallel 4` takes about 40 minutes on one host. Read
`junit_01.xml` for the result: passes are silent in Hydrophone's log, so a
quiet log is not a stalled run. Re-run a fix with `--focus` (a different run
identity; it never replaces a full round). The last full IPv4 round on this
tree passed 459/459 (2026-09-30).

## Bringing up the IPv6 and dual-stack profiles

`test/conformance/kubernetes/profiles.yml` defines three profiles, all 3 control
nodes + 3 workers on one host: `linux-amd64-ipv4-native`, `linux-amd64-ipv6-native`
(Pod CIDRs `fd00:d8:<n>::/48`, service CIDR `fd00:d8:5::/112`) and
`linux-amd64-dualstack-native` (both; IPv4 is the primary family, as the
profile lists it first).  `cluster.rb` derives everything else from the
profile: the API servers bind `::` when IPv6 is present and advertise an
address of the primary family, the `kubernetes` Service and its endpoints
follow that family, every node publishes one `InternalIP` per family (the
first address of its Pod bridge, `10.24n.0.1` / `fd00:d8:n::1`), and the
serving certificates carry the addresses of both families.

Each cluster instance runs inside a network namespace of its own so the Pod
bridges, nftables tables, node ports and routes never meet the host's or
another instance's:

```bash
export PATH=/opt/rubies/3.4.11/bin:$PATH            # the Gemfile's Ruby
export RUBERNETES_M8_CGROUP_ROOT=/sys/fs/cgroup/lanes   # one cgroup root per instance
tools/conformance/netns_env.sh up lanes6 --v4 1 --v6 e6   # veth uplink, NAT, resolv.conf
tools/conformance/netns_env.sh exec lanes6 -- \
  ruby tools/conformance/cluster.rb up --profile linux-amd64-ipv6-native --root /srv/rbn-lanes
tools/conformance/round.sh lanes6 /srv/rbn-lanes/linux-amd64-ipv6-native \
  /srv/rbn-lanes/rounds/ipv6-01 --parallel 4          # start it with setsid nohup
```

- `netns_env.sh up <name> --v4 <n> --v6 <hex>` gives the namespace an uplink
  `10.250.<n>.0/30` + `fd00:1a:<hex>::/64` to the host, masquerades Pod traffic to
  the uplink address inside the namespace and the uplink out on the host, enables
  forwarding, and writes `/etc/netns/<name>/resolv.conf` (the host's
  `127.0.0.53` stub is unreachable from inside).  `exec` remounts cgroup2 on
  `/sys/fs/cgroup`, which `ip netns exec`'s fresh sysfs hides.  A second instance
  takes another `<n>`/`<hex>` and another `RUBERNETES_M8_CGROUP_ROOT`; `cluster.rb
  up`'s stale-workload kill is scoped to that root, so instances never kill each
  other's Pods.  `cluster.rb up` stops a cluster still running under the same
  `--root` first (the agents' streaming ports are fixed per worker).
- `round.sh` runs hydrophone inside the namespace with the pinned images from
  `tools/conformance/lock.rb`, keeps only the tail of hydrophone's stdout, and
  prints the JUnit totals and the failed spec names from `junit_01.xml`; read
  the JUnit, never hydrophone's stdout.  Progress while it runs:
  `kubectl -n conformance logs e2e-conformance-test -c conformance-container`.
- The official runner (`tools/conformance/run.rb`, lanes K1-K7) enters the
  namespace when `RUBERNETES_M8_NETNS=<name>` is set: every runner command and
  the kubeconfig reachability probe run under `ip netns exec <name>`.
- From the host, the cluster is reachable at the uplink address
  (`https://10.250.<n>.2:<port>`, the port from `cluster.json`); this shell's
  `http_proxy` covers everything but loopback, so use `NO_PROXY=10.250.<n>.2`
  (or `curl --noproxy '*'`) or every request "fails" with the proxy's answer.

### Known differences per profile (2026-09-27)

- IPv6-only: an IPv6-only Pod has no route to IPv4 destinations (no NAT64);
  image pulls are done by the node agent, which has both families through the
  uplink, so this only affects test Pods that dial the IPv4 internet.
- Dual-stack: the `kubernetes` Service is SingleStack in the primary family, as
  kube-apiserver creates it.  The node agents publish `InternalIP`s of both
  families; the cluster DNS a Pod gets (`nameserver`) is the bridge address of
  the primary family only (kubelet's `clusterDNS` is a list; ours takes the
  node's gateway addresses in profile order).
- Both: the API servers' `kubernetes` Endpoints list one address per API
  server with distinct ports on the same uplink address (three replicas on one
  host), where kubeadm lists distinct addresses.

## Related
- [Kubernetes compatibility contract](../../spec/verification/kubernetes-compatibility.md)
- [Milestone evidence rules](../../spec/delivery/milestones.md)
- [Pinned runner inputs](../../third_party/locks/conformance-runners.json)
