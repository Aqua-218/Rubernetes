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
| `cluster.rb up\|down\|status` | Starts and stops a cluster of 3 control nodes and 3 workers under `--root`. It uses the real `exe/rubernetes-*` processes and sets up the PKI, a kubeconfig and cluster DNS |
| `netns_env.sh up\|down\|exec` | Gives each cluster its own network namespace with an uplink, NAT and a resolver |
| `round.sh` | Runs one Hydrophone Conformance round inside a namespace and prints the JUnit totals and the names of failed specs |
| `run.rb` | Runs lanes K1 to K7 and writes a run manifest per profile. Run with `rake m8:lanes` |
| `build_selection_ledger.rb` | Rebuilds the K3 selection ledger from a Ginkgo dry run. Run with `rake m8:selection_ledger` |
| `resolve_image_digests.rb` | Resolves the image tags used by the corpus to digests for the lock |

The lanes are implemented in `k0_input_integrity.rb`, `k5_differential.rb`,
`k6_corpus.rb`, `k7_lifecycle.rb` and `lanes.rb`.

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

Read the result from `junit_01.xml`. Hydrophone prints nothing for a spec
that passes, so a log that looks stuck does not mean the run has stopped.

Use `--focus` to re-run after a fix. A `--focus` run counts as a separate
run and never replaces the result of a full run.

The last full run on this tree was on 2026-09-30. 459 of 459 passed on the
IPv4 profile.

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

```bash
export PATH=/opt/rubies/3.4.11/bin:$PATH            # the Ruby the Gemfile pins
export RUBERNETES_M8_CGROUP_ROOT=/sys/fs/cgroup/lanes   # one cgroup root per cluster
tools/conformance/netns_env.sh up lanes6 --v4 1 --v6 e6   # veth uplink, NAT, resolv.conf
tools/conformance/netns_env.sh exec lanes6 -- \
  ruby tools/conformance/cluster.rb up --profile linux-amd64-ipv6-native --root /srv/rbn-lanes
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

The IPv6-only profile has no NAT64, so an IPv6-only Pod cannot reach IPv4
destinations. Images are pulled by the node agent, which has both families
through the uplink. Only test Pods that connect to the IPv4 internet are
affected.

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
