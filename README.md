# Rubernetes

English | [日本語](README.ja.md)

Rubernetes is a reimplementation of Kubernetes v1.36.2 in Ruby. It runs on
Linux. A real `kubectl`, Helm, client-go and upstream charts work against it
unchanged.

Every program in a cluster is Ruby code from this repository: the API
server, the Raft datastore, the controllers, the scheduler, the node agent,
the container runtime, the Pod network, the service proxy, cluster DNS and
the volume path.

How it relates to Kubernetes itself:

- Nothing from Kubernetes runs inside a cluster.
- Kubernetes binaries and images are used only as the reference that tests
  compare against. Their versions are pinned.
- The API schema is imported from upstream. Some algorithms (server-side
  apply, CEL type checking, the DRA allocator, the device cgroup filter and
  others) are Ruby ports of the upstream Go code. [`NOTICE`](NOTICE) lists
  each port with its origin and license.

| | |
|---|---|
| Compatibility target | Kubernetes v1.36.2 |
| Official Conformance | 446 of 446 named v1.36.2 cases passed (2026-11-18 UTC, IPv4 native profile) |
| Target environment | Linux x86_64, cgroup v2, root, Ruby 3.4.11 |
| Size | about 220 k lines of Ruby and C under `lib/` and `ext/`, 100 k lines of tests |
| License | Apache-2.0 |

The Conformance result comes from the unmodified `registry.k8s.io/conformance`
image, run through Hydrophone against the `linux-amd64-ipv4-native` profile.

This README is the practical entry point. The specification and design
documents are in [`spec/`](spec/README.md) (Japanese).

## Components

There are six executables, plus a dashboard.

| Executable | Kubernetes counterpart |
|---|---|
| `rubernetes-apiserver` | kube-apiserver and etcd |
| `rubernetes-controller-manager` | kube-controller-manager |
| `rubernetes-scheduler` | kube-scheduler |
| `rubernetes-agent` | kubelet, a CRI runtime and CNI |
| `rubernetes-proxy` | kube-proxy |
| `rubectl` | a subset of kubectl |
| `apps/dashboard` | Kubernetes dashboard and Prometheus |

At runtime a cluster needs Ruby and one small C extension. Some syscalls
cannot be made safely from a forking Ruby VM, and
[`ext/rubernetes_linux`](ext/README.md) makes those.

### rubernetes-apiserver

Serves the whole default API surface and discovery of v1.36.2:

- JSON, YAML and Protobuf
- watch, patch, and server-side apply with field managers
- admission plugins, webhooks and CEL policies
- authentication and authorization, API Priority and Fairness, audit,
  encryption at rest
- CRDs and API aggregation
- feature gates and `--runtime-config`

Data is stored in the built-in Raft datastore under
`lib/rubernetes/consensus/`. It has a CRC-32C WAL, snapshots, joint
consensus, pre-vote, ReadIndex and mutual TLS.

### rubernetes-controller-manager

Runs the upstream controller set: workloads, garbage collection, namespaces,
Endpoints and EndpointSlice, service accounts and tokens, node lifecycle,
CSR approval, PV and PVC, quota and the rest. The controllers sit on an
informer and work-queue framework with leader election.

### rubernetes-scheduler

Implements the scheduling framework with the default plugin set, including
preemption, asynchronous binding and scoring.

### rubernetes-agent

Does the kubelet's job: the Pod sync loop, probes, eviction, graceful node
shutdown, device plugins, the CPU, memory and topology managers, and DRA. It
also serves the kubelet API (`exec`, `logs`, `/metrics`, `/configz` and so
on).

There are three container runtimes:

- native: uses clone3, cgroup v2 and namespaces directly. OCI images are
  pulled and verified in Ruby. Zstandard-compressed layers use the host's
  `libzstd.so.1`.
- microvm: runs a Pod in Firecracker under the jailer, with a
  dm-verity-verified rootfs and a supervisor reached over vsock.
- CRI: connects to an external CRI runtime. It is used only when enabled
  explicitly.

The Pod network is a built-in bridge datapath with dual-stack IPAM,
NetworkPolicy, egress NAT and cluster DNS. NetworkPolicy is enforced with
nftables or eBPF.

### rubernetes-proxy

Handles Service, EndpointSlice, NodePort, session affinity and traffic
policies. It has iptables, nftables and eBPF datapaths, with the same chain
layout and metrics as upstream.

### rubectl

Supports `get`, `create`, `apply`, `patch`, `delete`, `watch`, `logs` and `raw`, and
reads the Ruby Manifest DSL generated from the schema. A real `kubectl`
works just as well.

Use `rubectl logs web-0 -n production -c app --tail 100 -f` to follow a
container's logs. Use `-p` for its previous instance, `--timestamps` for log
timestamps, and either `--since 10m` or `--since-time 2026-11-20T10:00:00Z`
to filter by time. When you omit `-c`, the command uses the Pod's
`kubectl.kubernetes.io/default-container` annotation or the first container.
The command uses the current kubeconfig and requires `get` on `pods` and `pods/log`.

Use `rubectl disk web-0 -n production` to see a Pod’s measured ephemeral
storage, each container’s writable layer and logs, and volume usage by backing
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
`get` access to the Pod and the node’s `nodes/proxy` subresource.

Run `rubectl disk -n production` to rank Pods by ephemeral storage use, with
unmeasured Pods at the end. Use `rubectl disk -A` to rank Pods across all namespaces.
Add `--node worker-1` to limit the ranking to a
single node. The ranking uses `list` access to Pods in that namespace and reads
each relevant node’s summary once. With `-o json`, `pods` contains the ranked
Pod identities, node names, statuses, and totals in bytes.

Run `rubectl disk node/worker-1` to see used, available, and total capacity in
bytes for the node root filesystem and the runtime image and container
filesystems. These entries can refer to the same filesystem, so the report
shows each measurement separately. This command reads the named node’s summary
once and requires `get` access to `nodes/proxy`. With `-o json`, `filesystems`
contains `fs`, `imageFs`, and `containerFs`, each with `usedBytes`,
`availableBytes`, and `capacityBytes`. Missing measurements are `null` in JSON
and `unknown` in text.

### apps/dashboard

A Rails dashboard. It browses the cluster and keeps its own
Prometheus-shaped time-series store, with PromQL, recording and alerting
rules, and a Prometheus-compatible HTTP API. See
[its README](apps/dashboard/README.md).

## Quick start

You need:

- Linux x86_64 with cgroup v2, and root
- `nft` and `iptables`
- Ruby 3.4.11 (pinned by the Gemfile)
- outbound access to pull images
- kubectl v1.36.2 (not needed just to bring a cluster up)

The kubectl checksum is in `test/compatibility/clients/matrix.yml`. KVM is
needed only for the `microvm` RuntimeClass.

```sh
git clone <this repository> && cd 2026
bundle install
rake abi:compile                    # builds the C extension under build/

# Create a cluster: 1 control node and 1 worker, usable in about ten seconds
sudo ruby -Ilib exe/rubectl cluster up

export KUBECONFIG=/var/lib/rubernetes/clusters/default/kubeconfig
kubectl get nodes
kubectl create deployment web --image=nginx --replicas=3
kubectl expose deployment web --port=80 --type=NodePort
kubectl get pods -o wide

sudo ruby -Ilib exe/rubectl cluster status
sudo ruby -Ilib exe/rubectl cluster down     # stop the processes; the state stays on disk
sudo ruby -Ilib exe/rubectl cluster start    # start again from that state, also after a host reboot
sudo ruby -Ilib exe/rubectl cluster scale --controls 3   # grow to 3 control nodes while it runs
```

`rubectl cluster up` builds a cluster on one host, together with the PKI,
the Raft datastore, cluster DNS and a kubeconfig. The state lives in
`/var/lib/rubernetes/clusters/<name>`, and `cluster.json` there lists every process,
port and file it started.

| Option | Meaning |
|---|---|
| `--ha` | 3 control nodes and 3 workers; Raft reaches consensus among three |
| `--controls N`, `--workers N` | choose the node counts yourself |
| `--ip-family ipv4\|ipv6\|dual` | address family of Pods and Services |
| `--identities components` | give each component the identity kubeadm gives it |
| `--name NAME`, `--root DIR` | the cluster's name and where it lives |
| `--no-storage` | no default StorageClass and no hostPath provisioner |

`scale` changes the datastore's membership through Raft joint consensus. The
cluster stays usable during the change, and with three control nodes it keeps
running when one is lost. A smaller `--controls` removes the newest control
nodes: a leader that is leaving hands the lead to a node that stays, and the
components that talked to a removed node are pointed at a remaining one and
restarted.

By default the cluster has a StorageClass named `standard`. A
PersistentVolumeClaim gets a directory on the host as its volume, the way
kube-controller-manager's `--enable-hostpath-provisioner` provides one.

`tools/conformance/cluster.rb`, which the Conformance runs use, calls the
same code (`lib/rubernetes/cluster/`). It only pins the topology to 3+3.

### Before running it on a shared host

`up` removes the following before it starts:

- workloads under `/sys/fs/cgroup/rubernetes`
- stale `rbn*` bridges and `rbn-*` network namespaces in its own network
  namespace

`up` refuses to start while another cluster is alive in the same network
namespace, and when `--root` names a directory holding files that are not a
cluster's. To run several clusters on one host, give each its
own network namespace with `tools/conformance/netns_env.sh`. The steps are
in [tools/conformance/README.md](tools/conformance/README.md).

### Long-lived installation

[deploy/cluster/README.md](deploy/cluster/README.md) describes how to install
a long-lived cluster from release artifacts: systemd units, PKI, upgrade,
backup and restore.

Each daemon reads one YAML file, given with `--config`, and nothing from the
environment. `--check-config` validates the file. Versioned defaults are in
`config/defaults/`.

### Dashboard and metrics

```sh
cd apps/dashboard && bundle install
RUBERNETES_KUBECONFIG=$KUBECONFIG bin/rails server -p 3000
```

Then open `http://localhost:3000`. The dashboard scrapes every API server,
every kubelet and every annotated Pod and Service into its own store. It
serves the Prometheus HTTP API (`/api/v1/query` and the rest), so Grafana can
use it as a Prometheus data source.

## Extensions written in Ruby

Cluster behaviour can be added with one Ruby file. The file is stored in the
API, and the running components load it as it is: nothing is rebuilt and
nothing restarts.

| To add | In Kubernetes | In Rubernetes |
|---|---|---|
| a scheduler Filter or Score | write it in Go, rebuild kube-scheduler and replace it | a `filter` or `score` block |
| admission validation or mutation | deploy a webhook server with its TLS certificates | a `validate` or `mutate` block |
| a controller | build an operator image and deploy it | a `controller` block |

This file makes a `team` label mandatory on Pods and keeps batch work off the
nodes reserved for interactive services:

```ruby
# team_rules.rb
validate "pods", on: :create do |request|
  owner = request.object.dig("metadata", "labels", "team")
  request.reject("Pods need a `team` label so we know whom to ask") if owner.to_s.empty?
end

filter "KeepBatchOffInteractive" do |pod, node|
  next true unless pod.labels["tier"] == "batch"

  node.labels["workload"] == "interactive" ? "node is reserved for interactive workloads" : true
end
```

```sh
sudo ruby -Ilib exe/rubectl cluster up --workers 3 --extensions
export KUBECONFIG=/var/lib/rubernetes/clusters/default/kubeconfig

ruby -Ilib exe/rubectl extension apply team_rules.rb
# team-rules: filter:KeepBatchOffInteractive  validate:pods
#   scheduler   loaded
#   admission   loaded
#   controller  loaded

kubectl run web --image=nginx
# Error from server (Forbidden): extension team-rules denied the request:
# Pods need a `team` label so we know whom to ask
```

The reason a filter returns appears as it is in the scheduling failure
message of `kubectl describe pod`. Fix the file, `apply` it again, and the
next Pod is handled by the new version. A file with a syntax error is refused
on your machine, with the line number.

Run the filter and score blocks in a trusted local file against the Pods and
Nodes in your cluster before installing it. Each node gets a weighted score
or a rejection reason pointing to the Ruby file and line.

```sh
rubectl extension preview examples/extensions/team_rules.rb default/crunch
```

Save the inputs once to replay the same placement rules offline while editing.
The preview evaluates only this extension. It treats the target Pod as incoming
and excludes it from the resident Pods on its current node.

```sh
kubectl get pods,nodes -A -o json > cluster.json
rubectl extension preview examples/extensions/team_rules.rb default/crunch cluster.json
```

With the earlier version saved as `before.rb`, compare eligibility, rejection
reasons and scores for the same inputs. A changed score or weight is shown with
its Ruby source line, even when two changes cancel out in the total.

```sh
rubectl extension diff before.rb examples/extensions/team_rules.rb default/crunch cluster.json
```

`rubectl extension list` shows what each component made of every extension
and how often its blocks raised. Extensions are also visible through
`kubectl get extensions.rubernetes.io`.

An extension runs inside the scheduler, the API servers and the controller
manager, with their privileges. It is not isolated. Treat anyone who can write
an Extension as cluster-admin. Extensions are off by default: only a cluster
brought up with `--extensions`, or a component whose configuration says
`extensions: {enabled: true}`, loads them.

Examples are in [examples/extensions/](examples/extensions/README.md), the
specification in [spec/ruby/extensions.md](spec/ruby/extensions.md).

## Looking inside a running cluster

The components are Ruby processes, so they can be examined without stopping
them. A cluster made by `rubectl cluster up` offers three commands for it,
all run as root on the cluster host.

`rubectl why` shows how the scheduler decided about a Pod: which plugin ruled
each node out, and what every plugin scored the remaining ones. kube-scheduler
shows this only after a restart at a higher verbosity.

```sh
sudo ruby -Ilib exe/rubectl why crunch
# default/crunch: scheduled on worker-2  (attempt 1, 29.71 ms, 2026-11-11T15:34:20.272Z)
#   worker-2    599  TaintToleration 100x3  NodeResourcesFit 99  team-rules.PreferQuietNodes 100x2
#   worker-1    579  TaintToleration 100x3  NodeResourcesFit 99  team-rules.PreferQuietNodes 90x2
#   worker-0      -  team-rules.KeepBatchOffInteractive: node is reserved for interactive workloads
```

`rubectl console` opens a Ruby prompt inside a running component. `help`
lists what is in reach.

```sh
sudo ruby -Ilib exe/rubectl console scheduler
# rubernetes-scheduler (pid 2641363, Ruby 3.4.11) -- `help` lists what is in reach, `exit` leaves
# scheduler> nodes.map { |node| [node.name, node.pods.length] }
# => [["worker-0", 2], ["worker-1", 2], ["worker-2", 3]]
# scheduler> queue
# => #<Rubernetes::Scheduler::SchedulingQueue @capacity @mutex @sequence @pending @unschedulable ...>
# scheduler> ivar(queue, :unschedulable).length
# => 1
```

`rubectl trace` prints the calls of one method as they happen, with
arguments, result and duration. No logging is added and nothing is rebuilt;
the TracePoint it attaches is taken off again when the watch ends.

```sh
sudo ruby -Ilib exe/rubectl trace scheduler "Rubernetes::Scheduler::Framework#schedule" --seconds 30
# 15:37:00.558    78.220 ms  pod=#<Rubernetes::Scheduler::Pod default/t-86d6fc64db-r2sz2> nodes=[3 items] ...  => #<Rubernetes::Scheduler::ScheduleResult scheduled>
```

The console listens on a Unix socket each process owns; only root can open
it. Whoever connects can read and change everything the process holds, which
is the same privilege as attaching a debugger. The specification is
[spec/ruby/console.md](spec/ruby/console.md) (Japanese).

## Manifests written in Ruby

Manifests can be written in Ruby as well. What comes out is standard
Kubernetes objects, so the real `kubectl` takes them as they are.

```ruby
# web.rb
settings = config_map("web-config") { data LOG_LEVEL: "info" }

web = deployment "web" do
  rollout_on settings
  replicas 3

  container "nginx", image: "nginx:1.27" do
    port 80, name: "http"
    cpu request: "100m", limit: "500m"
    ephemeral_storage request: "32Mi", limit: "128Mi"
    env from: settings
    env_field "POD_IP", "status.podIP"
    env_resource "CPU_MILLICORES", "requests.cpu", divisor: "1m"
    http_probe :readiness, port: :http, period_seconds: 5
  end
end

frontend = expose web, ports: {http: 80}
ingress_for frontend, host: "web.example.test", port: :http, class_name: "nginx"
```

`http_probe` resolves `port: :http` against the TCP ports on this container, including ports declared later in the block. If the name is misspelled, `rubectl render` shows the Ruby line and available names.

A Ruby `check` runs after the file's declarations have been evaluated. Use it to enforce rules across resources before `render`, `plan`, or `apply` sends a manifest. A false result reports the check's description and source line.

```ruby
check "production Deployments need a team label" do |resources|
  resources.select { |r| r["kind"] == "Deployment" && r.dig("metadata", "namespace") == "prod" }
           .all? { |r| !r.dig("metadata", "labels", "team").to_s.empty? }
end
```

Use `env_field "TEAM", label: "example.com/team"` or `env_field "REVISION", annotation: "example.com/revision"` to read Pod metadata into the container environment at startup.

Use `env_resource "CPU_MILLICORES", "requests.cpu", divisor: "1m"` to expose the current container's CPU request in millicores. Add `container: "worker"` to read a regular container, init container, or sidecar in the same Pod, including one declared later in the manifest. An omitted divisor uses the Kubernetes default of `1`.

For an app that serves a virtual host, use `http_probe :readiness, port: :http, path: "/ready", headers: {Host: "catalog.example.test"}`. The probe connects to the Pod and sends the specified Host. An array of values sends repeated header fields in order.

Use `tcp_probe :startup, port: :sql` to wait for a database listener or `grpc_probe :readiness, port: 9000, service: "catalog"` to check a gRPC service. For a command inside the container, pass its arguments as an array, such as `exec_probe :liveness, command: ["pg_isready", "-q"]`.

Changing `settings.data` changes the Pod template on the next apply. The Deployment rolls out Pods with the new environment. Editing a ConfigMap label keeps the running Pods. `env from: settings` uses the name from the Ruby declaration.

Inside a container, `mount settings, at: "/etc/app"` creates the Pod volume and mounts the ConfigMap as read-only files. Multiple containers can share the volume. The same helper accepts a declared Secret. To choose a volume name, use `mount "cfg", from: settings, at: "/etc/app"`. A declared PersistentVolumeClaim works the same way. Use `mount uploads, at: "/data"` for a writer and add `read_only: true` for a reader. For a block-mode claim, use `device disk, at: "/dev/data"`.

An ordered array projects multiple sources into one directory. With `mount "cfg", from: [defaults, overrides], at: "/etc/app"`, later entries win when file names overlap.

In a StatefulSet, `data = volume_claim_template "data" do ... end` declares a PVC for each replica. Set fields such as `access_modes ["ReadWriteOnce"]` and `resources { requests storage: "10Gi" }` in the block. Pass the reference to an init or app container with `mount data, at: "/data"`, or `device data, at: "/dev/data"` when the template sets `volume_mode "Block"`.

Share an emptyDir between containers by assigning its declaration to a Ruby variable. The default medium is disk. Use `:memory` for tmpfs and `size_limit:` to bound the volume. Both mounts refer to the same volume in the rendered Pod.

```ruby
pod "report" do
  restart_policy "Never"
  cache = empty_dir "cache", medium: :memory, size_limit: "32Mi"
  init_container("prepare", image: "busybox:1.36") do
    mount cache, at: "/out"
    command ["sh", "-c", "echo ready > /out/status"]
  end
  container("reader", image: "busybox:1.36") do
    mount cache, at: "/input", read_only: true
    command ["cat", "/input/status"]
  end
end
```

Group declarations by environment with `in_namespace "preview" do ... end`. Namespaced resources in the block default to `preview`, and a resource’s `namespace:` takes precedence. Nested blocks restore the surrounding namespace when they exit. Cluster-scoped resources such as Namespace and ClusterRole carry no inferred namespace.

```ruby
in_namespace "preview" do
  account = service_account "web"
  registry = secret "registry" do
    type "kubernetes.io/dockerconfigjson"
    string_data ".dockerconfigjson" => ENV.fetch("DOCKER_CONFIG_JSON")
  end

  deployment "web" do
    use_service_account account
    image_pull_secrets registry
    container "app", image: "registry.example.test/web:1"
  end
end
```

Pass `--env DOCKER_CONFIG_JSON` when evaluating this file with rubectl. These
helpers set `serviceAccountName` and `imagePullSecrets` in a Pod or workload’s
Pod spec, including Jobs and CronJobs. Declared references must share the
workload’s namespace. Pull secrets are added once by name to any raw list you
set with `image_pull_secrets [{name: "existing"}]` in the Pod spec. To reference
a pull Secret already in the cluster, use `image_pull_secrets secret("existing")`.

`expose web, ports: {http: 80}` builds a Service in the Deployment’s namespace, using its selector and the named container port `http`. Add `prefer: :same_zone` or `prefer: :same_node` to prefer endpoints in the same zone or on the same node through the Service’s `trafficDistribution` field. If a port name or traffic preference is misspelled, `render` and `apply` report the Ruby source line and valid names before contacting the cluster.

To expose a workload through the routed load balancer, use
`expose web, ports: {http: 80}, type: :load_balancer, load_balancer_class: "rubernetes.io/routed", allocate_node_ports: false`.
The Service uses the configured routed address pool and leaves its NodePorts unallocated.

`ingress_for` builds a `networking.k8s.io/v1` Ingress with the same name and namespace as the declared Service. Pass the result of `service` or `expose`. If the Service declares a single TCP port, `port:` can be omitted. For multiple ports, select a TCP Service port by name or number, such as `:http` or `80`. The default is `path: "/"` with `path_type: :prefix`. Use `path_type: :exact` for an exact match and `class_name:` to select an IngressClass. Traffic is handled by the cluster’s Ingress controller.

`sidecar("proxy", image: "proxy:1") { port 8443, name: "https" }` declares a Kubernetes restartable sidecar. The proxy starts before subsequent init containers, and `expose web, ports: {https: 443}` can publish its named port.

Inside a workload block, `spread_across "topology.kubernetes.io/zone"` spreads replicas across zones with a maximum skew of one. The helper reuses the workload’s final Pod selector, including expressions. Use `when_unsatisfiable: :schedule_anyway` to keep scheduling when a zone is unavailable.

`autoscale web, replicas: 2..8, cpu: 70` declares a HorizontalPodAutoscaler in the workload’s namespace. It targets 70% of requested CPU across two to eight replicas. For autoscaled workloads, omit the Deployment’s fixed replica count, set container CPU requests and enable the resource metrics API in the cluster.

Adding `container: :api` to `autoscale` targets only the CPU or memory utilization of the declared `api` container. This lets a workload with a proxy sidecar scale on application load.

Load the gem's `sig/` directory in an RBS-aware editor to complete declaration and helper method names and see their keyword arguments and types. A name declared in the manifest, such as `:api`, is resolved at evaluation time. A misspelled container name reports the Ruby line and available containers.

A Ruby manifest runs with `Rubernetes::Manifest::Builder` as top-level `self`, including inside `in_namespace`. A `resource` block uses `Rubernetes::Manifest::ObjectBuilder` as `self`. For Steep, put the receiver annotation inside a Ruby block. The example uses `tap`, which preserves the manifest receiver.

```ruby
tap do
  # @type self: Rubernetes::Manifest::Builder
  web = deployment :web, namespace: :preview do
    container :api, image: "nginx:1.27" do
      port 80, name: "http"
      cpu request: "100m"
    end
  end

  frontend = expose web, ports: {http: 80}
  ingress_for frontend, host: "web.example.test", port: :http
  autoscale web, replicas: 2..8, cpu: 70, container: :api
  disruption_budget web, max_unavailable: "25%"
end
```

Inspect the installed gem with `rbs -r rubernetes method Rubernetes::Manifest::Builder autoscale`. From a checkout, run `bundle exec rbs -I sig method Rubernetes::Manifest::Builder autoscale`.

Run `rubectl plan -f web.rb --allow-code` to preview each declaration using server-side apply against the current cluster. The output identifies resources to create or update and lists changed field paths. Editing a ConfigMap used by `rollout_on` shows both the changed data key and the Deployment’s Pod template. Secret values stay out of the plan. Add `-o text` to see each action next to its Ruby declaration (for example, `web.rb:8  UPDATE Deployment/prod/web`) followed by its changed field paths.

If the API rejects a Ruby resource during `plan` or `apply`, rubectl shows its kind and name alongside the declaration’s relative path and line number, followed by the API error with Secret values redacted.

When a ConfigMap key belongs to another field manager, the conflict identifies its owner and field. Preview the transfer with `rubectl plan -f app.rb --allow-code -o text --field-manager ruby-two --force`. Applying with the same field manager and `--force` commits the change.

```sh
ruby -Ilib exe/rubectl render -f web.rb --allow-code -o yaml | kubectl apply -f -
```

The `selector`, and the template labels it has to match, are filled in when
they are not written. Fields are checked against the schema, so a slip shows
before anything is applied:

```text
web.rb:9: containers.nginx.readinessProbe.httpGet: HTTPGetAction has no field "pathh" (did you mean "path"?)
```

Loops, conditions and shared parts are plain Ruby. The file is evaluated in a
separate process with no network and no cluster credentials. Examples are in
[examples/manifests/](examples/manifests/README.md), the specification in
[spec/ruby/manifest-dsl.md](spec/ruby/manifest-dsl.md) (Japanese).

### Preview CronJob schedules

Save this CronJob as `nightly.rb` to preview its schedule before applying it.

```ruby
cron_job "nightly", namespace: "default" do
  schedule "30 1 * * *"
  time_zone "America/New_York"
  container("report", image: "busybox:1.36") { command ["echo", "ready"] }
end
```

```sh
rubectl cron -f nightly.rb --allow-code --from 2026-11-01T04:45:00Z --count 2
rubectl apply -f nightly.rb --allow-code
```

`cron` works offline. It lists times strictly after the supplied RFC3339 timestamp, five per CronJob by default. The example returns `01:30:00-04:00` and `01:30:00-05:00` during the same fall-back transition. Times use the declared `time_zone`, or UTC when omitted. An `@every` schedule uses `--from` as its starting time. The controller also considers suspension, concurrency, and starting deadlines when deciding whether to create a Job.

## Repository layout

| Path | Contents |
|---|---|
| [`lib/rubernetes/`](lib/rubernetes/README.md) | Production code, one directory per subsystem (`api/`, `consensus/`, `scheduler/`, `node/` and so on) |
| [`exe/`](exe/README.md) | The six executables. They parse options and hand over to `lib/rubernetes/bootstrap` |
| [`ext/rubernetes_linux/`](ext/README.md) | The C extension: `clone3` plus exec, and typed syscalls |
| `schema/` | The schema, OpenAPI and defaults imported from Kubernetes v1.36.2 |
| `generated/` | Ruby types, RBS, codecs and the Manifest DSL generated from `schema/`. Never edited by hand |
| [`spec/`](spec/README.md) | The specification and design documents |
| [`test/`](test/README.md) | Unit, property, integration, e2e, chaos, security and compatibility suites, plus the conformance profiles |
| [`tools/`](tools/README.md) | Automation written in Ruby: schema import and generation, conformance, milestone gates, formal verification, release |
| [`verification/`](verification/README.md) | TLA+ and Lean models, and trace schemas |
| [`third_party/locks/`](third_party/locks/README.md) | Every upstream source, image and binary, pinned by commit and digest |
| [`deploy/`](deploy/cluster/README.md) | systemd units and operating procedures |
| [`apps/dashboard/`](apps/dashboard/README.md) | The Rails dashboard and metrics server |
| `benchmarks/` | Benchmarks |
| `artifacts/` | Evidence bundles. Not tracked by Git |

## Development

```sh
bundle install
rake abi:compile                 # once, and again after changing ext/
rake test:parallel               # whole suite, one process per file, about 6 min; JOBS=n sets the width
rake test                        # serial run, about 1 h; the evidence gates use this one
ruby -Ilib -Itest test/unit/some_test.rb -n /pattern/
rake lint                        # RuboCop, 160 columns, double quotes
rake lint:fix                    # safe autocorrect only; re-run the tests afterwards
rake rbs:generate                # refresh manifest resource signatures after updating the schema
rake rbs:validate                # check the signatures against the live DSL and validate RBS
```

Follow these rules when you change the code.

### Generate types from the schema

Do not write Kubernetes types by hand. To change a type, change the importer
or generator under `tools/schema/` and regenerate. Generated output must be
reproducible byte for byte.

### Check behaviour against upstream

When you add API, controller, scheduler or kubelet behaviour, add a test
that compares the result with the pinned Kubernetes binaries or images.
Where that is not possible, derive the test from the corresponding upstream
test. Your own reading of the source is not enough evidence.

### Never report an unexecuted check as a pass

A check that lacks an adapter, a kernel feature or an external runner
reports `INCOMPLETE` or an error. A waiver is recorded with its name and
reason; the kernel waiver in
[tools/milestones/README.md](tools/milestones/README.md) is an example.

### Assume duck typing

Every RuboCop cop that is turned off is listed in `.rubocop.yml` with the
reason. Most of them have an autocorrect that assumes a concrete receiver
type: `grep` on a Struct, `partition` on a Hash, `empty?` on a `File::Stat`.
`rake lint` stays at zero offenses and there is no todo file. List
format-only commits in `.git-blame-ignore-revs`.

### Load the whole library after adding a require

After adding a `require` under `lib/`, load the whole library once:

```sh
ruby -Ilib -e 'require "rubernetes"'
```

A wrong `require_relative` raises no error until a process loads that file.

### Create commits with the tool

`rake repo:commit` splits the changes in the work tree into commits.
`ruby tools/repo/auto_commit.rb --cycle <name> --status 0` does the same.
The tool:

- makes one commit per contiguous edit
- names each commit after the declaration the change belongs to
- orders sources before tests before documents
- publishes with a compare-and-swap on HEAD
- commits unstaged changes too, so stash anything that should not land
- adds no trailers other than the author

## Verification

There are four kinds of verification.

### Tests

Run with `rake test`. There are about 3,400 test cases across the unit,
property, integration, chaos and security suites. They include tests that
compare codecs, validation, server-side apply, controllers and the scheduler
with reference programs written in Go.

### Kubernetes Conformance and compatibility

Run with [tools/conformance](tools/conformance/README.md). The checks are
split into eight lanes, K0 to K7.

| Lane | What it checks |
|---|---|
| K0 | Integrity of the inputs |
| K1 | The official Conformance suite, run through Hydrophone |
| K2 | Sonobuoy certified-conformance |
| K3 | The whole e2e inventory, run according to a ledger that classifies 7,579 specs |
| K4 | Node conformance |
| K5 | Comparison against a real kube-apiserver |
| K6 | 32 upstream Helm charts and operators |
| K7 | Cluster lifecycle |

The K3 ledger is `test/compatibility/api/selection-ledger.json`. There are
three profiles (IPv4, IPv6 and dual-stack), each with three control nodes
and three workers. They are defined in
`test/conformance/kubernetes/profiles.yml`.

### Formal models

These are in [verification/](verification/README.md). Raft and the runtime
lifecycle are specified in TLA+ and Lean; the TLA+ specifications are checked
with TLC and Apalache. Journals written by the production code are replayed
as traces to confirm that the implementation matches the models. There is
also a linearizability checker that works on real client histories.

### Milestone evidence gates

Run with [tools/milestones](tools/milestones/README.md). There are ten
milestones, from M0 (executable foundation) to M9 (release). Each one
collects its check results into an evidence bundle, and a gate re-checks the
bundle. A bundle includes the results of the milestones before it, so a
source change invalidates every later milestone as well. The commands are
`rake m<n>:evidence` and `rake m<n>:verify`.

## Status and known limitations

As of 2026-10-01.

### Platform

Linux x86_64 only. arm64 has not been tested. The kernels exercised are 6.8
and later. One M4 check, an SCTP CRC32c helper, needs kernel 6.12 and is
recorded as a waiver on older kernels.

### Networking

The Pod network defaults to the built-in bridge. The agent can also run CNI
plugins with `network.plugin: cni`. The Conformance runs use the built-in
bridge.

IPv6-only clusters can use an existing NAT64 gateway with
`rubectl cluster up --ip-family ipv6 --nat64-prefix CIDR`. Configure the
node's IPv6 route for that prefix through the gateway before bringing up
the cluster. See [IPv6-only Pod egress](spec/node/network.md#sec-5-9-9).

You can expose LoadBalancer Services on bare metal from a routed IP pool with
`rubectl cluster up --load-balancer-pool CIDR` and the `rubernetes.io/routed`
class. Add `--default-routed-load-balancer` to also serve charts that omit
`spec.loadBalancerClass`. Cloud installations can deploy their provider's
external Cloud Controller Manager for classless Services. See [LoadBalancer Services](deploy/cluster/README.md#loadbalancer-services).

### Scale

Every measurement was taken on a six-node cluster built on one host. A
multi-host cluster can be configured with the same YAML, but has not been
verified end to end.

### Metrics

The metrics registry exposes upstream metric names, including cAdvisor and
kube-proxy families. Some families describe mechanisms specific to a different
runtime or platform, such as etcd leases and Windows HostProcess containers.
Their HELP text explains why the family has no samples. The per-component
list is in [metrics.rb](lib/rubernetes/observability/metrics.rb).

### Alpha APIs

Use `--runtime-config` to serve an alpha API version and enable its feature gate where required. The compatibility table covers all 44 gates marked Alpha in the pinned Kubernetes v1.36.2 feature corpus. It links each behavior to its implementation or test and identifies checks that require a particular kernel, runtime or device. [Alpha feature gate coverage](spec/verification/alpha-feature-gates.md)

### Evidence bundles

The bundles on disk were captured before the latest source changes, so they
are not valid for the current source. The gates and the Conformance suite
have been re-run on the current tree. A release candidate has to re-capture
M0 through M9.

### Lint

`rake lint` reports zero offenses over the whole tree.

## Documentation

- [Specification index](spec/README.md) and [architecture](spec/foundation/architecture.md)
- [Extensions written in Ruby: specification](spec/ruby/extensions.md) and [examples](examples/extensions/README.md)
- [Milestones and completion gates](spec/delivery/milestones.md)
- [Kubernetes compatibility contract](spec/verification/kubernetes-compatibility.md)
- [Coding standards](spec/delivery/coding-standards.md) and [project structure](spec/delivery/project-structure.md)
- [Operating a cluster](deploy/cluster/README.md)
- [Conformance tooling](tools/conformance/README.md) and [milestone gates](tools/milestones/README.md)

## License

Apache License 2.0. The full text is in [LICENSE](LICENSE). Upstream-derived
parts and their licenses are listed in [NOTICE](NOTICE).
