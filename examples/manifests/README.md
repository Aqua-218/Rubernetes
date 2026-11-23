# Manifests written in Ruby

English | [日本語](README.ja.md)

Manifests written in Ruby. What comes out is standard Kubernetes objects, so
the real `kubectl` takes them as they are. The rules are in the
[specification](../../spec/ruby/manifest-dsl.md) (Japanese).

| File | What it declares |
|---|---|
| [web.rb](web.rb) | A ConfigMap, a Deployment and a Service. Production also scales from 3 to 8 replicas at 70% CPU utilization |
| [tenants.rb](tenants.rb) | A namespace, a ResourceQuota and a Deployment for each tenant in a list |
| [nightly_report.rb](nightly_report.rb) | A CronJob with a Secret and a scratch volume |

## Using them

`render` only shows the output; no cluster is contacted.

```sh
ruby -Ilib exe/rubectl render -f examples/manifests/web.rb --allow-code -o yaml
```

To apply, hand the output of `render` to `kubectl`, or use `rubectl apply`:

```sh
ruby -Ilib exe/rubectl render -f examples/manifests/web.rb --allow-code -o yaml | kubectl apply -f -
APP_ENV=production ruby -Ilib exe/rubectl apply -f examples/manifests/web.rb --allow-code --env APP_ENV
```

The Ruby file is evaluated in a separate process with no network and no
cluster credentials. Only the environment variables named with `--env` reach
it.

## What is different from YAML

A Deployment is written like this. The `selector`, and the template labels it
has to match, are filled in when they are not written.

```ruby
deployment "web" do
  replicas 3

  container "nginx", image: "nginx:1.27" do
    port 80, name: :http
    cpu request: "100m", limit: "500m"
    env from: configmap("web-config")
    http_probe :readiness, port: :http, period_seconds: 5
  end
end
```

Fields are checked against the schema. A slip is reported before anything is
applied, with its line and the nearest name:

```text
web.rb:9: containers.nginx.readinessProbe.httpGet: HTTPGetAction has no field "pathh" (did you mean "path"?)
web.rb:2: Deployment has no field or helper "replica" (did you mean "replicas"?)
```

Loops, conditions and shared parts are plain Ruby; no template language is
needed. [tenants.rb](tenants.rb) shows it.

## Helpers

The short forms available inside a workload block.

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

Group declarations by environment with `in_namespace "preview" do ... end`. Namespaced resources in the block default to `preview`, and a resource's `namespace:` takes precedence. Nested blocks restore the surrounding namespace when they exit. Cluster-scoped resources such as Namespace and ClusterRole carry no inferred namespace.

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
helpers set `serviceAccountName` and `imagePullSecrets` in a Pod or workload's
Pod spec, including Jobs and CronJobs. Declared references must share the
workload's namespace. Pull secrets are added once by name to any raw list you
set with `image_pull_secrets [{name: "existing"}]` in the Pod spec. To reference
a pull Secret already in the cluster, use `image_pull_secrets secret("existing")`.

`expose web, ports: {http: 80}` builds a Service in the Deployment's namespace, using its selector and the named container port `http`. Add `prefer: :same_zone` or `prefer: :same_node` to prefer endpoints in the same zone or on the same node through the Service's `trafficDistribution` field. If a port name or traffic preference is misspelled, `render` and `apply` report the Ruby source line and valid names before contacting the cluster.

To expose a workload through the routed load balancer, use
`expose web, ports: {http: 80}, type: :load_balancer, load_balancer_class: "rubernetes.io/routed", allocate_node_ports: false`.
The Service uses the configured routed address pool and leaves its NodePorts unallocated.

`ingress_for` builds a `networking.k8s.io/v1` Ingress with the same name and namespace as the declared Service. Pass the result of `service` or `expose`. If the Service declares a single TCP port, `port:` can be omitted. For multiple ports, select a TCP Service port by name or number, such as `:http` or `80`. The default is `path: "/"` with `path_type: :prefix`. Use `path_type: :exact` for an exact match and `class_name:` to select an IngressClass. Traffic is handled by the cluster's Ingress controller.

`sidecar("proxy", image: "proxy:1") { port 8443, name: "https" }` declares a Kubernetes restartable sidecar. The proxy starts before subsequent init containers, and `expose web, ports: {https: 443}` can publish its named port.

Inside a workload block, `spread_across "topology.kubernetes.io/zone"` spreads replicas across zones with a maximum skew of one. The helper reuses the workload's final Pod selector, including expressions. Use `when_unsatisfiable: :schedule_anyway` to keep scheduling when a zone is unavailable.

`autoscale web, replicas: 2..8, cpu: 70` declares a HorizontalPodAutoscaler in the workload's namespace. It targets 70% of requested CPU across two to eight replicas. For autoscaled workloads, omit the Deployment's fixed replica count, set container CPU requests and enable the resource metrics API in the cluster.

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
