# frozen_string_literal: true

require "json"
require "yaml"
require "tmpdir"

# A stand-in for Rubernetes::Client::KubernetesClient over a fixed set of
# objects, recording the writes the dashboard performs.
class FakeCluster
  Response = Struct.new(:status, :body, :headers, keyword_init: true)

  attr_reader :writes, :objects

  def initialize(objects = FakeCluster.default_objects)
    @objects = objects
    @writes = []
  end

  def self.default_objects
    {
      "nodes" => [node("worker-0"), node("worker-1", ready: false)],
      "namespaces" => [{"metadata" => {"name" => "default", "creationTimestamp" => "2026-09-29T08:00:00Z"}, "status" => {"phase" => "Active"}},
                       {"metadata" => {"name" => "gitlab", "creationTimestamp" => "2026-09-29T08:00:00Z"},
                        "status" => {"phase" => "Active"}}],
      "pods" => [pod("web-1", "gitlab", "worker-0", phase: "Running", ready: true),
                 pod("crash-1", "gitlab", "worker-1", phase: "Running", ready: false, waiting: "CrashLoopBackOff", restarts: 7),
                 pod("job-1", "default", "worker-0", phase: "Succeeded", ready: false)],
      "deployments" => [{"metadata" => {"name" => "web", "namespace" => "gitlab", "creationTimestamp" => "2026-09-29T08:00:00Z"},
                         "spec" => {"replicas" => 2, "selector" => {"matchLabels" => {"app" => "web"}},
                                    "template" => {"spec" => {"containers" => [{"name" => "web", "image" => "web:1"}]}}},
                         "status" => {"replicas" => 2, "readyReplicas" => 1, "availableReplicas" => 1, "updatedReplicas" => 2,
                                      "conditions" => [{"type" => "Available", "status" => "False", "reason" => "MinimumReplicasUnavailable"}]}}],
      "statefulsets" => [], "daemonsets" => [], "jobs" => [], "cronjobs" => [], "replicasets" => [],
      "services" => [{"metadata" => {"name" => "web", "namespace" => "gitlab", "creationTimestamp" => "2026-09-29T08:00:00Z"},
                      "spec" => {"type" => "ClusterIP", "clusterIP" => "10.96.0.10", "ports" => [{"port" => 80, "protocol" => "TCP"}],
                                 "selector" => {"app" => "web"}}}],
      "ingresses" => [], "endpointslices" => [], "configmaps" => [{"metadata" => {"name" => "cfg", "namespace" => "gitlab"}, "data" => {"a" => "1"}}],
      "secrets" => [{"metadata" => {"name" => "sec", "namespace" => "gitlab"}, "type" => "Opaque", "data" => {"password" => "c2VjcmV0"}}],
      "persistentvolumeclaims" => [], "serviceaccounts" => [], "horizontalpodautoscalers" => [], "resourcequotas" => [],
      "persistentvolumes" => [], "storageclasses" => [], "ingressclasses" => [], "customresourcedefinitions" => [], "clusterroles" => [], "priorityclasses" => [],
      "events" => [{"metadata" => {"name" => "e1", "namespace" => "gitlab", "creationTimestamp" => "2026-09-29T09:00:00Z"}, "type" => "Warning", "reason" => "BackOff",
                    "message" => "Back-off restarting failed container", "count" => 7, "lastTimestamp" => "2026-09-29T09:05:00Z",
                    "involvedObject" => {"kind" => "Pod", "name" => "crash-1", "namespace" => "gitlab", "fieldPath" => "spec.containers{c}"}}]
    }
  end

  def self.node(name, ready: true)
    {"metadata" => {"name" => name, "creationTimestamp" => "2026-09-29T08:00:00Z", "labels" => {"node-role.kubernetes.io/worker" => ""}},
     "spec" => {},
     "status" => {"conditions" => [{"type" => "Ready", "status" => ready ? "True" : "False", "reason" => ready ? "KubeletReady" : "KubeletNotReady"}],
                  "nodeInfo" => {"kubeletVersion" => "v1.36.2", "osImage" => "Ubuntu", "kernelVersion" => "7.0.0"},
                  "addresses" => [{"type" => "InternalIP", "address" => "10.240.0.1"}],
                  "capacity" => {"cpu" => "64", "memory" => "128Gi", "pods" => "110"},
                  "allocatable" => {"cpu" => "63", "memory" => "120Gi", "pods" => "110"}}}
  end

  def self.pod(name, namespace, node, phase:, ready:, waiting: nil, restarts: 0)
    state = if waiting
              {"waiting" => {"reason" => waiting}}
            else
              (if phase == "Succeeded"
                 {"terminated" => {"reason" => "Completed",
                                   "exitCode" => 0}}
               else
                 {"running" => {"startedAt" => "2026-09-29T09:00:00Z"}}
               end)
            end
    {"metadata" => {"name" => name, "namespace" => namespace, "uid" => "uid-#{name}", "creationTimestamp" => "2026-09-29T09:00:00Z", "labels" => {"app" => "web"}},
     "spec" => {"nodeName" => node, "containers" => [{"name" => "c", "image" => "img:1", "ports" => [{"containerPort" => 8080}]}],
                "volumes" => [{"name" => "data", "emptyDir" => {}}]},
     "status" => {"phase" => phase, "podIP" => "10.240.0.9", "startTime" => "2026-09-29T09:00:00Z", "qosClass" => "BestEffort",
                  "conditions" => [{"type" => "Ready", "status" => ready ? "True" : "False"}],
                  "containerStatuses" => [{"name" => "c", "ready" => ready, "restartCount" => restarts, "state" => state}]}}
  end

  def get(resource, name = nil, namespace: nil, api_version: "v1", query: nil, **)
    items = Array(@objects[resource])
    items = items.select { |o| o.dig("metadata", "namespace") == namespace } if namespace && namespace != :all
    if query && query["fieldSelector"]
      query["fieldSelector"].split(",").each do |pair|
        key, value = pair.split("=", 2)
        items = items.select do |o|
          case key
          when "spec.nodeName" then o.dig("spec", "nodeName") == value
          when "involvedObject.name" then o.dig("involvedObject", "name") == value
          when "involvedObject.kind" then o.dig("involvedObject", "kind") == value
          else true
          end
        end
      end
    end
    if query && query["labelSelector"]
      wanted = query["labelSelector"].split(",").to_h { |pair| pair.split("=", 2) }
      items = items.select { |o| wanted.all? { |k, v| o.dig("metadata", "labels", k) == v } }
    end
    if name
      found = items.find { |o| o.dig("metadata", "name") == name }
      raise "not found: #{resource}/#{name}" unless found

      return found
    end
    {"kind" => "List", "items" => items}
  end

  def raw(_method, path, query: nil, raise_for_status: true, **)
    if path.end_with?("/log")
      Response.new(status: 200, body: "line 1\nline 2\ncontainer=#{query && query["container"]}\n", headers: {})
    else
      Response.new(status: 200, body: "", headers: {})
    end
  end

  def patch(resource, name, patch, namespace: nil, api_version: "v1", type: :merge, **)
    @writes << [:patch, resource, name, namespace, patch, type]
    get(resource, name, namespace: namespace)
  end

  def delete(resource, name, namespace: nil, api_version: "v1", options: nil, **)
    @writes << [:delete, resource, name, namespace, options]
    {"kind" => "Status", "status" => "Success"}
  end
end

# A runtime over a FakeCluster and a temporary store, seeded with a few
# series so the API and graph pages have data.
module DashboardTestRuntime
  def self.build(objects: FakeCluster.default_objects, now_ms: (Time.now.to_f * 1000).to_i)
    dir = Dir.mktmpdir("dashboard-test")
    store = Tsdb::Store.new(dir)
    cluster = FakeCluster.new(objects)
    engine = Promql::Engine.new(store, now: -> { now_ms })
    scraper = Prom::Scraper.new(store, clock: -> { now_ms })
    rules = Prom::Rules.new({"groups" => [{"name" => "test", "rules" => [{"alert" => "TargetDown", "expr" => "up == 0", "labels" => {"severity" => "critical"},
                                                                          "annotations" => {"summary" => "{{ $labels.instance }} down"}},
                                                                         {"record" => "job:up:avg", "expr" => "avg by (job) (up)"}]}]})
    runtime = Dashboard::Runtime.new(client: cluster, store: store, engine: engine, rules: rules)
    runtime.instance_variable_set(:@scraper, scraper)
    collector = Prom::Collector.new(store: store, targets: -> { [] }, scraper: scraper, engine: engine, rules: rules, interval_seconds: 15,
                                    clock: -> { now_ms })
    runtime.instance_variable_set(:@collector, collector)
    seed(store, scraper, now_ms)
    rules.evaluate(engine, now_ms)
    [runtime, cluster, dir]
  end

  def self.seed(store, scraper, now_ms)
    body_up = "# TYPE requests_total counter\nrequests_total{code=\"200\"} 120\nrequests_total{code=\"500\"} 3\n"
    good = Prom::Target.new(job: "apiserver", instance: "127.0.0.1:39307", labels: {"process" => "apiserver-control-0"}, url: "https://127.0.0.1:39307/metrics",
                            fetch: -> { [200, body_up] })
    bad = Prom::Target.new(job: "kubelet", instance: "worker-1", labels: {"node" => "worker-1"}, url: "https://api/api/v1/nodes/worker-1/proxy/metrics",
                           fetch: -> { raise Errno::ECONNREFUSED, "no route" })
    node = Prom::Target.new(job: "kubelet-resource", instance: "worker-0", labels: {"node" => "worker-0"}, url: "internal://node",
                            fetch: -> { [200, "node_cpu_usage_seconds_total 100\nnode_memory_working_set_bytes 2147483648\n"] })
    scraper.scrape(good)
    scraper.scrape(bad)
    scraper.scrape(node)
    # A little history for range queries.
    5.times do |i|
      store.append({"__name__" => "history", "k" => "v"}, now_ms - ((5 - i) * 15_000), i.to_f)
    end
  end
end
