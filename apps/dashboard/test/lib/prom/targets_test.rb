# frozen_string_literal: true

require "test_helper"
require "tmpdir"

module Prom
  class TargetsTest < ActiveSupport::TestCase
    class FakeClient
      def initialize(objects)
        @objects = objects
      end

    def get(resource, api_version: "v1", **)
      {"items" => @objects.fetch(resource, [])}
    end

    def raw(_method, path, **)
      Struct.new(:status, :body).new(200, "proxied #{path}\n")
    end
  end

  def pod(name, ns, ip, annotations, node: "worker-0", phase: "Running")
    {"metadata" => {"name" => name, "namespace" => ns, "annotations" => annotations},
     "spec" => {"nodeName" => node, "containers" => [{"name" => "c", "ports" => [{"containerPort" => 8080}]}]},
     "status" => {"podIP" => ip, "phase" => phase}}
  end

  test "discovers kubelet endpoints, annotated pods and annotated services" do
    objects = {
      "nodes" => [{"metadata" => {"name" => "worker-0"}}, {"metadata" => {"name" => "worker-1"}}],
      "pods" => [
        pod("gitaly-0", "gitlab", "10.240.0.6",
            {"prometheus.io/scrape" => "true", "prometheus.io/port" => "9236", "prometheus.io/path" => "/metrics"}),
        pod("plain", "default", "10.240.0.7", {}),
        pod("noport", "default", "10.240.0.8", {"prometheus.io/scrape" => "true"}),
        pod("pending", "default", "", {"prometheus.io/scrape" => "true"}, phase: "Pending"),
        pod("v6", "default", "fd00::5", {"prometheus.io/scrape" => "true", "prometheus.io/port" => "80", "prometheus.io/path" => "stats"})
      ],
      "services" => [{"metadata" => {"name" => "exporter", "namespace" => "gitlab", "annotations" => {"prometheus.io/scrape" => "true"}}}],
      "endpointslices" => [{"metadata" => {"name" => "exporter-abc", "namespace" => "gitlab", "labels" => {"kubernetes.io/service-name" => "exporter"}},
                            "ports" => [{"port" => 9168}],
                            "endpoints" => [{"addresses" => ["10.242.0.9"], "conditions" => {"ready" => true}, "nodeName" => "worker-2",
                                             "targetRef" => {"name" => "exporter-pod"}},
                                            {"addresses" => ["10.242.0.10"], "conditions" => {"ready" => false}}]}]
    }
    fetched = []
    targets = Prom::Targets.new(client: FakeClient.new(objects), cluster_json: {}, kubeconfig_context: {server: "https://api:6443"},
                                http: lambda { |url|
                                  fetched << url
                                  [200, "x 1\n"]
                                })
    all = targets.discover
    jobs = all.group_by(&:job).transform_values(&:length)

    assert_equal({"kubelet" => 2, "cadvisor" => 2, "kubelet-resource" => 2, "kubelet-probes" => 2,
                  "kubernetes-pods" => 3, "kubernetes-service-endpoints" => 1}, jobs)

    kubelet = all.find { |t| t.job == "kubelet" && t.instance == "worker-1" }

    assert_equal "https://api:6443/api/v1/nodes/worker-1/proxy/metrics", kubelet.url
    assert_equal [200, "proxied /api/v1/nodes/worker-1/proxy/metrics\n"], kubelet.fetch.call

    gitaly = all.find { |t| t.labels["pod"] == "gitaly-0" }

    assert_equal "http://10.240.0.6:9236/metrics", gitaly.url
    assert_equal({"namespace" => "gitlab", "pod" => "gitaly-0", "node" => "worker-0"}, gitaly.labels)
    gitaly.fetch.call

    assert_equal ["http://10.240.0.6:9236/metrics"], fetched

    noport = all.find { |t| t.labels["pod"] == "noport" }

    assert_equal "http://10.240.0.8:8080/metrics", noport.url, "falls back to the first container port"
    v6 = all.find { |t| t.labels["pod"] == "v6" }

    assert_equal "http://[fd00::5]:80/stats", v6.url

    endpoint = all.find { |t| t.job == "kubernetes-service-endpoints" }

    assert_equal "http://10.242.0.9:9168/metrics", endpoint.url
    assert_equal({"namespace" => "gitlab", "service" => "exporter", "pod" => "exporter-pod", "node" => "worker-2"}, endpoint.labels)
  end

  test "api servers come from cluster.json process configs" do
    Dir.mktmpdir do |dir|
      config = File.join(dir, "apiserver-control-0.yml")
      File.write(config, {"processes" => {"rubernetes-apiserver" => {"port" => 39_307}}}.to_yaml)
      cluster = {"processes" => [{"name" => "apiserver-control-0", "executable" => "rubernetes-apiserver", "config" => config},
                                 {"name" => "scheduler", "executable" => "rubernetes-scheduler", "config" => config}]}
      context = {server: "https://127.0.0.1:39307", insecure_skip_tls_verify: true}
      targets = Prom::Targets.new(client: FakeClient.new({}), cluster_json: cluster, kubeconfig_context: context)
      apiservers = targets.apiserver_targets

      assert_equal 1, apiservers.length
      assert_equal "127.0.0.1:39307", apiservers[0].instance
      assert_equal({"process" => "apiserver-control-0"}, apiservers[0].labels)
      assert_equal "https://127.0.0.1:39307/metrics", apiservers[0].url
    end
  end

  test "discovery failures yield no targets rather than raising" do
    broken = Object.new
    broken.define_singleton_method(:get) { |*| raise "api down" }
    targets = Prom::Targets.new(client: broken, cluster_json: {})

    assert_equal [], targets.discover
  end

  test "discovers the scheduler, controller manager and proxies from their serving config" do
    Dir.mktmpdir do |dir|
      write = lambda do |name, process, port|
        path = File.join(dir, "#{name}.yml")
        File.write(path,
                   {"version" => 1,
                    "processes" => {process => {"serving" => {"enabled" => true, "bind_address" => "127.0.0.1", "port" => port}}}}.to_yaml)
        path
      end
      off = File.join(dir, "proxy-worker-1.yml")
      File.write(off, {"version" => 1, "processes" => {"rubernetes-proxy" => {"node_name" => "worker-1"}}}.to_yaml)
      cluster = {"processes" => [
        {"name" => "scheduler", "executable" => "rubernetes-scheduler",
         "config" => write.call("scheduler", "rubernetes-scheduler", 21_001)},
        {"name" => "controller-manager", "executable" => "rubernetes-controller-manager",
         "config" => write.call("controller-manager", "rubernetes-controller-manager", 21_002)},
        {"name" => "proxy-worker-0", "executable" => "rubernetes-proxy",
         "config" => write.call("proxy-worker-0", "rubernetes-proxy", 21_003)},
        {"name" => "proxy-worker-1", "executable" => "rubernetes-proxy", "config" => off}
      ]}
      fetched = []
      targets = Prom::Targets.new(client: FakeClient.new({}), cluster_json: cluster, kubeconfig_context: nil,
                                  http: lambda { |url|
                                    fetched << url
                                    [200, "x 1\n"]
                                  })
      all = targets.control_plane_targets

      assert_equal %w[kube-controller-manager kube-proxy kube-scheduler kube-scheduler-resources], all.map(&:job).sort
      scheduler = all.find { |t| t.job == "kube-scheduler" }

      assert_equal "http://127.0.0.1:21001/metrics", scheduler.url
      assert_equal({"process" => "scheduler"}, scheduler.labels)
      assert_equal "http://127.0.0.1:21001/metrics/resources", all.find { |t| t.job == "kube-scheduler-resources" }.url
      proxy = all.find { |t| t.job == "kube-proxy" }

      assert_equal({"process" => "proxy-worker-0", "node" => "worker-0"}, proxy.labels)
      proxy.fetch.call

      assert_equal ["http://127.0.0.1:21003/metrics"], fetched
    end
  end
end
