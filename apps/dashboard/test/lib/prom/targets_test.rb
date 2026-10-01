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
        "services" => [{"metadata" => {"name" => "exporter", "namespace" => "gitlab",
                                       "annotations" => {"prometheus.io/scrape" => "true"}}}],
        "endpointslices" => [{"metadata" => {"name" => "exporter-abc", "namespace" => "gitlab", "labels" => {"kubernetes.io/service-name" => "exporter"}},
                              "ports" => [{"port" => 9168}],
                              "endpoints" => [{"addresses" => ["10.242.0.9"], "conditions" => {"ready" => true}, "nodeName" => "worker-2",
                                               "targetRef" => {"name" => "exporter-pod"}},
                                              {"addresses" => ["10.242.0.10"], "conditions" => {"ready" => false}}]}]
      }
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
