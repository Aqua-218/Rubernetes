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

      assert_equal ["http://127.0.0.1:21003/metrics"], fetched
    end
  end
end
