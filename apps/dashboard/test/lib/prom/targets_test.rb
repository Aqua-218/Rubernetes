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
