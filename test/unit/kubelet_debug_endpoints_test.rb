# frozen_string_literal: true

# kubelet API endpoints beyond streaming (pkg/kubelet/server/server.go,
# v1.36.2): /configz with the v1beta1 KubeletConfiguration the node really
# runs, /runningpods/, POST /run, the {uid} forms of exec/attach/run,
# /debug/flags/v and the disabled profiling endpoint.

require_relative "../test_helper"
require "json"
require "rubernetes/node"

class KubeletDebugEndpointsTest < Minitest::Test
  Configz = Rubernetes::Node::KubeletConfigz

  def test_configz_reports_defaults_overlaid_with_the_agent_configuration
    config = {"streaming" => {"host" => "127.0.0.1", "port" => 21_250},
              "sync" => {"period_seconds" => 5}, "lease" => {"duration_seconds" => 40}, "max_pods" => 64,
              "static_pod_path" => "/etc/kubernetes/manifests", "cgroup_root" => "/sys/fs/cgroup",
              "system_reserved" => {"cpu" => "500m", "memory" => "512Mi"}, "cpu_manager" => {"policy" => "static"},
              "eviction" => {"hard" => {"memory.available" => "200Mi"}}, "image_gc" => {"high_threshold_percent" => 90},
              "shutdown" => {"grace_period" => "30s", "grace_period_critical_pods" => "10s"},
              "crash_loop_back_off" => {"max_container_restart_period_seconds" => 60},
              "feature_gates" => {"KubeletCrashLoopBackOffMax" => true}}
    kubelet = Configz.build(config, cluster_dns: ["10.240.0.1"], cluster_domain: "cluster.local").fetch("kubeletconfig")
    assert_equal 21_250, kubelet["port"]
    assert_equal "5s", kubelet["syncFrequency"]
    assert_equal 64, kubelet["maxPods"]
    assert_equal "/etc/kubernetes/manifests", kubelet["staticPodPath"]
    assert_equal ["10.240.0.1"], kubelet["clusterDNS"]
    assert_equal "cluster.local", kubelet["clusterDomain"]
    assert_equal({"cpu" => "500m", "memory" => "512Mi"}, kubelet["systemReserved"])
    assert_equal "static", kubelet["cpuManagerPolicy"]
    assert_equal({"memory.available" => "200Mi"}, kubelet["evictionHard"])
    assert_equal 90, kubelet["imageGCHighThresholdPercent"]
    assert_equal 80, kubelet["imageGCLowThresholdPercent"], "v1beta1 default"
    assert_equal "30s", kubelet["shutdownGracePeriod"]
    assert_equal({"maxContainerRestartPeriod" => "1m0s"}, kubelet["crashLoopBackOff"])
    assert_equal({"KubeletCrashLoopBackOffMax" => true}, kubelet["featureGates"])
    assert_equal "AlwaysAllow", kubelet.dig("authorization", "mode"), "no authorizer configured: say so"
    assert_equal true, kubelet.dig("authentication", "anonymous", "enabled")
    assert_equal "cgroupfs", kubelet["cgroupDriver"]
    assert_equal "", kubelet["containerRuntimeEndpoint"], "no CRI configured"

    secured = Configz.build({"streaming" => {"tls" => {"cert_file" => "/pki/k.crt", "key_file" => "/pki/k.key", "client_ca_file" => "/pki/ca.crt"},
                                             "authentication" => {"webhook" => true}, "authorization" => {"mode" => "Webhook"}}})
                     .fetch("kubeletconfig")
    assert_equal "Webhook", secured.dig("authorization", "mode")
    assert_equal false, secured.dig("authentication", "anonymous", "enabled")
    assert_equal "/pki/ca.crt", secured.dig("authentication", "x509", "clientCAFile")
    assert_equal "/pki/k.crt", secured["tlsCertFile"]
    assert_equal({"memory.available" => "100Mi", "nodefs.available" => "10%", "nodefs.inodesFree" => "5%",
                  "imagefs.available" => "15%", "imagefs.inodesFree" => "5%"}, secured["evictionHard"])
  end

  def test_durations_render_like_metav1_duration
    assert_equal "1m0s", Configz.duration(60)
    assert_equal "1h0m0s", Configz.duration(3600)
    assert_equal "1h1m1s", Configz.duration(3661)
    assert_equal "30s", Configz.duration("30s")
    assert_equal "2m30s", Configz.duration("2m30s")
    assert_equal "100ms", Configz.duration(0.1)
    assert_equal "0s", Configz.duration(0)
  end

  class Lifecycle
    def initialize(records) = @records = records
    attr_reader :records
    def record(uid) = @records[uid]
  end

  class Exec
    attr_reader :commands

    def initialize = @commands = []

    def exec(container, command:, **)
      @commands << [container, command]
      {"stdout" => ["hello world\n"]}
    end
  end

  Request = Struct.new(:path, :method, :query, :body) do
    def query_value(name) = (query || {})[name]
    def headers = {}
    def header(_name) = nil
  end

  def server(exec: Exec.new)
    pod = {"metadata" => {"name" => "web", "namespace" => "ns", "uid" => "u1"},
           "spec" => {"containers" => [{"name" => "app", "image" => "nginx:1"}, {"name" => "side", "image" => "busybox"}]}}
    records = {"u1" => {uid: "u1", state: "Running", pod: pod,
                        containers: [{id: "c1", name: "app", started: true}, {id: "c2", name: "side", started: true, exited: true}]}}
    @levels = []
    Rubernetes::Node::StreamingServer.new(log_service: Object.new, lifecycle: Lifecycle.new(records), exec_service: exec,
                                          configz: -> { {"kubeletconfig" => {"maxPods" => 7}} },
                                          log_level_setter: ->(level) { @levels << level })
  end

  def test_runningpods_lists_running_containers
    status, headers, body = server.call(Request.new("/runningpods/", "GET"))
    assert_equal 200, status
    assert_equal "application/json", headers["content-type"]
    list = JSON.parse(body.join)
    assert_equal "PodList", list["kind"]
    item = list["items"].first
    assert_equal({"name" => "web", "namespace" => "ns", "uid" => "u1"}, item["metadata"])
    assert_equal [{"name" => "app", "image" => "nginx:1", "resources" => {}}], item.dig("spec", "containers")
  end

  def test_configz_and_debug_endpoints
    subject = server
    status, _headers, body = subject.call(Request.new("/configz", "GET"))
    assert_equal 200, status
    assert_equal({"kubeletconfig" => {"maxPods" => 7}}, JSON.parse(body.join))
    assert_equal 405, subject.call(Request.new("/debug/pprof/heap", "GET")).first
    status, _headers, body = subject.call(Request.new("/debug/flags/v", "PUT", {}, "4"))
    assert_equal [200, "successfully set klog.logging.verbosity to 4"], [status, body.join]
    subject.call(Request.new("/debug/flags/v", "PUT", {}, "2"))
    assert_equal %w[debug info], @levels
    require "stringio"
    require "rubernetes/bootstrap"
    io = StringIO.new
    logger = Rubernetes::Bootstrap::StructuredLogger.new(io: io, process_name: "agent")
    logger.debug("hidden")
    logger.level = "debug"
    logger.debug("shown")
    assert_equal 1, io.string.lines.length
    assert_equal 400, subject.call(Request.new("/debug/flags/v", "PUT", {}, "x")).first
    assert_equal 405, subject.call(Request.new("/debug/flags/v", "GET")).first
  end

  def test_run_executes_the_legacy_cmd_and_accepts_the_uid_form
    exec = Exec.new
    subject = server(exec: exec)
    subject.define_singleton_method(:await_container) { |_ns, _pod, name, follow:| "container-#{name}" }
    status, _headers, body = subject.call(Request.new("/run/ns/web/app", "POST", {"cmd" => "echo hello world"}))
    assert_equal [200, "hello world\n"], [status, body.join]
    assert_equal ["container-app", %w[echo hello world]], exec.commands.last
    assert_equal 200, subject.call(Request.new("/run/ns/web/u1/app", "POST", {"cmd" => "true"})).first
    assert_equal 404, subject.call(Request.new("/run/ns/missing/app", "POST", {"cmd" => "true"})).first
    match = Rubernetes::Node::StreamingServer::EXEC_PATH.match("/exec/ns/web/u1/app")
    assert_equal %w[ns web u1 app], [match[:namespace], match[:pod], match[:uid], match[:container]]
    match = Rubernetes::Node::StreamingServer::EXEC_PATH.match("/exec/ns/web/app")
    assert_equal ["app", nil], [match[:container], match[:uid]]
  end

  def test_probe_metrics_follow_the_prober_worker
    probes = Rubernetes::Node::ProbeManager.new
    labels = {"metric_labels" => {"container" => "app", "pod" => "web", "namespace" => "ns", "pod_uid" => "u1"}}
    probes.define_singleton_method(:execute) { |_id, _definition, context:| [true, "ok", "exec"] }
    probes.check("c1", probe: {"exec" => {"command" => ["true"]}}, type: "readiness", context: labels)
    probes.define_singleton_method(:execute) { |_id, _definition, context:| [false, "no", "exec"] }
    probes.check("c1", probe: {"exec" => {"command" => ["false"]}}, type: "readiness", context: labels)
    probes.check("c2", probe: nil, type: "liveness", context: labels)
    text = probes.metrics.render
    assert_includes text, 'prober_probe_total{container="app",namespace="ns",pod="web",pod_uid="u1",probe_type="Readiness",result="successful"} 1'
    assert_includes text, 'prober_probe_total{container="app",namespace="ns",pod="web",pod_uid="u1",probe_type="Readiness",result="failed"} 1'
    refute_includes text, 'probe_type="Liveness"', "no probe configured: nothing to count"
    assert_includes text, 'prober_probe_duration_seconds_count{container="app",namespace="ns",pod="web",probe_type="Readiness"} 1',
                    "only the successful probe observes its duration"

    lifecycle = Struct.new(:records, :probes).new({}, probes)
    server = Rubernetes::Node::StreamingServer.new(log_service: Object.new, lifecycle: lifecycle)
    status, _headers, body = server.call(Request.new("/metrics/probes", "GET"))
    assert_equal 200, status
    assert_includes body.join, "prober_probe_total"
  end

  def test_cadvisor_metrics_come_from_the_summary
    summary = {"pods" => [{"podRef" => {"name" => "web", "namespace" => "ns", "uid" => "u1"},
                           "cpu" => {"usageCoreNanoSeconds" => 3_000_000_000}, "memory" => {"workingSetBytes" => 100},
                           "containers" => [{"name" => "app", "startTime" => "2026-01-01T00:00:00Z",
                                             "cpu" => {"usageCoreNanoSeconds" => 2_000_000_000},
                                             "memory" => {"usageBytes" => 90, "workingSetBytes" => 80, "rssBytes" => 70, "pageFaults" => 5},
                                             "rootfs" => {"usedBytes" => 4096}}]}]}
    text = Rubernetes::Node::CadvisorMetrics.render(summary, machine: {cpu_cores: 4, memory_bytes: 1024}, images: {%w[u1 app] => "nginx:1"})
    assert_includes text, "machine_cpu_cores 4\n"
    assert_includes text, 'container_cpu_usage_seconds_total{container="app",cpu="total",id="/kubepods/podu1/app",image="nginx:1",name="app",namespace="ns",pod="web"} 2'
    assert_includes text, 'container_cpu_usage_seconds_total{container="",cpu="total",id="/kubepods/podu1",image="",name="",namespace="ns",pod="web"} 3'
    assert_includes text, 'container_memory_working_set_bytes{container="app",id="/kubepods/podu1/app",image="nginx:1",name="app",namespace="ns",pod="web"} 80'
    assert_includes text, 'container_fs_usage_bytes{container="app",device="rootfs",id="/kubepods/podu1/app",image="nginx:1",name="app",namespace="ns",pod="web"} 4096'
    assert_includes text, 'container_start_time_seconds{container="app",id="/kubepods/podu1/app",image="nginx:1",name="app",namespace="ns",pod="web"} 1.7672256e+09'
  end
end
