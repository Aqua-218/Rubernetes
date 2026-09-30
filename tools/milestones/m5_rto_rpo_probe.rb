#!/usr/bin/env ruby
# frozen_string_literal: true

# RTO/RPO evidence (M5 exit criterion 2): three production
# `rubernetes-apiserver` processes backed by the Raft datastore, a production
# `rubernetes-controller-manager` reconciling a Deployment through one of
# them, then a SIGKILL of two API servers (quorum loss).  Acknowledged
# writes must all survive (RPO 0); reads, writes and the control loop must
# resume within 60 s of the quorum coming back (RTO).

require "fileutils"
require "json"
require "socket"
require "tmpdir"
require "yaml"
require "rbconfig"

require_relative "m5_probe_support"
$LOAD_PATH.unshift File.join(M5ProbeSupport::ROOT, "lib")
require "rubernetes/consensus"
require "rubernetes/client"

module M5RTORPOProbe
  ROOT = M5ProbeSupport::ROOT
  IDS = %w[a b c].freeze

  class Process
    attr_reader :name, :pid, :log

    def initialize(name:, argv:, log:)
      @name = name
      @argv = argv
      @log = log
      @pid = nil
    end

    def start
      @pid = ::Process.spawn(*@argv, out: @log, err: @log)
      self
    end

    def alive?
      return false unless @pid

      ::Process.waitpid(@pid, ::Process::WNOHANG).nil?
    rescue Errno::ECHILD
      false
    end

    def kill!(signal = "KILL")
      return unless @pid

      ::Process.kill(signal, @pid)
      ::Process.waitpid(@pid)
    rescue Errno::ESRCH, Errno::ECHILD
      nil
    ensure
      @pid = nil
    end
  end

  module_function

  def free_port
    socket = TCPServer.new("127.0.0.1", 0)
    port = socket.addr[1]
    socket.close
    port
  end

  def write_config(root, id, http_ports, raft_ports)
    peers = IDS.reject { |peer| peer == id }.to_h { |peer| [peer, "127.0.0.1:#{raft_ports[peer]}"] }
    document = {
      "version" => 1,
      "logging" => {"level" => "info"},
      "processes" => {
        "rubernetes-apiserver" => {
          "bind_address" => "127.0.0.1",
          "port" => http_ports[id],
          "max_body_bytes" => 3_145_728,
          "watch_history_limit" => 100_000,
          "datastore" => {
            "type" => "raft",
            "node_id" => id,
            "cluster_id" => "m5-rto",
            "data_dir" => File.join(root, "data", id),
            "pki_dir" => File.join(root, "pki", id),
            "listen_address" => "127.0.0.1",
            "listen_port" => raft_ports[id],
            "voters" => IDS,
            "peers" => peers
          }
        }
      }
    }
    path = File.join(root, "apiserver-#{id}.yml")
    File.write(path, YAML.dump(document))
    path
  end

  def controller_config(root, endpoint)
    document = {
      "version" => 1,
      "logging" => {"level" => ENV.fetch("RUBERNETES_M5_CONTROLLER_LOG_LEVEL", "info")},
      "processes" => {
        "rubernetes-controller-manager" => {
          "api_server" => endpoint,
          "identity" => "m5-controller-manager",
          "sync" => {"interval_seconds" => 0.1},
          "controllers" => %w[deployment-controller replicaset-controller],
          "lease" => {"namespace" => "kube-system", "name" => "m5-rto-controller-manager", "lease_duration_seconds" => 5,
                      "renew_deadline_seconds" => 3, "retry_period_seconds" => 0.1}
        }
      }
    }
    path = File.join(root, "controller-manager.yml")
    File.write(path, YAML.dump(document))
    path
  end

  def client_for(port)
    Rubernetes::Client::KubernetesClient.new(server: "http://127.0.0.1:#{port}", open_timeout: 2, read_timeout: 5)
  end

  def wait_until(timeout:, interval: 0.05)
    deadline = M5ProbeSupport.monotonic + timeout
    loop do
      result = begin
        yield
      rescue StandardError
        false
      end
      return true if result
      return false if M5ProbeSupport.monotonic > deadline

      sleep interval
    end
  end

  def ready?(client)
    response = client.raw("GET", "/readyz", raise_for_status: false)
    response.success?
  rescue StandardError
    false
  end

  def run
    started_at = M5ProbeSupport.now
    root = Dir.mktmpdir("m5-rto")
    processes = {}
    controller = nil
    begin
      ca, ca_key = Rubernetes::Consensus::Identity.generate_ca("m5-rto")
      IDS.each do |id|
        bundle = Rubernetes::Consensus::Identity.issue_node(ca, ca_key, cluster_id: "m5-rto", node_id: id)
        Rubernetes::Consensus::Identity.write_bundle(File.join(root, "pki", id), bundle)
      end
      http_ports = IDS.to_h { |id| [id, free_port] }
      raft_ports = IDS.to_h { |id| [id, free_port] }
      configs = IDS.to_h { |id| [id, write_config(root, id, http_ports, raft_ports)] }
      IDS.each do |id|
        processes[id] = Process.new(name: "apiserver-#{id}", log: File.join(root, "apiserver-#{id}.log"),
                                    argv: [RbConfig.ruby, "-I", File.join(ROOT, "lib"), File.join(ROOT, "exe/rubernetes-apiserver"), "--config", configs[id]]).start
      end
      clients = IDS.to_h { |id| [id, client_for(http_ports[id])] }
      boot_started = M5ProbeSupport.monotonic
      raise "API servers did not become ready" unless wait_until(timeout: 60) { IDS.all? { |id| ready?(clients[id]) } }

      boot_seconds = M5ProbeSupport.monotonic - boot_started
      survivor = "a"
      client = clients[survivor]
      controller = Process.new(name: "controller-manager", log: File.join(root, "controller-manager.log"),
                               argv: [RbConfig.ruby, "-I", File.join(ROOT, "lib"), File.join(ROOT, "exe/rubernetes-controller-manager"),
                                      "--config", controller_config(root, "http://127.0.0.1:#{http_ports[survivor]}")]).start
      namespace = "m5-rto"
      client.raw("POST", "/api/v1/namespaces", body: JSON.generate("apiVersion" => "v1", "kind" => "Namespace", "metadata" => {"name" => namespace}),
                                               headers: {"content-type" => "application/json"})
      deployment = {"apiVersion" => "apps/v1", "kind" => "Deployment", "metadata" => {"name" => "web", "namespace" => namespace},
                    "spec" => {"replicas" => 2, "selector" => {"matchLabels" => {"app" => "web"}},
                               "template" => {"metadata" => {"labels" => {"app" => "web"}},
                                              "spec" => {"containers" => [{"name" => "web",
                                                                           "image" => "registry.example/web@sha256:#{"0" * 64}"}]}}}}
      client.raw("POST", "/apis/apps/v1/namespaces/#{namespace}/deployments", body: JSON.generate(deployment),
                                                                              headers: {"content-type" => "application/json"})
      replicaset_replicas = lambda do
        list = client.raw("GET", "/apis/apps/v1/namespaces/#{namespace}/replicasets").json
        list.fetch("items").map { |item| item.dig("spec", "replicas") }
      end
      control_loop_ok = wait_until(timeout: 60) { replicaset_replicas.call == [2] }
      raise "controller-manager did not reconcile the Deployment before the fault" unless control_loop_ok

      acknowledged = []
      40.times do |index|
        response = client.raw("POST", "/api/v1/namespaces/#{namespace}/configmaps",
                              body: JSON.generate("apiVersion" => "v1", "kind" => "ConfigMap", "metadata" => {"name" => "cm-#{index}"}, "data" => {"i" => index.to_s}),
                              headers: {"content-type" => "application/json"}, raise_for_status: false)
        acknowledged << "cm-#{index}" if response.success?
      end
      victims = IDS - [survivor]
      # Quorum loss: kill two of three API servers (their Raft nodes die with them).
      victims.each { |id| processes[id].kill! }
      killed_at = M5ProbeSupport.monotonic
      quorum_lost_write = begin
        response = client_for(http_ports[survivor]).raw("POST", "/api/v1/namespaces/#{namespace}/configmaps",
                                                        body: JSON.generate("apiVersion" => "v1", "kind" => "ConfigMap", "metadata" => {"name" => "cm-during-outage"}),
                                                        headers: {"content-type" => "application/json"}, raise_for_status: false)
        {"status" => response.status, "acknowledged" => response.success?}
      rescue StandardError => error
        {"status" => nil, "acknowledged" => false, "error" => error.class.name}
      end
      # Readiness follows leader/quorum contact; give the election timeout
      # (<= 300 ms) a moment to expire before sampling.
      sleep 1.0
      readyz_during_outage = ready?(client)
      # Restore quorum.
      victims.each do |id|
        processes[id] = Process.new(name: "apiserver-#{id}", log: File.join(root, "apiserver-#{id}.log"),
                                    argv: [RbConfig.ruby, "-I", File.join(ROOT, "lib"), File.join(ROOT, "exe/rubernetes-apiserver"), "--config", configs[id]]).start
      end
      restored_at = M5ProbeSupport.monotonic
      read_ok = wait_until(timeout: 60) do
        response = client.raw("GET", "/api/v1/namespaces/#{namespace}/configmaps/cm-0", raise_for_status: false)
        response.success?
      end
      read_seconds = M5ProbeSupport.monotonic - restored_at
      write_ok = wait_until(timeout: 60) do
        response = client.raw("POST", "/api/v1/namespaces/#{namespace}/configmaps",
                              body: JSON.generate("apiVersion" => "v1", "kind" => "ConfigMap", "metadata" => {"name" => "cm-after-recovery"}),
                              headers: {"content-type" => "application/json"}, raise_for_status: false)
        response.success? || response.status == 409
      end
      write_seconds = M5ProbeSupport.monotonic - restored_at
      # Control loop: scale the Deployment and wait for the ReplicaSet to follow.
      scale_ok = wait_until(timeout: 60) do
        response = client.raw("PATCH", "/apis/apps/v1/namespaces/#{namespace}/deployments/web",
                              body: JSON.generate("spec" => {"replicas" => 3}), headers: {"content-type" => "application/merge-patch+json"}, raise_for_status: false)
        response.success?
      end
      control_ok = scale_ok && wait_until(timeout: 60) { replicaset_replicas.call == [3] }
      control_seconds = M5ProbeSupport.monotonic - restored_at
      present = client.raw("GET", "/api/v1/namespaces/#{namespace}/configmaps").json.fetch("items").map do |item|
        item.dig("metadata", "name")
      end
      lost = acknowledged - present
      # Every replica converges to the same object set.
      counts = IDS.map do |id|
        wait_until(timeout: 30) { ready?(clients[id]) }
        clients[id].raw("GET", "/api/v1/namespaces/#{namespace}/configmaps").json.fetch("items").length
      end
      outage_write_ok = quorum_lost_write["acknowledged"] == false && !acknowledged.include?("cm-during-outage")
      cases = [{
        "id" => "quorum_loss_two_of_three_apiservers",
        "boot_seconds" => boot_seconds.round(3),
        "acknowledged_before_fault" => acknowledged.length,
        "write_during_outage" => quorum_lost_write,
        "readyz_during_outage" => readyz_during_outage,
        "lost_acknowledged_writes" => lost.length,
        "rpo_objects" => lost.length,
        "read_resumed_seconds" => read_seconds.round(3),
        "write_resumed_seconds" => write_seconds.round(3),
        "control_loop_resumed_seconds" => control_seconds.round(3),
        "control_loop_reconciled_before_fault" => control_loop_ok,
        "replica_object_counts" => counts,
        "outage_seconds" => (restored_at - killed_at).round(3),
        "measurement_source" => "real_apiserver_and_controller_manager_processes",
        "passed" => lost.empty? && read_ok && write_ok && control_ok && outage_write_ok && !readyz_during_outage &&
          read_seconds < 60 && write_seconds < 60 && control_seconds < 60 && counts.uniq.length == 1
      }]
      M5ProbeSupport.emit(M5ProbeSupport.report(
        kind: "m5_rto_rpo_report", measurement_level: "integration_tested", started_at: started_at, cases: cases,
        extra: {"topology" => {"apiservers" => 3, "datastore" => "raft", "controller_manager" => 1},
                "sources" => M5ProbeSupport.source_files(%w[lib/rubernetes/bootstrap/api_server_service.rb lib/rubernetes/consensus/raft_store.rb
                                                            lib/rubernetes/consensus/server.rb exe/rubernetes-apiserver exe/rubernetes-controller-manager])}
      ))
    ensure
      controller&.kill!
      processes.each_value { |process| process.kill! if process.alive? }
      if ENV["RUBERNETES_M5_KEEP_RUN"]
        warn "run directory kept at #{root}"
      else
        FileUtils.rm_rf(root)
      end
    end
  end
end

M5RTORPOProbe.run if $PROGRAM_NAME == __FILE__
