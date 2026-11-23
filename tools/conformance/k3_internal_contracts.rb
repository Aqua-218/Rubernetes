#!/usr/bin/env ruby
# frozen_string_literal: true

require "etc"
require "digest"
require "net/http"
require "securerandom"

require_relative "k3_internal_contract_index"
require_relative "k7_cluster_driver"
require_relative "k3_internal_node_resources"
require_relative "../../lib/rubernetes/bootstrap/kubernetes_service_reconciler"

module Conformance
  # Runs each excluded contract against the same binaries and API endpoints as
  # the Linux fixture. Each result names the upstream spec it replaces.
  class K3InternalContracts
    include K3InternalNodeResources

    D = K7ClusterDriver
    PAUSE = "registry.k8s.io/pause:3.10.2"
    AGNHOST = "registry.k8s.io/e2e-test-images/agnhost:2.63.0"
    FAILURE_SECONDS = 20
    CASES = K3InternalContractIndex::CASES.invert.freeze

    def run(cases)
      raise ArgumentError, "no contract case selected" if cases.empty?

      descriptor = JSON.parse(File.read(D.descriptor_path))
      unless descriptor["kind"] == "conformance_cluster" && File.identical?(descriptor.fetch("kubeconfig"), ENV.fetch("KUBECONFIG"))
        raise D::Unsupported, "the kubeconfig must name the local fixture recorded in cluster.json"
      end

      cases.map { |key| execute(key) }
    end

    private

    def execute(key)
      id = CASES.fetch(key)
      started = Time.now.utc.iso8601
      warn "starting #{key}"
      evidence = case key
                 when "apiserver-identity-restart" then verify_identity_restart
                 when "datastore-sigkill" then verify_datastore_recovery(:kill)
                 when "datastore-partition" then verify_datastore_recovery(:partition)
                 when "scheduler-metrics" then verify_metrics("scheduler", "scheduler_pending_pods")
                 when "controller-manager-metrics" then verify_metrics("controller-manager", "running_managed_controllers")
                 else verify_node_resources(key)
                 end
      warn "passed #{key}"
      {"id" => id, "replacement_case" => key, "passed" => true, "started_at" => started,
       "finished_at" => Time.now.utc.iso8601, "observations" => evidence}
    rescue StandardError => error
      warn "failed #{key}: #{error.message}"
      {"id" => id, "replacement_case" => key, "passed" => false, "started_at" => started,
       "finished_at" => Time.now.utc.iso8601, "reason" => "#{error.class}: #{error.message}"}
    end

    def verify_identity_restart
      servers = raft_servers
      expected = servers.map do |server|
        identity = process_configuration(server).fetch("datastore").fetch("node_id")
        Rubernetes::Bootstrap::KubernetesServiceReconciler.apiserver_id(identity)
      end.sort
      D.wait_until("one named identity Lease per API server", 120) { identity_leases.keys.sort == expected }
      before = identity_leases
      restarted = D.apiserver_rolling_restart.fetch("restarted")
      after = nil
      D.wait_until("all original identity Leases renewed by restarted API servers", 120) do
        after = identity_leases
        after.keys.sort == expected && before.all? { |name, value| renewed_lease?(value, after.fetch(name)) }
      end
      {"restarted" => restarted, "before" => before, "after" => after}
    end

    def identity_leases
      D.kubectl_object("get", "lease", "-n", "kube-system", "-l", "apiserver.kubernetes.io/identity=kube-apiserver")
        .to_h.fetch("items", []).to_h do |lease|
          [lease.dig("metadata", "name"), {"uid" => lease.dig("metadata", "uid"), "holder" => lease.dig("spec", "holderIdentity"),
                                           "renew_time" => lease.dig("spec", "renewTime")}]
        end
    end

    def renewed_lease?(previous, current)
      current["uid"] == previous["uid"] && !current["holder"].to_s.empty? && current["holder"] != previous["holder"] &&
        Time.iso8601(current.fetch("renew_time")) > Time.iso8601(previous.fetch("renew_time"))
    end

    def verify_datastore_recovery(fault)
      servers = raft_servers
      with_namespace("raft-#{fault}") do |namespace|
        create_replication_controller(namespace, "existing", replicas: 1, image: PAUSE)
        old_pod = wait_for_pods(namespace, "existing", 1).first
        outage = fault == :kill ? kill_replica(servers.first) : partition_replicas(servers, namespace)
        recovered = wait_for_replica_replacement(namespace, old_pod)
        fresh = verify_new_replica_serves(namespace)
        {"outage" => outage, "existing_pod_uid" => old_pod.dig("metadata", "uid"),
         "recovered_pod_uid" => recovered.dig("metadata", "uid"), "new_pod_served_hostname" => fresh}
      end
    end

    def kill_replica(replica)
      pid = D.pid_of(replica) || raise("Raft replica #{replica.fetch("name")} is not running")
      D.stop!(replica, signal: "KILL")
      begin
        sleep FAILURE_SECONDS
        raise "the killed process is still running" if D.process_alive?(pid, replica)
      ensure
        restarted_pid = D.start!(replica)
        D.wait_until("restarted Raft replica serving API", 180) { D.apiserver_healthy?(replica) }
      end
      {"replica" => replica.fetch("name"), "signal" => "SIGKILL", "old_pid" => pid, "new_pid" => restarted_pid,
       "failure_duration_seconds" => FAILURE_SECONDS}
    end

    def partition_replicas(servers, namespace)
      ports = partition_ports(servers)
      table = "rbn_k3_#{Process.pid}_#{SecureRandom.hex(3)}"
      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + FAILURE_SECONDS
      apply_partition(table, ports)
      begin
        _out, error, status = D.kubectl("get", "--raw", "/api/v1/namespaces/#{namespace}/replicationcontrollers")
        raise "a linearizable list succeeded during the Raft network partition" if status.success?

        remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
        sleep remaining if remaining.positive?
      ensure
        nft!("delete", "table", "inet", table)
      end
      servers.each { |server| D.wait_until("#{server.fetch("name")} rejoined Raft", 180) { D.apiserver_healthy?(server) } }
      {"isolated_raft_ports" => ports, "failure_duration_seconds" => FAILURE_SECONDS, "failed_list" => error.strip}
    end

    def partition_ports(servers)
      ports = servers.map do |server|
        pid = D.pid_of(server) || raise("Raft replica is not running")
        raise "run this check inside the fixture network namespace" unless File.identical?("/proc/self/ns/net", "/proc/#{pid}/ns/net")

        datastore = process_configuration(server).fetch("datastore")
        raise "Raft transport needs its own loopback listener" unless datastore.fetch("listen_address") == "127.0.0.1"

        Integer(datastore.fetch("listen_port"))
      end
      raise "Raft listeners must use unique ports" unless ports.uniq == ports && ports.all? { |port| port.between?(1, 65_535) }

      ports
    end

    def apply_partition(table, ports)
      rules = <<~NFT
        table inet #{table} {
          chain raft_output {
            type filter hook output priority -5; policy accept;
            ip daddr 127.0.0.1 tcp dport { #{ports.join(", ")} } counter drop
            ip saddr 127.0.0.1 tcp sport { #{ports.join(", ")} } counter drop
          }
        }
      NFT
      nft!("-f", "-", input: rules)
    end

    def nft!(*arguments, input: "")
      _out, err, status = Open3.capture3("nft", *arguments, stdin_data: input)
      raise "nft #{arguments.join(" ")} failed: #{err.strip}" unless status.success?
    end

    def wait_for_replica_replacement(namespace, original)
      kubectl!("delete", "pod", original.dig("metadata", "name"), "-n", namespace, "--grace-period=0", "--force", "--wait=false")
      wait_for_pods(namespace, "existing", 1, exclude_uid: original.dig("metadata", "uid")).first
    end

    def verify_new_replica_serves(namespace)
      create_replication_controller(namespace, "new-replica", replicas: 1, image: AGNHOST, args: ["serve-hostname"], port: 9376)
      pod = wait_for_pods(namespace, "new-replica", 1).first.dig("metadata", "name")
      D.wait_until("new replication controller's pod serving its hostname", 120) do
        out, _, status = D.kubectl("get", "--raw", "/api/v1/namespaces/#{namespace}/pods/#{pod}:9376/proxy/")
        status.success? && out.strip == pod
      end
      pod
    end

    def verify_metrics(component, expected_family)
      process = D.processes.find { |entry| entry.fetch("name") == component } || raise("missing #{component}")
      raise "#{component} fixture process is not running" unless D.pid_of(process)

      settings = process_configuration(process).fetch("serving")
      response = Net::HTTP.new(settings.fetch("bind_address"), settings.fetch("port"), nil).get("/metrics")
      raise "#{component} /metrics returned #{response.code}" unless response.code == "200" && response["content-type"].to_s.start_with?("text/plain")

      metrics = response.body
      families = metrics.scan(/^# TYPE ([a-zA-Z_:][a-zA-Z0-9_:]*) /).flatten
      samples = metrics.lines.count { |line| line.match?(/\A[a-zA-Z_:][a-zA-Z0-9_:]*(?:\{.*\})?\s+(?:[+-]?\d|[+-]?Inf|NaN)/) }
      raise "#{component} did not serve Prometheus samples from its component registry" unless samples.positive? && families.include?(expected_family)

      {"component" => component, "expected_family" => expected_family, "metric_families" => families.length,
       "samples" => samples, "body_sha256" => Digest::SHA256.hexdigest(metrics)}
    end

    def raft_servers
      servers = D.api_servers
      unless servers.size >= 3 && servers.all? { |server| process_configuration(server).dig("datastore", "type") == "raft" }
        raise D::Unsupported, "the contract requires a dedicated fixture with at least three Raft replicas"
      end

      servers
    end

    def process_configuration(process)
      YAML.safe_load_file(process.fetch("config")).fetch("processes").fetch(process.fetch("executable"))
    end

    def kubectl!(*arguments, input: "")
      out, err, status = Open3.capture3({"NO_PROXY" => "*", "no_proxy" => "*"}, D::KUBECTL, "--request-timeout=30s", *arguments, stdin_data: input)
      raise "kubectl #{arguments.join(" ")} failed: #{err.strip}" unless status.success?

      out
    end

    def with_namespace(prefix, deletion_timeout: 180)
      name = "internal-#{prefix}-#{SecureRandom.hex(4)}"
      kubectl!("create", "namespace", name)
      begin
        yield name
      ensure
        kubectl!("delete", "namespace", name, "--wait=false", "--ignore-not-found")
        D.wait_until("namespace #{name} deleted", deletion_timeout) do
          kubectl!("get", "namespace", name, "--ignore-not-found", "-o", "name").strip.empty?
        end
      end
    end

    def create_replication_controller(namespace, name, replicas:, image:, args: [], port: nil, node: nil)
      labels = {"contract" => name}
      container = {"name" => "workload", "image" => image, "args" => args}
      container["ports"] = [{"containerPort" => port}] if port
      pod = {"containers" => [container]}
      pod["nodeSelector"] = {"kubernetes.io/hostname" => node} if node
      body = {"apiVersion" => "v1", "kind" => "ReplicationController", "metadata" => {"name" => name},
              "spec" => {"replicas" => replicas, "selector" => labels, "template" => {"metadata" => {"labels" => labels}, "spec" => pod}}}
      kubectl!("create", "-f", "-", "-n", namespace, input: JSON.generate(body))
    end

    def wait_for_pods(namespace, label, expected, exclude_uid: nil)
      ready = []
      D.wait_until("#{expected} ready pods for #{namespace}/#{label}", 720) do
        ready = workload_pods(namespace, label).select do |pod|
          pod.dig("metadata", "uid") != exclude_uid && !pod.dig("metadata", "deletionTimestamp") &&
            Array(pod.dig("status", "conditions")).any? { |condition| condition.values_at("type", "status") == %w[Ready True] }
        end
        ready.size == expected
      end
      ready
    end

    def workload_pods(namespace, label)
      D.kubectl_object("get", "pods", "-n", namespace, "-l", "contract=#{label}").to_h.fetch("items", [])
    end
  end
end

if $PROGRAM_NAME == __FILE__
  results = Conformance::K3InternalContracts.new.run(ARGV)
  puts JSON.pretty_generate("results" => results)
  exit(results.all? { |result| result.fetch("passed") } ? 0 : 1)
end
