#!/usr/bin/env ruby
# frozen_string_literal: true

# Privileged Kubernetes v1.36.2 Pod-lifecycle harness for the M2 oracle.
#
# The harness runs the fixture Pods on a genuine Kubernetes v1.36.2 node
# (kubelet, kube-apiserver, etcd, containerd, runc, and kindnetd all inside the
# digest-pinned node image built from the pinned source checkout) and records
# the externally observable state transitions: Pod status updates streamed from
# the API server watch, Events, and container runtime (CRI) timestamps. It never
# fabricates an expected value: every observable is derived from something the
# cluster reported, and a case that does not settle inside its deadline makes
# the whole run INCOMPLETE with the last observed state attached.
#
# Isolation: the node runs on a dedicated `docker network create --internal`
# bridge, egress is proven unreachable from inside the node before any fixture
# Pod is applied, and every interaction goes through `docker exec` so no host
# port is published. The busybox workload image is imported with its upstream
# manifest digest so the kubelet never needs a registry.
#
# Input (stdin JSON, written by runner.rb):
#   {"request": <oracle request>, "node_image": "<digest-pinned reference>",
#    "runtime": {"containerd": {...}, "runc": {...}}}
# Output (stdout JSON): see `#success_document` / `#failure_document`.

require "digest"
require "fileutils"
require "json"
require "open3"
require "securerandom"
require "shellwords"
require "time"
require "tmpdir"

require_relative "registry_image"

module M2LifecycleOracleHarness
  class HarnessError < StandardError; end

  ROOT = File.expand_path("../../../..", __dir__).freeze
  FIXTURE_PATH = File.join(ROOT, "test/conformance/kubernetes/m2_lifecycle_oracle/fixtures/lifecycle.json").freeze
  KUBERNETES_LOCK_PATH = File.join(ROOT, "third_party/locks/kubernetes-v1.36.2.json").freeze
  KIND_LOCK_PATH = File.join(ROOT, "third_party/locks/kind-v0.33.0.json").freeze
  NODE_IMAGE_LOCK_PATH = File.join(ROOT, "third_party/locks/m2-lifecycle-node-image.json").freeze
  CNI_LOCK_PATH = File.join(ROOT, "third_party/locks/m2-lifecycle-cni.json").freeze
  IMAGE_CACHE_DIR = File.join(ROOT, "build/tools/m2-lifecycle-oracle/images").freeze
  ADMIN_CONF = "/etc/kubernetes/admin.conf"
  NAMESPACE = "default"
  KUBERNETES_VERSION = "v1.36.2"
  KUBERNETES_SOURCE_COMMIT = "24e2b02af5543d7910c2bb074c7264df5a8f0467"
  REQUIRED_CASES = %w[init_sidecar_app_order startup_liveness_readiness_thresholds restart_policy_and_backoff
                      graceful_termination_oracle].freeze
  CNI_IDENTITY_KEYS = %w[plugin version source_commit image_reference image_digest config_sha256].freeze
  RESTARTING_VARIANTS = %w[always_exit_0 on_failure_exit_1].freeze
  TERMINAL_VARIANTS = %w[on_failure_exit_0 never_exit_1].freeze
  LIVENESS_KILL_MESSAGE = "Container app failed liveness probe, will be restarted"
  # Every wait has an explicit bound (coding standard R-2.3). The values are
  # generous because kubelet backoff and sync-loop jitter are part of what is
  # being observed, but they are fixed so repeated runs behave the same way.
  TIMEOUTS = {
    docker_command: 120,
    kind_create: 420,
    node_ready: 180,
    cni_ready: 120,
    cases: 240,
    delete: 90,
    teardown: 180
  }.freeze
  POLL_INTERVAL_SECONDS = 0.5

  module_function

  # ---------------------------------------------------------------------------
  # Pure normalization helpers (unit-tested without a cluster)
  # ---------------------------------------------------------------------------

  def canonical_digest(value)
    Digest::SHA256.hexdigest(JSON.generate(canonical_value(value)))
  end

  def canonical_value(value)
    case value
    when Hash then value.keys.map(&:to_s).sort.to_h do |key|
                     [key, canonical_value(value[key] || value[key.to_sym])]
                   end
    when Array then value.map { |child| canonical_value(child) }
    else value
    end
  end

  def parse_time(value)
    return nil if value.nil? || value.to_s.empty? || value.to_s.start_with?("0001-01-01")

    Time.iso8601(value.to_s)
  rescue ArgumentError
    nil
  end

  # "back-off 10s restarting failed container=app pod=x_default(uid)" => "10s"
  def parse_backoff_message(message)
    match = message.to_s.match(/\Aback-off (\S+) restarting failed container=/)
    match && match[1]
  end

  def state_kind(state)
    return nil unless state.is_a?(Hash)

    %w[waiting running terminated].find { |kind| state.key?(kind) }
  end

  def container_status(pod, name, init: false)
    list = pod.dig("status", init ? "initContainerStatuses" : "containerStatuses")
    Array(list).find { |status| status.is_a?(Hash) && status["name"] == name }
  end

  # Compact, timestamp-free summary used by the ordering observable.
  def container_summary(status)
    kind = state_kind(status["state"])
    details = status["state"].is_a?(Hash) ? status["state"][kind] : nil
    summary = {
      "name" => status["name"],
      "state" => kind,
      "restartCount" => status["restartCount"],
      "ready" => status["ready"] == true,
      "started" => status["started"] == true
    }
    summary["exitCode"] = details["exitCode"] if kind == "terminated" && details.is_a?(Hash)
    summary
  end

  # Full single-container summary used by the restart and termination cases.
  # Every key is always present so both sides of the comparison agree on shape.
  def restart_status_summary(status)
    kind = state_kind(status["state"])
    details = kind ? status["state"][kind] : {}
    last_kind = state_kind(status["lastState"])
    last = last_kind ? status["lastState"][last_kind] : {}
    {
      "state" => kind,
      "reason" => details.is_a?(Hash) ? details["reason"] : nil,
      "exitCode" => kind == "terminated" && details.is_a?(Hash) ? details["exitCode"] : nil,
      "lastState" => last_kind,
      "lastReason" => last.is_a?(Hash) ? last["reason"] : nil,
      "lastExitCode" => last_kind == "terminated" && last.is_a?(Hash) ? last["exitCode"] : nil
    }
  end

  # CRI container records: [{"name", "createdAt", "startedAt", "finishedAt", "init"}]
  # with RFC-3339 nanosecond timestamps. Returns the ordered operation list.
  def order_operations(cri_containers)
    events = []
    cri_containers.each do |container|
      name = container.fetch("name")
      created = parse_time(container["createdAt"])
      started = parse_time(container["startedAt"])
      finished = parse_time(container["finishedAt"])
      raise HarnessError, "CRI container #{name} has no createdAt" unless created

      events << [created, 0, "create:#{name}"]
      events << [started, 1, "start:#{name}"] if started
      events << [finished, 2, "wait:#{name}"] if finished && container["init"] == true && container["restartable"] != true
    end
    events.sort_by { |time, rank, label| [time, rank, label] }.map(&:last)
  end

  def order_observable(pod, cri_containers)
    spec = pod.fetch("spec")
    {
      "operations" => order_operations(cri_containers),
      "phase" => pod.dig("status", "phase"),
      "status" => {
        "initContainerStatuses" => Array(spec["initContainers"]).map do |container|
          container_summary(container_status(pod, container.fetch("name"), init: true) || {"name" => container.fetch("name")})
        end,
        "containerStatuses" => Array(spec["containers"]).map do |container|
          container_summary(container_status(pod, container.fetch("name")) || {"name" => container.fetch("name")})
        end
      }
    }
  end

  def probe_label(probe)
    command = probe.dig("exec", "command")
    "exec:#{Array(command).first}"
  end

  # pod_history / event_history: arrays of {"at" => Float seconds, "object" => ...}
  # in arrival order for the probes Pod.
  def probe_observable(container_spec, pod_history, event_history)
    startup = container_spec.fetch("startupProbe")
    liveness = container_spec.fetch("livenessProbe")
    readiness = container_spec.fetch("readinessProbe")
    name = container_spec.fetch("name")
    kill_index = event_history.index do |entry|
      object = entry.fetch("object")
      object["reason"] == "Killing" && object["message"].to_s.strip == LIVENESS_KILL_MESSAGE && object.dig("involvedObject",
                                                                                                           "fieldPath") == "spec.containers{#{name}}"
    end
    raise HarnessError, "liveness Killing event for container #{name} was not observed" unless kill_index

    kill_at = event_history.fetch(kill_index).fetch("at")
    failures_before_kill = event_history.first(kill_index).filter_map do |entry|
      object = entry.fetch("object")
      next unless object["reason"] == "Unhealthy" && object["message"].to_s.start_with?("Liveness probe failed") && object.dig(
        "involvedObject", "fieldPath"
      ) == "spec.containers{#{name}}"

      object["count"].to_i
    end.max || 0
    before_kill = pod_history.select { |entry| entry.fetch("at") <= kill_at }.map { |entry| entry.fetch("object") }
    latest_before_kill = before_kill.last
    status_before_kill = latest_before_kill && container_status(latest_before_kill, name)
    started_before_kill = before_kill.any? { |pod| (status = container_status(pod, name)) && status["started"] == true }
    ready_before_kill = before_kill.any? { |pod| (status = container_status(pod, name)) && status["ready"] == true }
    restarted = pod_history.map do |entry|
      entry.fetch("object")
    end.find { |pod| (status = container_status(pod, name)) && status["restartCount"].to_i >= 1 }
    raise HarnessError, "container #{name} did not restart after the liveness kill" unless restarted

    {
      "startup" => {
        "probe" => probe_label(startup),
        "successThreshold" => startup.fetch("successThreshold", 1),
        "failureThreshold" => startup.fetch("failureThreshold", 3),
        "periodSeconds" => startup.fetch("periodSeconds", 10),
        "result" => started_before_kill ? "succeeded" : "failed",
        "started" => started_before_kill
      },
      "readiness" => {
        "probe" => probe_label(readiness),
        "successThreshold" => readiness.fetch("successThreshold", 1),
        "failureThreshold" => readiness.fetch("failureThreshold", 3),
        "periodSeconds" => readiness.fetch("periodSeconds", 10),
        "result" => ready_before_kill ? "succeeded" : "failed",
        "ready" => ready_before_kill,
        "ready_before_liveness_kill" => ready_before_kill && status_before_kill.is_a?(Hash) && status_before_kill["restartCount"].to_i.zero?
      },
      "liveness" => {
        "probe" => probe_label(liveness),
        "failureThreshold" => liveness.fetch("failureThreshold", 3),
        "periodSeconds" => liveness.fetch("periodSeconds", 10),
        "initialDelaySeconds" => liveness.fetch("initialDelaySeconds", 0),
        "result" => "failed",
        "failures_before_kill" => failures_before_kill,
        "kill_reason" => "Killing",
        "kill_message" => LIVENESS_KILL_MESSAGE,
        "restartCount_after_kill" => container_status(restarted, name)["restartCount"]
      }
    }
  end

  # variants: {name => pod spec document}; histories: {name => [pod objects in arrival order]}
  def restart_observable(variants, histories)
    observable = {"restartPolicy" => {}, "restartCount" => {}, "phase" => {}, "status" => {}, "backoff_seconds" => {}}
    variants.each do |variant, document|
      history = histories.fetch(variant) { raise HarnessError, "no status history for restart variant #{variant}" }
      container = document.fetch("spec").fetch("containers").first.fetch("name")
      settled = if RESTARTING_VARIANTS.include?(variant)
                  history.find { |pod| restart_settled?(pod, container) }
                else
                  history.find { |pod| %w[Succeeded Failed].include?(pod.dig("status", "phase")) }
                end
      raise HarnessError, "restart variant #{variant} did not settle" unless settled

      status = container_status(settled, container)
      observable["restartPolicy"][variant] = document.fetch("spec").fetch("restartPolicy")
      observable["restartCount"][variant] = status["restartCount"]
      observable["phase"][variant] = settled.dig("status", "phase")
      observable["status"][variant] = restart_status_summary(status)
      next unless RESTARTING_VARIANTS.include?(variant)

      upto = history.index(settled)
      observable["backoff_seconds"][variant] = history.first(upto + 1).filter_map do |pod|
        current = container_status(pod, container)
        next unless current && state_kind(current["state"]) == "waiting" && current.dig("state", "waiting", "reason") == "CrashLoopBackOff"

        parse_backoff_message(current.dig("state", "waiting", "message"))
      end.uniq
    end
    observable
  end

  def restart_settled?(pod, container)
    status = container_status(pod, container)
    status.is_a?(Hash) && status["restartCount"].to_i >= 2 && state_kind(status["state"]) == "waiting" &&
      status.dig("state", "waiting", "reason") == "CrashLoopBackOff"
  end

  # final_pod: the object carried by the DELETED watch event; events_after_delete
  # in arrival order.
  # elapsed_seconds: wall-clock interval measured by the harness between its
  # DELETE request and the DELETED watch event.  The API timestamps
  # (deletionTimestamp, finishedAt) carry only second precision, so a kill
  # that lands a few hundred milliseconds after the grace deadline is
  # truncated onto the same second as often as not; the harness-measured
  # interval is the stable witness that the kubelet waited the full grace
  # period before SIGKILL.
  def termination_observable(pod_document, final_pod, events_after_delete, elapsed_seconds: nil)
    container = pod_document.fetch("spec").fetch("containers").first
    grace = pod_document.fetch("spec").fetch("terminationGracePeriodSeconds")
    status = container_status(final_pod, container.fetch("name"))
    raise HarnessError, "final status for #{container.fetch("name")} is missing" unless status

    terminated = status.dig("state", "terminated")
    unless terminated.is_a?(Hash)
      raise HarnessError,
            "container #{container.fetch("name")} was not terminated at deletion: #{JSON.generate(status["state"])}"
    end

    message = terminated["message"].to_s
    lines = message.lines.map(&:strip).reject(&:empty?)
    deletion_timestamp = parse_time(final_pod.dig("metadata", "deletionTimestamp"))
    finished_at = parse_time(terminated["finishedAt"])
    waited_full_grace = if elapsed_seconds.nil?
                          !deletion_timestamp.nil? && !finished_at.nil? && finished_at >= deletion_timestamp
                        else
                          Float(elapsed_seconds) >= grace
                        end
    killed_after_grace = terminated["exitCode"] == 137 && waited_full_grace
    operations = []
    operations << "exec:preStop" if lines.first == "preStop"
    operations << "signal:TERM" if lines.include?("TERM") && lines.index("TERM") > (lines.index("preStop") || -1)
    operations << "wait:#{grace}" if killed_after_grace
    operations << "signal:KILL" if terminated["exitCode"] == 137
    {
      "operations" => operations,
      "events" => events_after_delete.map { |entry| entry.fetch("object")["reason"] }.uniq,
      "phase" => final_pod.dig("status", "phase"),
      "status" => {
        "state" => "terminated",
        "exitCode" => terminated["exitCode"],
        "reason" => terminated["reason"],
        "message" => message
      },
      "terminationGracePeriodSeconds" => grace,
      "killed_after_grace_period" => killed_after_grace
    }
  end

  # Compact trace record for a Pod watch event (raw timestamps retained).
  def trace_pod_entry(entry)
    object = entry.fetch("object")
    statuses = (Array(object.dig("status", "initContainerStatuses")) + Array(object.dig("status", "containerStatuses"))).map do |status|
      kind = state_kind(status["state"])
      details = kind ? status["state"][kind] : {}
      {
        "name" => status["name"], "state" => kind, "ready" => status["ready"], "started" => status["started"],
        "restartCount" => status["restartCount"], "reason" => details.is_a?(Hash) ? details["reason"] : nil,
        "exitCode" => details.is_a?(Hash) ? details["exitCode"] : nil,
        "message" => details.is_a?(Hash) ? details["message"] : nil,
        "startedAt" => details.is_a?(Hash) ? details["startedAt"] : nil,
        "finishedAt" => details.is_a?(Hash) ? details["finishedAt"] : nil
      }
    end
    {
      "kind" => "pod_watch", "at" => Time.at(entry.fetch("at")).utc.iso8601(6), "type" => entry["type"],
      "pod" => object.dig("metadata", "name"), "resourceVersion" => object.dig("metadata", "resourceVersion"),
      "deletionTimestamp" => object.dig("metadata", "deletionTimestamp"), "phase" => object.dig("status", "phase"),
      "containers" => statuses
    }
  end

  def trace_event_entry(entry)
    object = entry.fetch("object")
    {
      "kind" => "event_watch", "at" => Time.at(entry.fetch("at")).utc.iso8601(6), "type" => entry["type"],
      "pod" => object.dig("involvedObject", "name"), "fieldPath" => object.dig("involvedObject", "fieldPath"),
      "reason" => object["reason"], "count" => object["count"], "message" => object["message"],
      "firstTimestamp" => object["firstTimestamp"], "lastTimestamp" => object["lastTimestamp"], "eventTime" => object["eventTime"]
    }
  end

  # ---------------------------------------------------------------------------
  # Infrastructure
  # ---------------------------------------------------------------------------

  def parse_json(path)
    JSON.parse(File.binread(path), max_nesting: 512)
  rescue Errno::ENOENT => error
    raise HarnessError, "required input is missing: #{path}: #{error.message}"
  rescue JSON::ParserError => error
    raise HarnessError, "required input is invalid JSON: #{path}: #{error.message}"
  end

  # Runs a command, raising HarnessError with stderr on failure. Bounded by a
  # timeout implemented through the `timeout` utility so a hung docker/kubectl
  # never blocks the oracle forever.
  def run_command(*command, stdin_data: nil, env: {}, timeout: TIMEOUTS.fetch(:docker_command), allow_failure: false)
    words = ["timeout", "--kill-after=10", timeout.to_s, *command.map(&:to_s)]
    stdout, stderr, status = Open3.capture3(env, *words, stdin_data: stdin_data, chdir: ROOT)
    unless status.success? || allow_failure
      detail = stderr.to_s.strip.empty? ? stdout.to_s.strip : stderr.to_s.strip
      raise HarnessError, "command failed (#{status.exitstatus.inspect}): #{command.map(&:to_s).shelljoin}: #{detail[0, 2000]}"
    end
    [stdout, stderr, status]
  end

  def docker(*, **)
    run_command("docker", *, **)
  end

  class Watcher
    attr_reader :label

    def initialize(node, path, label)
      @node = node
      @path = path
      @label = label
      @entries = []
      @mutex = Mutex.new
      @stderr = +""
      @pid = nil
      @thread = nil
    end

    # The only place the harness creates threads (coding standard R-3.3).
    def start
      reader, writer = IO.pipe
      error_reader, error_writer = IO.pipe
      @pid = Process.spawn("docker", "exec", @node, "kubectl", "--kubeconfig", ADMIN_CONF, "get", "--raw", @path,
                           in: :close, out: writer, err: error_writer)
      writer.close
      error_writer.close
      @thread = Thread.new do
        reader.each_line do |line|
          next if line.strip.empty?

          begin
            document = JSON.parse(line, max_nesting: 512)
          rescue JSON::ParserError => error
            @mutex.synchronize { @stderr << "unparseable watch line (#{error.message}): #{line[0, 200]}\n" }
            next
          end
          @mutex.synchronize { @entries << {"at" => Time.now.to_f, "type" => document["type"], "object" => document["object"] || {}} }
        end
        @stderr << error_reader.read.to_s
      ensure
        reader.close
        error_reader.close
      end
      self
    end

    def entries
      @mutex.synchronize { @entries.dup }
    end

    def stderr
      @mutex.synchronize { @stderr.dup }
    end

    def alive?
      @thread&.alive? == true
    end

    def stop
      return unless @pid

      begin
        Process.kill("TERM", @pid)
      rescue Errno::ESRCH
        nil
      end
      @thread&.join(15)
      begin
        Process.wait(@pid)
      rescue Errno::ECHILD
        nil
      end
      @pid = nil
    end
  end

  class Run
    attr_reader :trace

    def initialize(input)
      @input = input
      @request = input.fetch("request")
      @node_image = input.fetch("node_image")
      @runtime = input.fetch("runtime")
      @fixture_cases = @request.fetch("cases")
      @trace = []
      @cluster = "rubernetes-m2-lc-#{Process.pid}-#{SecureRandom.hex(3)}"
      @node = "#{@cluster}-control-plane"
      @network = @cluster
      @alias_container = "#{@cluster}-hostalias"
      @scratch = nil
      @watchers = []
      @source = {}
      @started_at = Time.now.utc
    end

    def step(name, **details)
      @trace << {"kind" => "step", "at" => Time.now.utc.iso8601(6), "step" => name}.merge(details.transform_keys(&:to_s))
    end

    def kubectl(*, stdin_data: nil, allow_failure: false, timeout: TIMEOUTS.fetch(:docker_command))
      M2LifecycleOracleHarness.docker("exec", "-i", @node, "kubectl", "--kubeconfig", ADMIN_CONF, *, stdin_data: stdin_data,
                                                                                                     allow_failure: allow_failure, timeout: timeout)
    end

    def kubectl_json(*)
      stdout, = kubectl(*, "-o", "json")
      JSON.parse(stdout, max_nesting: 512)
    end

    def node_exec(*, allow_failure: false)
      M2LifecycleOracleHarness.docker("exec", @node, *, allow_failure: allow_failure)
    end

    def wait_until(label, timeout)
      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
      attempts = 0
      loop do
        attempts += 1
        result = yield
        return result if result
        if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline
          raise HarnessError,
                "#{label} did not happen within #{timeout}s (#{attempts} polls)"
        end

        sleep(POLL_INTERVAL_SECONDS)
      end
    end

    def execute
      validate_inputs!
      @scratch = Dir.mktmpdir("rubernetes-m2-lifecycle-", ENV.fetch("RUBERNETES_M2_LIFECYCLE_SCRATCH", Dir.tmpdir))
      create_network!
      create_cluster!
      verify_cluster_identity!
      verify_network_isolation!
      verify_runtime_identity!
      verify_cni!
      import_workload_image!
      observations = observe_cases!
      success_document(observations)
    ensure
      teardown!
    end

    def validate_inputs!
      raise HarnessError, "harness requires uid 0" unless Process.uid.zero?
      unless @node_image.is_a?(String) && @node_image.match?(/\A[^@\s]+@sha256:[0-9a-f]{64}\z/)
        raise HarnessError,
              "node_image must be digest-pinned"
      end

      missing = REQUIRED_CASES - @fixture_cases.keys
      raise HarnessError, "request is missing cases: #{missing.join(", ")}" unless missing.empty?

      %w[containerd runc].each do |name|
        identity = @runtime[name]
        unless identity.is_a?(Hash) && identity["binary_sha256"].to_s.match?(/\A[0-9a-f]{64}\z/)
          raise HarnessError,
                "runtime identity for #{name} is required"
        end
      end
      @kind_lock = M2LifecycleOracleHarness.parse_json(KIND_LOCK_PATH)
      @node_image_lock = M2LifecycleOracleHarness.parse_json(NODE_IMAGE_LOCK_PATH)
      @cni_lock = M2LifecycleOracleHarness.parse_json(CNI_LOCK_PATH)
      @kubernetes_lock = M2LifecycleOracleHarness.parse_json(KUBERNETES_LOCK_PATH)
      unless @node_image == @node_image_lock.dig(
        "image", "reference"
      )
        raise HarnessError,
              "node image #{@node_image} is not the locked node image #{@node_image_lock.dig("image",
                                                                                             "reference")}"
      end

      @kind = File.join(ROOT, @kind_lock.fetch("install_path"))
      raise HarnessError, "kind binary is missing: #{@kind}" unless File.file?(@kind) && File.executable?(@kind)

      actual = Digest::SHA256.file(@kind).hexdigest
      expected = @kind_lock.dig("artifacts", "linux/amd64", "sha256")
      raise HarnessError, "kind binary SHA-256 #{actual} does not match lock #{expected}" unless actual == expected

      inspect, = M2LifecycleOracleHarness.docker("image", "inspect", "--format", "{{.Id}}", @node_image)
      unless inspect.strip == @node_image_lock.dig(
        "image", "image_id"
      )
        raise HarnessError,
              "node image #{@node_image} resolves to #{inspect.strip}, lock says #{@node_image_lock.dig("image",
                                                                                                        "image_id")}"
      end

      busybox = @kubernetes_lock.dig("runner_support_images", "busybox")
      @busybox_tag = busybox.fetch("reference")
      @busybox_digest = busybox.dig("platforms", "linux/amd64")
      @busybox_reference = "#{@busybox_tag.sub(%r{:[^:/]+\z}, "")}@#{@busybox_digest}"
      step("inputs_validated", node_image: @node_image, kind_sha256: actual, cluster: @cluster)
    end

    def create_network!
      M2LifecycleOracleHarness.docker("network", "create", "--internal", "--label", "rubernetes.m2.lifecycle-oracle=#{@cluster}", @network)
      inspect, = M2LifecycleOracleHarness.docker("network", "inspect", "--format", "{{.Internal}} {{.Driver}}", @network)
      raise HarnessError, "docker network #{@network} is not internal: #{inspect.strip}" unless inspect.split.first == "true"

      # kind's node entrypoint resolves host.docker.internal (or the default
      # gateway) to rewrite the embedded-DNS iptables rules. An internal network
      # has no gateway, so a sleeping pause container answers that name. It has
      # no listener and no route anywhere; the node keeps zero egress.
      alias_image = @node_image_lock.fetch("alias_container_image").fetch("reference")
      M2LifecycleOracleHarness.docker("run", "-d", "--name", @alias_container, "--network", @network, "--network-alias", "host.docker.internal",
                                      "--label", "rubernetes.m2.lifecycle-oracle=#{@cluster}", alias_image)
      step("network_created", network: @network, internal: true, alias_container_image: alias_image)
    end

    def create_cluster!
      config_path = File.join(@scratch, "kind.yaml")
      port = @node_image_lock.fetch("cluster").fetch("api_server_port")
      File.write(config_path, <<~YAML)
        kind: Cluster
        apiVersion: kind.x-k8s.io/v1alpha4
        networking:
          apiServerAddress: 127.0.0.1
          apiServerPort: #{Integer(port)}
        nodes:
        - role: control-plane
      YAML
      kubeconfig = File.join(@scratch, "kubeconfig")
      command = [@kind, "create", "cluster", "--name", @cluster, "--image", @node_image, "--config", config_path, "--kubeconfig",
                 kubeconfig, "--wait", "0", "--retain"]
      stdout, stderr, status = M2LifecycleOracleHarness.run_command(*command, env: {"KIND_EXPERIMENTAL_DOCKER_NETWORK" => @network},
                                                                              timeout: TIMEOUTS.fetch(:kind_create), allow_failure: true)
      output = "#{stdout}\n#{stderr}"
      # On an internal network Docker publishes no host port, so kind's final
      # kubeconfig export fails after the cluster is fully provisioned. That is
      # the only accepted failure; the cluster is then verified directly.
      unless status.success? || output.include?("failed to get api server port")
        raise HarnessError, "kind create cluster failed: #{output.strip[-3000..] || output.strip}"
      end

      step("kind_create_finished", exit_status: status.exitstatus, accepted_port_export_failure: !status.success?,
                                   output_sha256: Digest::SHA256.hexdigest(output))
      running, = M2LifecycleOracleHarness.docker("inspect", "--format", "{{.State.Running}} {{.Config.Image}}", @node)
      raise HarnessError, "node container #{@node} is not running: #{running.strip}" unless running.split.first == "true"
      raise HarnessError, "node container image is #{running.split.last}, expected #{@node_image}" unless running.split.last == @node_image

      wait_until("node Ready", TIMEOUTS.fetch(:node_ready)) do
        stdout, _stderr, node_status = kubectl("get", "nodes", "-o", "json", allow_failure: true)
        next false unless node_status.success?

        nodes = JSON.parse(stdout, max_nesting: 512)["items"] || []
        nodes.length == 1 && Array(nodes.first.dig("status", "conditions")).any? do |condition|
          condition["type"] == "Ready" && condition["status"] == "True"
        end
      end
      step("node_ready")
    end

    def verify_cluster_identity!
      version, = kubectl("version", "-o", "json")
      server = JSON.parse(version)["serverVersion"] || {}
      unless server["gitVersion"] == KUBERNETES_VERSION && server["gitCommit"] == KUBERNETES_SOURCE_COMMIT && server["gitTreeState"] == "clean"
        raise HarnessError,
              "kube-apiserver reports #{server["gitVersion"]} at #{server["gitCommit"]} (#{server["gitTreeState"]}), expected #{KUBERNETES_VERSION} at #{KUBERNETES_SOURCE_COMMIT}"
      end

      kubelet, = node_exec("kubelet", "--version")
      raise HarnessError, "kubelet reports #{kubelet.strip}" unless kubelet.strip == "Kubernetes #{KUBERNETES_VERSION}"

      kubelet_sha, = node_exec("sha256sum", @node_image_lock.dig("runtime", "kubelet", "in_image_path"))
      nodes = kubectl_json("get", "nodes")
      node_info = nodes.fetch("items").first.dig("status", "nodeInfo") || {}
      pods = kubectl_json("get", "pods", "-n", "kube-system")
      listing, = node_exec("ctr", "-n", "k8s.io", "images", "ls")
      store_digests = listing.lines.drop(1).to_h do |line|
        words = line.split
        [words[0], words[2]]
      end
      # Images imported into containerd (not pulled) expose their CRI image ID
      # through Pod status. The locked digest-pinned reference is proven by
      # (a) the Pod's image tag mapping to the locked digest in the node's
      # containerd store and (b) the Pod's imageID equalling the locked CRI ID.
      image_of = lambda do |prefix, key|
        pod = pods.fetch("items").find { |item| item.dig("metadata", "name").to_s.start_with?(prefix) }
        raise HarnessError, "kube-system pod #{prefix}* is missing" unless pod

        tag = pod.dig("spec", "containers", 0, "image").to_s
        expected = @node_image_lock.fetch("images").fetch(key)
        expected_cri = @node_image_lock.fetch("cri_image_ids").fetch(key)
        raise HarnessError, "#{prefix} runs image tag #{tag}, lock expects #{expected_cri["tag"]}" unless tag == expected_cri["tag"]

        digest = store_digests[tag]
        unless digest && expected.end_with?(digest)
          raise HarnessError,
                "#{prefix} image #{tag} maps to #{digest.inspect} in the node store, lock expects #{expected}"
        end

        cri_id = pod.dig("status", "containerStatuses", 0, "imageID").to_s
        inspect, = node_exec("crictl", "inspecti", tag)
        cri_status = JSON.parse(inspect)["status"] || {}
        unless cri_status["id"] == expected_cri["id"] && (cri_id == expected_cri["id"] || Array(cri_status["repoDigests"]).include?(cri_id))
          raise HarnessError,
                "#{prefix} CRI image ID #{cri_status["id"]} (pod reports #{cri_id}) is not the locked #{expected_cri["id"]}"
        end

        {"reference" => expected, "tag" => tag, "cri_image_id" => cri_status["id"], "pod_image_id" => cri_id}
      end
      apiserver = image_of.call("kube-apiserver-", "kube_apiserver")
      etcd = image_of.call("etcd-", "etcd")
      apiserver_image = apiserver.fetch("reference")
      etcd_image = etcd.fetch("reference")
      @source = {
        "version" => KUBERNETES_VERSION,
        "commit" => KUBERNETES_SOURCE_COMMIT,
        "tag" => KUBERNETES_VERSION,
        "kubelet_image" => @node_image,
        "apiserver_image" => apiserver_image,
        "etcd_image" => etcd_image,
        "image_detail" => {"kube_apiserver" => apiserver, "etcd" => etcd},
        "server_version" => server.slice("gitVersion", "gitCommit", "gitTreeState", "buildDate", "goVersion", "platform"),
        "kubelet_version" => kubelet.strip,
        "kubelet_sha256" => kubelet_sha.split.first,
        "node_info" => node_info.slice("kubeletVersion", "containerRuntimeVersion", "kernelVersion", "osImage", "architecture"),
        "cluster" => {"name" => @cluster, "node" => @node, "network" => @network, "provisioner" => "kind #{@kind_lock.fetch("tag")}"}
      }
      step("cluster_identity_verified", server_version: @source["server_version"], apiserver_image: apiserver_image, etcd_image: etcd_image)
    end

    def verify_network_isolation!
      inspect, = M2LifecycleOracleHarness.docker("network", "inspect", "--format", "{{.Internal}}", @network)
      raise HarnessError, "network #{@network} lost its internal flag" unless inspect.strip == "true"

      probes = {}
      %w[1.1.1.1:80 8.8.8.8:53 registry.k8s.io:443].each do |target|
        host, port = target.split(":")
        _stdout, stderr, status = node_exec("timeout", "5", "bash", "-c", "exec 3<>/dev/tcp/#{host}/#{port}", allow_failure: true)
        probes[target] = {"reachable" => status.success?, "detail" => stderr.to_s.strip[0, 200]}
        raise HarnessError, "node reached #{target}; the oracle network is not isolated" if status.success?
      end
      routes, = node_exec("ip", "-4", "route", "show", "default", allow_failure: true)
      raise HarnessError, "node has a default route (#{routes.strip}); the oracle network is not isolated" unless routes.strip.empty?

      @source["network_isolated"] = true
      @source["network_isolation_proof"] = {"docker_network_internal" => true, "default_route" => routes.strip, "egress_probes" => probes}
      step("network_isolation_verified", probes: probes)
    end

    def verify_runtime_identity!
      %w[containerd runc].each do |name|
        identity = @runtime.fetch(name)
        in_node_path = @node_image_lock.dig("runtime", name, "in_image_path")
        sha, = node_exec("sha256sum", in_node_path)
        in_node_sha = sha.split.first
        unless in_node_sha == identity["binary_sha256"]
          raise HarnessError,
                "#{name} inside the node (#{in_node_sha}) differs from the runner identity (#{identity["binary_sha256"]})"
        end

        version, = node_exec(in_node_path, "--version")
        first_line = version.lines.first.to_s.strip
        unless first_line == identity["version"]
          raise HarnessError,
                "#{name} version inside the node (#{first_line}) differs from the runner identity (#{identity["version"]})"
        end

        @runtime[name] = identity.merge("in_node_path" => in_node_path, "in_node_sha256" => in_node_sha, "in_node_version" => first_line)
      end
      step("runtime_identity_verified", containerd: @runtime["containerd"]["in_node_version"], runc: @runtime["runc"]["in_node_version"])
    end

    def verify_cni!
      wait_until("kindnet DaemonSet ready", TIMEOUTS.fetch(:cni_ready)) do
        daemonset = kubectl_json("get", "daemonset", "-n", "kube-system", "kindnet")
        desired = daemonset.dig("status", "desiredNumberScheduled").to_i
        desired.positive? && daemonset.dig("status", "numberReady").to_i == desired
      end
      pods = kubectl_json("get", "pods", "-n", "kube-system", "-l", "app=kindnet")
      pod = pods.fetch("items").first
      raise HarnessError, "kindnet pod is missing" unless pod

      image_id = pod.dig("status", "containerStatuses", 0, "imageID").to_s
      unless image_id == @cni_lock["cri_image_id"]
        raise HarnessError,
              "kindnetd imageID #{image_id} is not the locked CRI image ID #{@cni_lock["cri_image_id"]}"
      end

      image_ref = pod.dig("spec", "containers", 0, "image").to_s
      unless image_ref == @cni_lock["image_tag"]
        raise HarnessError,
              "kindnetd image tag #{image_ref} is not the locked #{@cni_lock["image_tag"]}"
      end

      listing, = node_exec("ctr", "-n", "k8s.io", "images", "ls")
      store_digest = listing.lines.drop(1).map(&:split).find { |words| words[0] == image_ref }&.fetch(2)
      unless store_digest == "sha256:#{@cni_lock["image_digest"]}"
        raise HarnessError,
              "kindnetd image #{image_ref} maps to #{store_digest.inspect} in the node store, lock expects sha256:#{@cni_lock["image_digest"]}"
      end

      version = image_ref.split(":").last
      unless version == @cni_lock["version"]
        raise HarnessError,
              "kindnetd image tag #{version} is not the locked version #{@cni_lock["version"]}"
      end

      config_path = @cni_lock.fetch("config_path")
      config = wait_until("CNI config #{config_path}", TIMEOUTS.fetch(:cni_ready)) do
        stdout, _stderr, status = node_exec("cat", config_path, allow_failure: true)
        status.success? && !stdout.empty? ? stdout : nil
      end
      config_sha = Digest::SHA256.hexdigest(config)
      unless config_sha == @cni_lock["config_sha256"]
        raise HarnessError,
              "CNI config #{config_path} SHA-256 #{config_sha} does not match lock #{@cni_lock["config_sha256"]}"
      end

      binaries = {}
      Array(@cni_lock["plugin_binaries"]).each do |binary, expected|
        stdout, = node_exec("sha256sum", "/opt/cni/bin/#{binary}")
        actual = stdout.split.first
        raise HarnessError, "CNI plugin binary #{binary} SHA-256 #{actual} does not match lock #{expected}" unless actual == expected

        binaries[binary] = actual
      end
      @cni = @cni_lock.slice(*CNI_IDENTITY_KEYS)
      @source["cni"] = @cni
      @source["cni_detail"] =
        {"image_id" => image_id, "config_path" => config_path, "config_sha256" => config_sha, "plugin_binaries" => binaries}
      step("cni_verified", image_id: image_id, config_sha256: config_sha)
    end

    def import_workload_image!
      archive = M2LifecycleOracleRegistryImage.fetch_oci_archive(@busybox_reference, cache_dir: IMAGE_CACHE_DIR)
      M2LifecycleOracleHarness.docker("cp", archive, "#{@node}:/kind/workload-image.oci.tar")
      # --index-name gives the OCI index a fully qualified name; without it ctr
      # invents `import-<date>` which the CRI image store cannot resolve back.
      node_exec("ctr", "-n", "k8s.io", "images", "import", "--digests", "--all-platforms", "--snapshotter", "overlayfs", "--index-name",
                @busybox_tag, "/kind/workload-image.oci.tar")
      listing, = node_exec("ctr", "-n", "k8s.io", "images", "ls", "-q")
      names = listing.lines.map(&:strip)
      unless names.include?(@busybox_reference)
        raise HarnessError,
              "imported workload image #{@busybox_reference} is not in the node image store"
      end

      stray = names.select { |name| name.start_with?("import-") && name.include?(@busybox_digest.delete_prefix("sha256:")) }
      raise HarnessError, "ctr created unresolvable image names: #{stray.join(", ")}" unless stray.empty?

      inspect, = node_exec("crictl", "inspecti", @busybox_reference)
      status = JSON.parse(inspect)["status"] || {}
      unless Array(status["repoDigests"]).include?(@busybox_reference)
        raise HarnessError,
              "CRI does not resolve #{@busybox_reference}: #{JSON.generate(status.slice("repoDigests",
                                                                                        "repoTags"))}"
      end

      @source["workload_image"] = {"reference" => @busybox_reference, "cri_image_id" => status["id"], "oci_archive_sha256" => Digest::SHA256.file(archive).hexdigest}
      step("workload_image_imported", reference: @busybox_reference, cri_image_id: status["id"])
    end

    def fixture_pods
      pods = {}
      REQUIRED_CASES.each do |name|
        fixture = @fixture_cases.fetch(name)
        if fixture["variants"].is_a?(Hash)
          fixture["variants"].each { |variant, document| pods["#{name}/#{variant}"] = document }
        else
          pods[name] = fixture.fetch("pod")
        end
      end
      pods
    end

    def strip_uid(document)
      copy = JSON.parse(JSON.generate(document))
      copy["metadata"].delete("uid")
      copy["metadata"]["labels"] = (copy["metadata"]["labels"] || {}).merge("rubernetes.io/m2-lifecycle-oracle" => @cluster)
      copy
    end

    def observe_cases!
      pod_watcher = Watcher.new(@node, "/api/v1/namespaces/#{NAMESPACE}/pods?watch=1", "pods").start
      event_watcher = Watcher.new(@node, "/api/v1/namespaces/#{NAMESPACE}/events?watch=1", "events").start
      @watchers.push(pod_watcher, event_watcher)
      sleep(1)
      raise HarnessError, "pod watch exited early: #{pod_watcher.stderr}" unless pod_watcher.alive?
      raise HarnessError, "event watch exited early: #{event_watcher.stderr}" unless event_watcher.alive?

      documents = fixture_pods
      list = {"apiVersion" => "v1", "kind" => "List", "items" => documents.values.map { |document| strip_uid(document) }}
      applied_at = Time.now.utc
      kubectl("apply", "-f", "-", stdin_data: JSON.generate(list))
      step("fixture_pods_applied", pods: documents.values.map { |document| document.dig("metadata", "name") })

      pod_names = documents.transform_values { |document| document.dig("metadata", "name") }
      results = {}
      pending = REQUIRED_CASES.dup
      delete_requested_at = nil
      order_cri = nil
      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + TIMEOUTS.fetch(:cases)
      loop do
        pods = pod_watcher.entries
        events = event_watcher.entries
        history = lambda do |pod_name|
          pods.select { |entry| entry.fetch("object").dig("metadata", "name") == pod_name }
        end

        if pending.include?("init_sidecar_app_order")
          pod_name = pod_names.fetch("init_sidecar_app_order")
          latest = history.call(pod_name).last&.fetch("object")
          if latest && order_settled?(latest, documents.fetch("init_sidecar_app_order"))
            order_cri = capture_cri(pod_name, documents.fetch("init_sidecar_app_order"))
            results["init_sidecar_app_order"] = M2LifecycleOracleHarness.order_observable(latest, order_cri)
            pending.delete("init_sidecar_app_order")
            step("case_settled", case: "init_sidecar_app_order")
          end
        end

        if pending.include?("startup_liveness_readiness_thresholds")
          pod_name = pod_names.fetch("startup_liveness_readiness_thresholds")
          container = documents.fetch("startup_liveness_readiness_thresholds").fetch("spec").fetch("containers").first
          pod_history = history.call(pod_name)
          event_history = events.select { |entry| entry.fetch("object").dig("involvedObject", "name") == pod_name }
          killed = event_history.any? do |entry|
            entry.fetch("object")["reason"] == "Killing" && entry.fetch("object")["message"].to_s.strip == LIVENESS_KILL_MESSAGE
          end
          restarted = pod_history.any? do |entry|
            (status = M2LifecycleOracleHarness.container_status(entry.fetch("object"),
                                                                container.fetch("name"))) && status["restartCount"].to_i >= 1
          end
          if killed && restarted
            results["startup_liveness_readiness_thresholds"] =
              M2LifecycleOracleHarness.probe_observable(container, pod_history, event_history)
            pending.delete("startup_liveness_readiness_thresholds")
            step("case_settled", case: "startup_liveness_readiness_thresholds")
          end
        end

        if pending.include?("restart_policy_and_backoff")
          variants = @fixture_cases.fetch("restart_policy_and_backoff").fetch("variants")
          histories = variants.to_h do |variant, document|
            [variant, history.call(document.dig("metadata", "name")).map do |entry|
              entry.fetch("object")
            end]
          end
          settled = variants.all? do |variant, document|
            container = document.fetch("spec").fetch("containers").first.fetch("name")
            if RESTARTING_VARIANTS.include?(variant)
              histories.fetch(variant).any? { |pod| M2LifecycleOracleHarness.restart_settled?(pod, container) }
            else
              histories.fetch(variant).any? { |pod| %w[Succeeded Failed].include?(pod.dig("status", "phase")) }
            end
          end
          if settled
            results["restart_policy_and_backoff"] = M2LifecycleOracleHarness.restart_observable(variants, histories)
            pending.delete("restart_policy_and_backoff")
            step("case_settled", case: "restart_policy_and_backoff")
          end
        end

        if pending.include?("graceful_termination_oracle")
          pod_name = pod_names.fetch("graceful_termination_oracle")
          document = documents.fetch("graceful_termination_oracle")
          container = document.fetch("spec").fetch("containers").first.fetch("name")
          pod_history = history.call(pod_name)
          if delete_requested_at.nil?
            latest = pod_history.last&.fetch("object")
            status = latest && M2LifecycleOracleHarness.container_status(latest, container)
            if status && status["ready"] == true && M2LifecycleOracleHarness.state_kind(status["state"]) == "running"
              delete_requested_at = Time.now.to_f
              kubectl("delete", "pod", pod_name, "--wait=false")
              step("delete_requested", pod: pod_name, running_since: status.dig("state", "running", "startedAt"))
            end
          else
            deleted = pod_history.find { |entry| entry["type"] == "DELETED" }
            if deleted
              events_after = events.select do |entry|
                entry.fetch("at") >= delete_requested_at && entry.fetch("object").dig("involvedObject", "name") == pod_name
              end
              results["graceful_termination_oracle"] = M2LifecycleOracleHarness.termination_observable(
                document, deleted.fetch("object"), events_after,
                elapsed_seconds: Float(deleted.fetch("at")) - delete_requested_at
              )
              pending.delete("graceful_termination_oracle")
              step("case_settled", case: "graceful_termination_oracle",
                                   deleted_after_seconds: (deleted.fetch("at") - delete_requested_at).round(3))
            elsif Time.now.to_f - delete_requested_at > TIMEOUTS.fetch(:delete)
              raise HarnessError, "pod #{pod_name} was not deleted within #{TIMEOUTS.fetch(:delete)}s after the delete request"
            end
          end
        end

        break if pending.empty?

        if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline
          snapshot = pending.to_h do |name|
            latest = pods.reverse.find do |entry|
              pod_names.values.include?(entry.fetch("object").dig("metadata",
                                                                  "name")) && (pod_names[name].nil? || entry.fetch("object").dig("metadata",
                                                                                                                                 "name") == pod_names[name])
            end
            [name, latest ? M2LifecycleOracleHarness.trace_pod_entry(latest) : nil]
          end
          raise HarnessError,
                "lifecycle cases did not settle within #{TIMEOUTS.fetch(:cases)}s: #{pending.join(", ")}; last observed: #{JSON.generate(snapshot)}"
        end
        raise HarnessError, "pod watch died: #{pod_watcher.stderr}" unless pod_watcher.alive?
        raise HarnessError, "event watch died: #{event_watcher.stderr}" unless event_watcher.alive?

        sleep(POLL_INTERVAL_SECONDS)
      end

      final_pods = pod_watcher.entries
      final_events = event_watcher.entries
      @trace.concat(final_pods.map { |entry| M2LifecycleOracleHarness.trace_pod_entry(entry) })
      @trace.concat(final_events.map { |entry| M2LifecycleOracleHarness.trace_event_entry(entry) })
      @trace.concat(Array(order_cri).map { |container| {"kind" => "cri_container"}.merge(container) })
      @trace.sort_by! { |entry| entry["at"].to_s }
      step("cases_complete", applied_at: applied_at.iso8601(6), pod_watch_entries: final_pods.length,
                             event_watch_entries: final_events.length)
      results
    end

    def order_settled?(pod, document)
      return false unless pod.dig("status", "phase") == "Running"

      spec = document.fetch("spec")
      spec.fetch("initContainers").all? do |container|
        status = M2LifecycleOracleHarness.container_status(pod, container.fetch("name"), init: true)
        next false unless status

        if container["restartPolicy"] == "Always"
          M2LifecycleOracleHarness.state_kind(status["state"]) == "running" && status["ready"] == true
        else
          M2LifecycleOracleHarness.state_kind(status["state"]) == "terminated" && status.dig("state", "terminated", "exitCode") == 0
        end
      end && spec.fetch("containers").all? do |container|
        status = M2LifecycleOracleHarness.container_status(pod, container.fetch("name"))
        status && M2LifecycleOracleHarness.state_kind(status["state"]) == "running" && status["ready"] == true
      end
    end

    def capture_cri(pod_name, document)
      listing, = node_exec("crictl", "ps", "-a", "-o", "json", "--label", "io.kubernetes.pod.name=#{pod_name}")
      containers = JSON.parse(listing, max_nesting: 64)["containers"] || []
      init_names = Array(document.dig("spec", "initContainers")).map { |container| container.fetch("name") }
      restartable = Array(document.dig("spec", "initContainers")).select do |container|
        container["restartPolicy"] == "Always"
      end.map { |container| container.fetch("name") }
      containers.map do |container|
        inspect, = node_exec("crictl", "inspect", container.fetch("id"))
        status = JSON.parse(inspect, max_nesting: 64)["status"] || {}
        name = status.dig("labels", "io.kubernetes.container.name") || status.dig("metadata", "name")
        {
          "name" => name,
          "id" => container.fetch("id"),
          "state" => status["state"],
          "createdAt" => status["createdAt"],
          "startedAt" => status["startedAt"],
          "finishedAt" => status["finishedAt"],
          "exitCode" => status["exitCode"],
          "attempt" => status.dig("metadata", "attempt"),
          "init" => init_names.include?(name),
          "restartable" => restartable.include?(name),
          "pod" => pod_name
        }
      end
    end

    def success_document(observations)
      {
        "schema_version" => 1,
        "suite" => "m2-kubernetes-lifecycle-oracle",
        "executed" => true,
        "status" => "PASS",
        "passed" => true,
        "errors" => [],
        "kubernetes_version" => KUBERNETES_VERSION,
        "source_commit" => KUBERNETES_SOURCE_COMMIT,
        "request_seed_sha256" => @request["request_seed_sha256"],
        "fixture_sha256" => @request["fixture_sha256"],
        "timeline_sha256" => @request["timeline_sha256"],
        "source" => @source.merge("runtime" => @runtime, "cni" => @cni),
        "runtime" => @runtime,
        "cni" => @cni,
        "observations" => observations,
        "observations_sha256" => M2LifecycleOracleHarness.canonical_digest(observations),
        "trace" => @trace,
        "harness" => {
          "path" => __FILE__,
          "sha256" => Digest::SHA256.file(__FILE__).hexdigest,
          "started_at" => @started_at.iso8601(6),
          "finished_at" => Time.now.utc.iso8601(6),
          "timeouts" => TIMEOUTS
        }
      }
    end

    def teardown!
      @watchers.each(&:stop)
      failures = []
      if @kind
        begin
          M2LifecycleOracleHarness.run_command(@kind, "delete", "cluster", "--name", @cluster, "--kubeconfig", File.join(@scratch.to_s, "kubeconfig"),
                                               env: {"KIND_EXPERIMENTAL_DOCKER_NETWORK" => @network}, timeout: TIMEOUTS.fetch(:teardown))
        rescue HarnessError => error
          failures << error.message
        end
      end
      %w[node alias_container].each do |kind|
        name = kind == "node" ? @node : @alias_container
        _stdout, _stderr, status = M2LifecycleOracleHarness.docker("rm", "-f", name, allow_failure: true)
        failures << "docker rm -f #{name} failed" unless status.success?
      end
      _stdout, stderr, status = M2LifecycleOracleHarness.docker("network", "rm", @network, allow_failure: true)
      failures << "docker network rm #{@network} failed: #{stderr.strip}" unless status.success? || stderr.include?("not found")
      FileUtils.rm_rf(@scratch) if @scratch
      step("teardown_finished", failures: failures)
      raise HarnessError, "teardown left resources behind: #{failures.join("; ")}" unless failures.empty?
    end
  end

  def read_input
    input = JSON.parse($stdin.read, max_nesting: 512)
    unless input.is_a?(Hash) && input["request"].is_a?(Hash) && input["runtime"].is_a?(Hash)
      raise HarnessError,
            "harness input must be an object with request, node_image, and runtime"
    end

    input
  rescue JSON::ParserError => error
    raise HarnessError, "harness input is not JSON: #{error.message}"
  end

  def failure_document(message, trace)
    {
      "schema_version" => 1,
      "suite" => "m2-kubernetes-lifecycle-oracle",
      "executed" => false,
      "status" => "INCOMPLETE",
      "passed" => false,
      "errors" => [message],
      "trace" => trace
    }
  end

  def main
    trace = []
    begin
      run = Run.new(read_input)
      trace = run.trace
      document = run.execute
      puts JSON.generate(document)
      0
    rescue HarnessError, M2LifecycleOracleRegistryImage::FetchError, SystemCallError, KeyError, JSON::ParserError => error
      warn("m2 lifecycle harness: #{error.class}: #{error.message}")
      puts JSON.generate(failure_document("#{error.class}: #{error.message}", trace))
      1
    end
  end
end

exit(M2LifecycleOracleHarness.main) if $PROGRAM_NAME == __FILE__
