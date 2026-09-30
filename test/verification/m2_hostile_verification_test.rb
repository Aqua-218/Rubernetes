# frozen_string_literal: true

require "digest"
require "json"
require "rubygems/package"
require "stringio"
require "tmpdir"
require "zlib"

require_relative "../test_helper"
require "rubernetes/bootstrap"

# Independent M2 hostile checks.  These tests deliberately stay at the Ruby
# contract boundary: they do not claim L3 kernel evidence, and they never
# change production code or generated artifacts.
class M2HostileVerificationTest < Minitest::Test
  Image = Rubernetes::Image
  Runtime = Rubernetes::Runtime
  Native = Rubernetes::Runtime::Native

  class Logger
    %i[debug info warn error fatal].each do |level|
      define_method(level) { |_event, **_fields| true }
    end
  end

  class ServiceRuntime
    attr_reader :calls

    def initialize
      @calls = []
    end

    def start(**_options)
      @calls << :start
      true
    end

    def recover(**_options)
      @calls << :recover
      true
    end

    def stop(**_options)
      @calls << :stop
      true
    end
  end

  class API
    attr_reader :calls

    def initialize
      @calls = []
    end

    def register_node(object)
      @calls << [:node, object]
      true
    end

    def renew_lease(object)
      @calls << [:lease, object]
      true
    end
  end

  class NoopLoop
    def start(**_options)
      true
    end

    def stop(**_options)
      true
    end
  end

  class RestartRuntime
    attr_reader :calls

    def initialize
      @calls = []
      @next_container = 0
    end

    def run_sandbox(_pod, runtime_class: nil)
      @calls << [:sandbox, runtime_class]
      "sandbox-1"
    end

    def create_container(_sandbox, spec)
      @next_container += 1
      id = "container-#{@next_container}"
      @calls << [:create, spec.fetch("name"), id]
      id
    end

    def start_container(id)
      @calls << [:start, id]
      true
    end

    def stop_container(id, timeout:)
      @calls << [:stop, id, timeout]
      true
    end

    def remove_container(id)
      @calls << [:remove, id]
      true
    end

    def remove_sandbox(id)
      @calls << [:sandbox_remove, id]
      true
    end
  end

  class FailingNamespace
    def create(**_options)
      raise "namespace effect failed"
    end
  end

  class SharedCgroup < Native::FakeCgroup
    def initialize(events)
      super()
      @events = events
    end

    def attach(handle, pid:)
      @events << :attach
      super
    end
  end

  class SharedProcess < Native::FakeProcessAdapter
    def initialize(events)
      super()
      @events = events
    end

    def spawn(**options)
      @events << :spawn
      super
    end

    def release_gate(gate)
      @events << :release_gate
      super
    end
  end

  def test_oci_layer_rejects_a_parent_symlink_before_writing_through_it
    layer = gzip_layer do |tar|
      tar.add_file_simple("parent/child", 0o644, 1) { |io| io.write("x") }
    end

    Dir.mktmpdir("m2-layer-race-") do |directory|
      root = File.join(directory, "root")
      outside = File.join(directory, "outside")
      Dir.mkdir(outside)
      Dir.mkdir(root)
      File.symlink(outside, File.join(root, "parent"))

      extractor = Image::LayerExtractor.new(root)
      assert_raises(Image::SecurityError) do
        extractor.extract(layer, digest: digest_for(layer), media_type: Image::MediaTypes::OCI_IMAGE_LAYER_GZIP)
      end
      refute_path_exists File.join(outside, "child")
    end
  end

  def test_registry_transport_requires_https_and_rejects_userinfo
    transport = Image::NetHTTPTransport.new
    assert_raises(Image::RegistryError) do
      transport.request(method: "GET", uri: "http://registry.example/v2/", headers: {})
    end
    assert_raises(Image::RegistryError) do
      Image::RegistryClient.new("registry.example/team/app:stable", endpoint: "https://user:secret@registry.example")
    end
  end

  def test_wal_rejects_a_torn_line_during_reopen
    Dir.mktmpdir("m2-wal-") do |directory|
      path = File.join(directory, "runtime.wal")
      wal = Runtime::DurableWAL.new(path, fsync: false)
      wal.append(operation_id: "op", event: "state_transition", payload: {"to" => "Validated"})
      File.open(path, "ab") { |file| file.write("{\"sequence\":2") }

      assert_raises(Runtime::JournalCorruption) { Runtime::DurableWAL.new(path, fsync: false) }
    end
  end

  def test_runtime_rejects_workload_effects_from_state_unknown
    adapter = Object.new
    adapter.define_singleton_method(:hold_workload) { raise Runtime::AmbiguousResult, "response lost" }
    runtime = Runtime::Runtime.new(data_dir: Dir.mktmpdir("m2-unknown-"), adapter: adapter)

    assert_raises(Runtime::OperationFailure) { runtime.run_sandbox({}, request_id: "unknown") }
    assert_equal "StateUnknown", runtime.ledger.operation_for_request("unknown").state
    assert_raises(Runtime::StateUnknownError) { runtime.run_sandbox({}, request_id: "unknown") }
  end

  def test_native_cgroup_and_process_gate_contract_is_ordered
    Dir.mktmpdir("m2-native-") do |directory|
      events = []
      cgroup = SharedCgroup.new(events)
      process = SharedProcess.new(events)
      runtime = Native.new(
        profile: :pure,
        sandbox_root: File.join(directory, "sandboxes"),
        log_root: File.join(directory, "logs"),
        journal_path: File.join(directory, "journal.wal"),
        cgroup_adapter: cgroup,
        process_adapter: process
      )
      sandbox = runtime.run_sandbox({}, request_id: "gate")
      container = runtime.create_container(sandbox, {"name" => "app", "command" => ["/bin/true"]})
      runtime.start_container(container)

      assert_equal %i[spawn attach release_gate], events
      assert_equal "running", runtime.container_status(container).fetch("state")
    end
  end

  def test_native_recovery_uses_an_external_observer_and_releases_ledger_only_entries
    Dir.mktmpdir("m2-native-recovery-") do |directory|
      runtime = Native.new(
        profile: :pure,
        sandbox_root: File.join(directory, "sandboxes"),
        log_root: File.join(directory, "logs"),
        journal_path: File.join(directory, "journal.wal")
      )
      runtime.run_sandbox({}, request_id: "recovery")

      refute_empty runtime.ledger.resources

      report = runtime.recover(observer: -> { [] }, cleaner: ->(resource:) { true })

      assert_equal [], report.to_h.fetch("kernel_only")
      assert_equal report.to_h.fetch("ledger_only").sort, runtime.ledger.resources.map { |resource| "#{resource.kind}:#{resource.id}" }.sort
      assert_empty runtime.ledger.resources
    end
  end

  def test_native_failed_effect_does_not_leave_a_reusable_sandbox_or_request
    Dir.mktmpdir("m2-native-rollback-") do |directory|
      runtime = Native.new(
        profile: :pure,
        sandbox_root: File.join(directory, "sandboxes"),
        log_root: File.join(directory, "logs"),
        journal_path: File.join(directory, "journal.wal"),
        namespace_adapter: FailingNamespace.new
      )

      assert_raises(RuntimeError) { runtime.run_sandbox({}, request_id: "failed-request") }
      assert_empty runtime.sandboxes
      assert_nil runtime.instance_variable_get(:@requests).fetch("failed-request", nil)
      assert_empty runtime.ledger.resources
    end
  end

  def test_native_rollback_releases_sandbox_components_in_reverse_acquisition_order
    events = []
    runtime = native_rollback_runtime(events: events)

    assert_raises(RuntimeError) { runtime.run_sandbox({}, request_id: "rollback-order") }

    assert_equal(%i[cgroup_release namespace_release workspace_release],
                 events.select { |event| event.to_s.end_with?("_release") })
    released = runtime.ledger.journal.records.filter_map do |record|
      next unless record.event == "resource_released"

      record.payload.fetch("kind")
    end

    assert_equal %w[cgroup namespace workspace], released
    assert_empty runtime.ledger.resources
  end

  def test_native_rollback_blocks_dependents_after_upper_failure_and_preserves_errors
    events = []
    runtime = native_rollback_runtime(events: events, failures: %i[cgroup namespace workspace])

    error = assert_raises(RuntimeError) { runtime.run_sandbox({}, request_id: "rollback-errors") }

    assert_equal(%i[cgroup_release],
                 events.select { |event| event.to_s.end_with?("_release") })
    cleanup = runtime.events.find { |event| event["event"] == "cleanup" }

    assert_equal 3, cleanup.fetch("errors").length
    assert_equal(%w[cgroup namespace workspace], cleanup.fetch("errors").map { |entry| entry.fetch("resource").split(":", 2).first })
    assert_equal cleanup.fetch("errors").first.fetch("resource"), cleanup.fetch("errors").fetch(1).fetch("blocked_by")
    assert_equal cleanup.fetch("errors").first.fetch("resource"), cleanup.fetch("errors").fetch(2).fetch("blocked_by")
    assert_equal cleanup.fetch("errors"), error.cleanup_errors
    pending = runtime.events.find { |event| event["event"] == "cleanup_pending" }

    assert_equal(%w[cgroup namespace workspace], pending.fetch("errors").map { |entry| entry.fetch("resource").split(":", 2).first })
    assert_equal "CleanupPending", runtime.ledger.operation_for_request("rollback-errors").state
  end

  def test_assembler_recovery_observer_does_not_hide_kernel_only_objects_behind_the_ledger
    assembly = Rubernetes::Bootstrap::Assembler.new(
      process_name: "rubernetes-agent", log_io: StringIO.new
    ).build
    runtime = assembly.service.runtime
    handle = runtime.namespace.create(id: "kernel-only", spec: {}, identity: "namespace:kernel-only")
    observer = assembly.service.instance_variable_get(:@runtime_observer)

    observed = observer.call

    assert_includes observed.map { |resource| resource[:id] || resource["id"] }, handle.id,
                    "startup reconciliation must observe kernel objects independently of the durable ledger"
  ensure
    runtime&.namespace&.destroy(handle) if runtime && handle
  end

  def test_probe_readiness_waits_for_the_success_threshold
    runtime = Object.new
    runtime.define_singleton_method(:exec) { |_id, _command, tty: false, timeout: nil| 0 }
    manager = Rubernetes::Node::ProbeManager.new(runtime: runtime, clock: -> { 0 })
    probe = {"exec" => {"command" => ["/ready"]}, "successThreshold" => 2}
    manager.register("container-1", probes: {"readinessProbe" => probe}, started_at: 0)

    manager.check("container-1", probe: probe, type: "readiness", now: 0)

    refute manager.ready?("container-1"), "readiness must remain false until successThreshold is met"
    manager.check("container-1", probe: probe, type: "readiness", now: 1)

    assert manager.ready?("container-1")
  end

  def test_lifecycle_preserves_restart_backoff_across_runtime_container_replacement
    runtime = RestartRuntime.new
    lifecycle = Rubernetes::Node::Lifecycle.new(
      runtime: runtime,
      clock: -> { 0 },
      sleeper: ->(_seconds) {}
    )
    pod = {
      "metadata" => {"name" => "restart", "uid" => "pod-restart"},
      "spec" => {
        "restartPolicy" => "Always",
        "containers" => [{"name" => "app", "image" => "example/app"}]
      }
    }

    lifecycle.start(pod)
    first = lifecycle.handle_container_exit(pod, container_name: "app", exit_code: 1, now: 0)
    second = lifecycle.handle_container_exit(pod, container_name: "app", exit_code: 1, now: 1)

    assert_equal 1, first.restart_count
    assert_equal 2, second.restart_count
    # kubelet: the first failure restarts at once, the second backs off 10 s.
    assert_equal 10, second.delay_seconds
  end

  def test_agent_service_starts_node_lease_retry_loop
    api = API.new
    node_agent = Rubernetes::Node::Agent.new(
      node_name: "node-a",
      api: api,
      lifecycle: Object.new,
      sync_loop: NoopLoop.new,
      source: api,
      clock: -> { Time.utc(2026, 1, 1) },
      sleeper: ->(_seconds) { Thread.pass }
    )
    runtime = ServiceRuntime.new
    # The streaming endpoint is a separate concern (and 10250 belongs to the
    # host's own kubelet on a shared machine); this test is about the lease.
    service = Rubernetes::Bootstrap::AgentService.new(
      config: {"streaming" => {"enabled" => false}}, logger: Logger.new, runtime: runtime, node_agent: node_agent
    )

    service.start

    thread = node_agent.instance_variable_get(:@lease_thread)

    assert thread && thread.alive?, "AgentService must enable lease renewal/retry for Node::Agent"
  ensure
    service&.stop(reason: "test") if service&.started?
  end

  def test_rollback_journal_does_not_accept_duplicate_json_keys
    Dir.mktmpdir("m2-duplicate-json-") do |directory|
      wal_path = File.join(directory, "runtime.wal")
      timestamp = "2026-01-01T00:00:00.000000Z"
      body = {
        "sequence" => 1,
        "operation_id" => "op",
        "event" => "evil",
        "payload" => {},
        "timestamp" => timestamp,
        "previous_digest" => Runtime::DurableWAL::EMPTY_DIGEST
      }
      body["digest"] = Digest::SHA256.hexdigest(JSON.generate(body))
      duplicate_line = JSON.generate(body).sub('"event":"evil"', '"event":"state_transition","event":"evil"')
      File.write(wal_path, duplicate_line << "\n")
      assert_raises(Runtime::JournalCorruption) { Runtime::DurableWAL.new(wal_path, fsync: false) }
    end
  end

  def test_snapshot_store_does_not_accept_duplicate_json_keys
    Dir.mktmpdir("m2-duplicate-snapshot-") do |directory|
      snapshot_body = {
        "schema" => Runtime::AtomicSnapshotStore::SCHEMA,
        "snapshot_id" => "base",
        "state" => "WorkloadStopped",
        "identity" => "base-id",
        "payload" => {}
      }
      snapshot_body["checksum"] = Runtime::Canonical.digest(snapshot_body)
      snapshot_line = JSON.generate(snapshot_body).sub(
        '"state":"WorkloadStopped"',
        '"state":"Running","state":"WorkloadStopped"'
      )
      File.write(File.join(directory, "base.snapshot.json"), snapshot_line << "\n")

      assert_raises(Runtime::SnapshotCorruption) do
        Runtime::AtomicSnapshotStore.new(directory, fsync: false).read("base")
      end
    end
  end

  private

  def native_rollback_runtime(events:, failures: [])
    failures = Array(failures).map(&:to_sym)
    namespace_adapter = Object.new
    namespace_adapter.define_singleton_method(:create) do |plan:, id:, identity:|
      events << :namespace_acquire
      "namespace-handle-#{id}"
    end
    namespace_adapter.define_singleton_method(:destroy) do |handle:, id:, identity:|
      events << :namespace_release
      raise "namespace cleanup failed" if failures.include?(:namespace)

      true
    end

    filesystem_adapter = Object.new
    filesystem_adapter.define_singleton_method(:prepare) do |workspace:, **_options|
      events << :workspace_acquire
      true
    end
    filesystem_adapter.define_singleton_method(:cleanup) do |workspace:|
      events << :workspace_release
      raise "workspace cleanup failed" if failures.include?(:workspace)

      true
    end

    cgroup_adapter = Class.new(Native::FakeCgroup) do
      define_method(:initialize) do |events, failures|
        super()
        @events = events
        @failures = failures
      end

      define_method(:remove) do |handle, force: false|
        @events << :cgroup_release
        raise "cgroup cleanup failed" if @failures.include?(:cgroup)

        super(handle, force: force)
      end
    end.new(events, failures)
    effect_hook = lambda do |effect_point:, **_options|
      raise "injected rollback failure" if effect_point == "resources_attached"
    end

    Native.new(
      profile: :pure,
      namespace_adapter: namespace_adapter,
      filesystem_adapter: filesystem_adapter,
      cgroup_adapter: cgroup_adapter,
      adapters: {effect_hook: effect_hook}
    )
  end

  def gzip_layer(&)
    tar_io = StringIO.new("".b)
    Gem::Package::TarWriter.new(tar_io, &)
    output = StringIO.new("".b)
    gzip = Zlib::GzipWriter.new(output)
    gzip.write(tar_io.string)
    gzip.close
    output.string
  end

  def digest_for(bytes)
    "sha256:#{Digest::SHA256.hexdigest(bytes)}"
  end
end
