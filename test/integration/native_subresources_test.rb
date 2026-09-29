# frozen_string_literal: true

require "stringio"
require "fileutils"

require_relative "../test_helper"
require "rubernetes"
require "rubernetes/bootstrap"

class NativeSubresourcesTest < Minitest::Test
  Native = Rubernetes::Runtime::Native

  class ProcessAdapter
    Wait = Data.define(:exit_status, :term_signal, :code)

    # `exits:` bounds how many spawned processes report an exit; later ones
    # keep running (the lifecycle relists container exits, so a fake whose
    # every process exits at once can never hold a Running Pod).
    def initialize(exit_status: 0, exits: nil)
      @exit_status = exit_status
      @exits = exits
      @pid = 40
    end

    def spawn(**_options)
      @pid += 1
      {pid: @pid, pidfd: nil, gate: nil, stdout: StringIO.new("attached\xFF".b),
       stderr: StringIO.new("error\xFE".b), cgroup: nil}
    end

    def release_gate(_gate)
      true
    end

    def wait(pid:, timeout: nil)
      return nil if @exits && (pid - 40) > @exits

      Wait.new(exit_status: @exit_status, term_signal: nil, code: @exit_status)
    end

    def signal(pid:, signal:)
      true
    end
  end

  class Connector
    attr_reader :calls

    def initialize
      @calls = []
    end

    def exec(**arguments)
      @calls << [:exec, arguments]
      {stdin: StringIO.new, stdout: "exec\xFF".b, stderr: "stderr\xFE".b, status: 0}
    end

    def port_forward(**arguments)
      @calls << [:port_forward, arguments]
      {stdin: StringIO.new, stdout: "forwarded".b, stderr: nil}
    end

    def http_get(**arguments)
      @calls << [:http_get, arguments]
      {"status" => 204}
    end

    def tcp_socket(**arguments)
      @calls << [:tcp_socket, arguments]
      true
    end
  end

  class ImageResolver
    def resolve(reference)
      {"reference" => reference, "digest" => "sha256:#{"a" * 64}"}
    end
  end

  def setup
    @directory = Dir.mktmpdir("native-subresources-")
  end

  def teardown
    FileUtils.remove_entry(@directory) if @directory && File.exist?(@directory)
  end

  def test_native_attach_uses_existing_process_stream_and_injected_subresources
    connector = Connector.new
    runtime = native(process_adapter: ProcessAdapter.new,
                     exec_adapter: connector,
                     port_forward_adapter: connector,
                     http_probe_adapter: connector,
                     tcp_probe_adapter: connector)
    container = running_container(runtime)

    attached = Rubernetes::Node::AttachService.new(runtime: runtime, trusted: true).attach(container.id)
    # `kubectl attach` joins the live stream: output written before the attach
    # is in the container log, not replayed on the attach stream (which never
    # reaches EOF while the container runs).
    assert_includes runtime.logs(container.id), "attached\xFF".b
    assert_respond_to attached, :read
    underlying_stdout = runtime.process_supervisor.handles.values.fetch(0).stdout
    attached.close
    refute_predicate underlying_stdout, :closed?, "closing one attach client closed supervisor-owned stdout"

    executed = Rubernetes::Node::ExecService.new(runtime: runtime, trusted: true).exec(container.id, ["/bin/echo", "ok"])
    assert_equal "exec\xFF".b, executed.read
    forwarded = Rubernetes::Node::PortForwardService.new(runtime: runtime, trusted: true).port_forward(container.id, ["127.0.0.1:8080"], timeout: 2)
    assert_equal "forwarded".b, forwarded.read

    manager = Rubernetes::Node::ProbeManager.new(runtime: runtime)
    assert manager.check(container.id, {"httpGet" => {"port" => 8080}}).success?
    assert manager.check(container.id, {"tcpSocket" => {"port" => 8080}}).success?
    assert_equal [:exec, :port_forward, :http_get, :tcp_socket], connector.calls.map(&:first)
  end

  def test_native_subresources_fail_closed_without_unsafe_fallbacks
    runtime = native
    container = running_container(runtime)

    assert_raises(Native::CapabilityError) { runtime.exec(container.id, ["/bin/true"]) }
    assert_raises(Native::CapabilityError) { runtime.port_forward(container.id, [8080], timeout: 1) }
    assert_raises(Native::CapabilityError) { runtime.http_get(container.id, {"port" => 8080}) }
    assert_raises(Native::CapabilityError) { runtime.tcp_socket(container.id, {"port" => 8080}) }
    # attach needs no connector: it follows the supervised process streams.
    refute_nil runtime.attach(container.id)
    assert_raises(Native::ConfigurationError) { runtime.port_forward(container.id, [0], timeout: 1) }
  end

  def test_agent_service_exposes_injected_native_subresources
    connector = Connector.new
    runtime = native(process_adapter: ProcessAdapter.new, exec_adapter: connector)
    container = running_container(runtime)
    service = Rubernetes::Bootstrap::AgentService.new(
      config: {}, logger: Object.new, runtime: runtime, trusted_subresources: true
    )

    stream = service.exec_service.exec(container.id, ["/bin/echo", "agent"])

    assert_equal "exec\xFF".b, stream.read
    assert_equal :exec, connector.calls.fetch(0).first
  end

  def test_lifecycle_extracts_native_container_identity_and_waits_for_init_exit
    runtime = native(process_adapter: ProcessAdapter.new(exit_status: 0, exits: 1))
    lifecycle = Rubernetes::Node::Lifecycle.new(runtime: runtime, image_resolver: ImageResolver.new,
                                                clock: -> { Time.utc(2026, 1, 1) }, sleeper: ->(_seconds) {})
    result = lifecycle.start(pod(init_command: ["/bin/true"]))

    assert_equal "Running", result.phase
    entry = lifecycle.record("pod-native").fetch(:containers).last
    assert_equal entry.fetch(:id), runtime.container_status(entry.fetch(:id)).fetch("id")
    assert_equal "running", runtime.container_status(entry.fetch(:id)).fetch("state")
  end

  def test_lifecycle_marks_nonzero_native_init_as_failed
    runtime = native(process_adapter: ProcessAdapter.new(exit_status: 7, exits: 1))
    lifecycle = Rubernetes::Node::Lifecycle.new(runtime: runtime, image_resolver: ImageResolver.new,
                                                sleeper: ->(_seconds) {})
    result = lifecycle.start(pod(init_command: ["/bin/false"]))

    assert_equal "Failed", result.phase
    assert_match(/init container/, result.error)
    assert_empty runtime.sandboxes
  end

  private

  def native(**options)
    Native.new(
      profile: :pure,
      sandbox_root: File.join(@directory, "sandboxes"),
      log_root: File.join(@directory, "logs"),
      journal_path: File.join(@directory, "journal.wal"),
      **options
    )
  end

  def running_container(runtime)
    sandbox = runtime.run_sandbox({}, request_id: "sandbox-#{object_id}")
    container = runtime.create_container(sandbox, {"id" => "container-#{object_id}", "command" => ["/bin/true"]})
    runtime.start_container(container)
    container
  end

  def pod(init_command:)
    {
      "metadata" => {"name" => "native", "uid" => "pod-native"},
      "spec" => {
        "restartPolicy" => "Never",
        "initContainers" => [{"name" => "init", "image" => "example/init", "command" => init_command}],
        "containers" => [{"name" => "app", "image" => "example/app", "command" => ["/bin/true"]}]
      }
    }
  end
end
