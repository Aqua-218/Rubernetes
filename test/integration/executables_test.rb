# frozen_string_literal: true

require "json"
require "tmpdir"
require "fileutils"
require "socket"
require "open3"
require "rbconfig"
require "timeout"
require_relative "../test_helper"

class ExecutablesTest < Minitest::Test
  DAEMON_START_TIMEOUT = 30
  ROOT = File.expand_path("../..", __dir__)
  EXECUTABLES = %w[
    rubectl
    rubernetes-apiserver
    rubernetes-controller-manager
    rubernetes-scheduler
    rubernetes-agent
    rubernetes-proxy
  ].freeze

  def setup
    @directory = Dir.mktmpdir("executables-")
  end

  def teardown
    FileUtils.remove_entry(@directory) if @directory && File.exist?(@directory)
  end

  def test_help_and_version_are_side_effect_free_success_paths
    EXECUTABLES.each do |executable|
      %w[--help --version].each do |option|
        stdout, stderr, status = Open3.capture3(
          RbConfig.ruby,
          "-I#{File.join(ROOT, "lib")}",
          File.join(ROOT, "exe", executable),
          "--config",
          "/path/that/must/not/be/read",
          option,
          chdir: ROOT
        )

        assert_predicate(status, :success?, "#{executable} #{option}: #{stderr}")
        assert_empty(stderr, "#{executable} #{option}")
        refute_empty(stdout, "#{executable} #{option}")
      end
    end
  end

  def test_daemon_bootstraps_and_stops_cleanly_on_term
    # The default streaming port is the well-known kubelet port, which is
    # routinely taken on a host that already runs a cluster.  The daemon's
    # bootstrap is what this test is about, so it gets a port of its own.
    port = Socket.open(:INET, :STREAM) do |socket|
      socket.bind(Addrinfo.tcp("127.0.0.1", 0))
      socket.local_address.ip_port
    end
    api_port = Socket.open(:INET, :STREAM) do |socket|
      socket.bind(Addrinfo.tcp("127.0.0.1", 0))
      socket.local_address.ip_port
    end
    config = File.join(@directory, "agent.yml")
    File.write(config, <<~YAML)
      ---
      version: 1
      processes:
        rubernetes-agent:
          # Never the default 127.0.0.1:6443: a host may run a real cluster
          # there.  A closed local port makes the node startup defer instead.
          api_server: http://127.0.0.1:#{api_port}
          streaming:
            host: 127.0.0.1
            port: #{port}
    YAML
    command = [
      RbConfig.ruby,
      "-I#{File.join(ROOT, "lib")}",
      File.join(ROOT, "exe", "rubernetes-agent"),
      "--config",
      config
    ]
    stdin, stdout, stderr, thread = Open3.popen3(*command, chdir: ROOT)
    stdin.close
    # A liveness assertion, not a performance one: under a loaded machine (a
    # conformance cluster on the same host) a 5s budget for spawning a Ruby
    # daemon reports a timeout that says nothing about the daemon.
    # Startup housekeeping may log before readiness (image.stages_reclaimed
    # after an earlier run left unpacked stages behind); readiness is the
    # first process.* event.
    next_process_event = lambda do
      loop do
        line = stderr.gets
        break nil if line.nil?

        event = JSON.parse(line)
        break event if event.fetch("event").start_with?("process.")
      end
    end
    ready = Timeout.timeout(DAEMON_START_TIMEOUT) { next_process_event.call }

    assert_equal("process.ready", ready&.fetch("event"))

    Process.kill("TERM", thread.pid)
    status = Timeout.timeout(DAEMON_START_TIMEOUT) { thread.value }
    stopped = next_process_event.call

    assert_predicate(status, :success?)
    assert_equal("process.stopped", stopped.fetch("event"))
    assert_equal("TERM", stopped.fetch("reason"))
    assert_empty(stdout.read)
  ensure
    stdout&.close
    stderr&.close
    if thread&.alive?
      Process.kill("KILL", thread.pid)
      thread.value
    end
  end
end
