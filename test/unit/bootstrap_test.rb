# frozen_string_literal: true

require "json"
require "stringio"
require "tempfile"
require_relative "../test_helper"
require "rubernetes/bootstrap"

class BootstrapTest < Minitest::Test
  def test_config_is_strict_and_deeply_frozen
    config = Rubernetes::Bootstrap::Config.load(process_name: "rubernetes-agent")

    assert_equal("info", config.logging_level)
    assert_predicate(config.to_h, :frozen?)
    assert_predicate(config.to_h.fetch("logging"), :frozen?)
    assert_raises(FrozenError) { config.to_h.fetch("logging")["level"] = "debug" }
  end

  def test_config_rejects_unknown_keys
    Tempfile.create(["rubernetes", ".yml"]) do |file|
      file.write("unknown: true\n")
      file.flush

      error = assert_raises(Rubernetes::Bootstrap::Config::Error) do
        Rubernetes::Bootstrap::Config.load(process_name: "rubernetes-agent", path: file.path)
      end
      assert_match(/unknown configuration keys/, error.message)
    end
  end

  def test_config_rejects_undefined_m0_process_fields
    Tempfile.create(["rubernetes", ".yml"]) do |file|
      file.write("processes:\n  rubernetes-agent:\n    token: must-not-be-accepted\n")
      file.flush

      error = assert_raises(Rubernetes::Bootstrap::Config::Error) do
        Rubernetes::Bootstrap::Config.load(process_name: "rubernetes-agent", path: file.path)
      end
      assert_match(/M0 process configuration must be empty/, error.message)
    end
  end

  def test_config_accepts_strict_csi_socket_identity_and_probe_settings
    Tempfile.create(["rubernetes-csi", ".yml"]) do |file|
      file.write(<<~YAML)
        processes:
          rubernetes-agent:
            volume:
              csi:
                socket: /run/rubernetes/csi/plugin.sock
                timeout: 5
                probe: true
                socket_uid: 1000
                socket_gid: 2000
                socket_mode: "0660"
                peer_uid: 3000
                peer_gid: 4000
                identity:
                  name: example.csi
                  vendor_version: 1.2.3
      YAML
      file.flush

      csi = Rubernetes::Bootstrap::Config.load(process_name: "rubernetes-agent", path: file.path)
                                      .process.fetch("volume").fetch("csi")
      assert_equal "/run/rubernetes/csi/plugin.sock", csi.fetch("socket")
      assert_equal "example.csi", csi.fetch("identity").fetch("name")
      assert_equal true, csi.fetch("probe")
      assert_equal 1000, csi.fetch("socket_uid")
      assert_equal 2000, csi.fetch("socket_gid")
      assert_equal "0660", csi.fetch("socket_mode")
      assert_equal 3000, csi.fetch("peer_uid")
      assert_equal 4000, csi.fetch("peer_gid")
    end
  end

  def test_config_rejects_invalid_csi_socket_and_peer_identity_ranges
    invalid_values = {
      "socket_uid" => -1,
      "socket_gid" => 4_294_967_295,
      "peer_uid" => "0",
      "peer_gid" => nil,
      "socket_mode" => "0880"
    }

    invalid_values.each do |key, value|
      Tempfile.create(["rubernetes-csi-invalid-#{key}", ".yml"]) do |file|
        file.write(<<~YAML)
          processes:
            rubernetes-agent:
              volume:
                csi:
                  socket: /run/rubernetes/csi/plugin.sock
                  #{key}: #{value.inspect}
        YAML
        file.flush

        error = assert_raises(Rubernetes::Bootstrap::Config::Error) do
          Rubernetes::Bootstrap::Config.load(process_name: "rubernetes-agent", path: file.path)
        end
        assert_match(/#{Regexp.escape(key)}/, error.message)
      end
    end
  end

  # kubelet evictionHard/evictionSoft/...: parsed like ParseThresholdConfig
  # when the configuration is loaded, so a bad threshold stops the agent at
  # start instead of silently disabling eviction.
  def test_config_validates_eviction_thresholds
    {
      "      soft:\n        memory.available: 1Gi\n" => "grace period must be specified for the soft eviction threshold memory.available",
      "      hard:\n        memory.bogus: 1Gi\n" => "unsupported eviction signal memory.bogus",
      "      hard:\n        nodefs.available: 120%\n" => "must be <= 100%",
      "      surprise: true\n" => "unknown fields: surprise",
      "      pressure_transition_period: soon\n" => "invalid duration soon"
    }.each do |body, message|
      Tempfile.create(["rubernetes-eviction", ".yml"]) do |file|
        file.write("processes:\n  rubernetes-agent:\n    node_name: n\n    eviction:\n#{body}")
        file.flush
        error = assert_raises(Rubernetes::Bootstrap::Config::Error, body) do
          Rubernetes::Bootstrap::Config.load(process_name: "rubernetes-agent", path: file.path)
        end
        assert_includes error.message, message
      end
    end
    Tempfile.create(["rubernetes-eviction", ".yml"]) do |file|
      file.write("processes:\n  rubernetes-agent:\n    node_name: n\n    eviction:\n      hard:\n        memory.available: 200Mi\n" \
                 "      soft:\n        nodefs.available: 15%\n      soft_grace_period:\n        nodefs.available: 1m\n" \
                 "      pressure_transition_period: 30s\n")
      file.flush
      config = Rubernetes::Bootstrap::Config.load(process_name: "rubernetes-agent", path: file.path)
      assert_equal "200Mi", config.process.dig("eviction", "hard", "memory.available")
    end
  end

  def test_config_rejects_csi_socket_mode_above_permission_bits
    Tempfile.create(["rubernetes-csi-invalid-mode", ".yml"]) do |file|
      file.write(<<~YAML)
        processes:
          rubernetes-agent:
            volume:
              csi:
                socket: /run/rubernetes/csi/plugin.sock
                socket_mode: 4096
      YAML
      file.flush

      error = assert_raises(Rubernetes::Bootstrap::Config::Error) do
        Rubernetes::Bootstrap::Config.load(process_name: "rubernetes-agent", path: file.path)
      end
      assert_match(/socket_mode/, error.message)
    end
  end

  def test_config_rejects_csi_without_an_absolute_socket
    Tempfile.create(["rubernetes-csi-invalid", ".yml"]) do |file|
      file.write("processes:\n  rubernetes-agent:\n    volume:\n      csi:\n        socket: relative.sock\n")
      file.flush

      error = assert_raises(Rubernetes::Bootstrap::Config::Error) do
        Rubernetes::Bootstrap::Config.load(process_name: "rubernetes-agent", path: file.path)
      end
      assert_match(/csi\.socket.*absolute/, error.message)
    end
  end

  def test_structured_logger_emits_one_json_object
    io = StringIO.new
    clock = -> { Time.utc(2026, 8, 22, 1, 2, 3, 456_789) }
    logger = Rubernetes::Bootstrap::StructuredLogger.new(
      io: io,
      process_name: "rubernetes-agent",
      clock: clock
    )

    assert(logger.info("probe.ready", count: 2))
    payload = JSON.parse(io.string)
    assert_equal("2026-08-22T01:02:03.456789Z", payload.fetch("timestamp"))
    assert_equal("info", payload.fetch("level"))
    assert_equal("probe.ready", payload.fetch("event"))
    assert_equal("rubernetes-agent", payload.fetch("process"))
    assert_equal(2, payload.fetch("count"))
  end

  def test_container_detects_cycles
    container = Rubernetes::Bootstrap::Container.new
    container.register(:left) { |dependencies| dependencies.resolve(:right) }
    container.register(:right) { |dependencies| dependencies.resolve(:left) }

    error = assert_raises(Rubernetes::Bootstrap::Container::DependencyCycle) { container.resolve(:left) }
    assert_match(/left -> right -> left/, error.message)
  end

  def test_shutdown_request_wakes_waiter_without_a_thread
    moments = [1.0]
    shutdown = Rubernetes::Bootstrap::Shutdown.new(clock: -> { moments.fetch(0) })
    shutdown.request!

    request = shutdown.wait(timeout: 0.1)
    assert_equal("REQUESTED", request.signal)
    assert_equal(1.0, request.requested_at)
  ensure
    shutdown&.close
  end

  # A forked child inherits the installed trap blocks and the self-pipe.  A
  # workload signalled between fork and exec must not report its own TERM
  # into the parent's shutdown pipe: that stops the node agent that owns it.
  def test_shutdown_ignores_notifications_from_forked_children
    shutdown = Rubernetes::Bootstrap::Shutdown.new
    shutdown.install!
    child = fork do
      Process.kill("TERM", Process.pid)
      sleep 0.2
      exit!(0)
    end
    Process.waitpid(child)

    assert_nil(shutdown.wait(timeout: 0.2))
    refute(shutdown.requested?)
  ensure
    shutdown&.close
  end

  def test_config_check_assembles_dependencies_and_exits
    stdout = StringIO.new
    stderr = StringIO.new

    status = Rubernetes::Bootstrap::CLI.run(
      process_name: "rubernetes-proxy",
      argv: ["--check-config"],
      stdout: stdout,
      stderr: stderr
    )

    assert_equal(0, status)
    assert_empty(stderr.string)
    assert_equal(true, JSON.parse(stdout.string).fetch("valid"))
  end
end
