# frozen_string_literal: true

require "tempfile"
require_relative "../test_helper"
require "rubernetes/bootstrap/config"
require "rubernetes/bootstrap/runner"
require "rubernetes/cluster"
require "tmpdir"

# A component opens a console only where its configuration names a socket,
# and a console that cannot be opened never keeps the component from running.
class ConsoleConfigTest < Minitest::Test
  Config = Rubernetes::Bootstrap::Config

  def load_config(console)
    file = Tempfile.new(["component", ".yml"])
    file.write(YAML.dump({"version" => 1, "logging" => {"level" => "info"}, "processes" => {}}.merge(console ? {"console" => console} : {})))
    file.flush
    Config.load(process_name: "rubernetes-scheduler", path: file.path)
  ensure
    file&.close
  end

  def test_no_console_unless_the_configuration_names_a_socket
    assert_nil load_config(nil).console_socket
    assert_equal "/run/x/scheduler.sock", load_config({"socket" => "/run/x/scheduler.sock"}).console_socket
  end

  def test_the_socket_must_be_an_absolute_path_and_nothing_else_is_configurable
    assert_raises(Config::Error) { load_config({"socket" => "scheduler.sock"}) }
    assert_raises(Config::Error) { load_config({"socket" => "/run/x.sock", "allow" => "everyone"}) }
    assert_raises(Config::Error) { load_config("/run/x.sock") }
  end

  def test_every_process_of_a_provisioned_cluster_gets_a_socket_of_its_own
    Dir.mktmpdir do |root|
      cluster = Rubernetes::Cluster::Provisioner.new(root: root, name: "unit", controls: 1, workers: 1)
      paths = [cluster.send(:write_scheduler_config, "/x/kubeconfig"), cluster.send(:write_proxy_config, "worker-0", 0, "/x/kubeconfig")]
      sockets = paths.map { |path| YAML.safe_load_file(path).dig("console", "socket") }

      assert_equal [File.join(root, "run", "scheduler.sock"), File.join(root, "run", "proxy-worker-0.sock")], sockets
      assert_match Rubernetes::Cluster::Provisioner::OWN_ENTRIES, "run", "`up` and `delete` must still recognise the directory as a cluster's"
    end
  end

  Assembly = Struct.new(:config, :logger, :shutdown, :service)

  class Recorder
    attr_reader :events

    def initialize = @events = []
    def start = @events << :started
    def stop(reason:) = @events << [:stopped, reason]
    def install! = nil
    def close = nil
    def wait = Struct.new(:signal).new("TERM")
    def warn(event, **) = @events << event
    def error(event, **) = @events << event
  end

  def run_component(socket)
    recorder = Recorder.new
    config = Struct.new(:console_socket, :process_name).new(socket, "rubernetes-scheduler")
    seen = nil
    recorder.define_singleton_method(:wait) do
      seen = socket && File.socket?(socket)
      Struct.new(:signal).new("TERM")
    end
    status = Rubernetes::Bootstrap::Runner.new(assembly: Assembly.new(config, recorder, recorder, recorder)).run
    [status, recorder.events, seen]
  end

  def test_the_console_listens_while_the_component_runs_and_is_gone_afterwards
    Dir.mktmpdir do |directory|
      socket = File.join(directory, "run", "scheduler.sock")
      status, events, listening = run_component(socket)

      assert_equal 0, status
      assert listening, "the socket exists while the component waits for its shutdown signal"
      refute_path_exists socket
      assert_equal [:started, [:stopped, "TERM"]], events
    end
  end

  def test_a_console_that_cannot_be_opened_is_logged_and_the_component_runs
    status, events, = run_component("/proc/nowhere/scheduler.sock")

    assert_equal 0, status
    assert_equal [:started, "console.unavailable", [:stopped, "TERM"]], events
  end

  def test_without_a_socket_nothing_is_opened
    assert_equal [0, [:started, [:stopped, "TERM"]], nil], run_component(nil)
  end
end
