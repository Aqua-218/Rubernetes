# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"
require "tmpdir"
require_relative "../support/node_lifecycle_fakes"
require_relative "../support/private_logind"

# Graceful node shutdown end to end over a private dbus-daemon: the agent's
# shutdown manager raises logind's InhibitDelayMaxSec with its drop-in and a
# reload, holds a delay inhibitor lock, and on PrepareForShutdown(true) goes
# NotReady ("node is shutting down"), refuses new Pods and kills the running
# ones group by group (lowest priority first) as Failed/Terminated with a
# DisruptionTarget condition before releasing the lock.  The cases follow
# test/e2e_node/node_shutdown_linux_test.go (v1.36.2): graceful shutdown with
# the two-group and the by-priority configuration, a cancelled shutdown, a
# restarted D-Bus, and the recorded start/end times.  A stopped agent gives
# the host's logind back as it found it.  DBUS_SYSTEM_BUS_ADDRESS and the
# drop-in directory point at the test's own bus and directory, so the host's
# system bus and /etc/systemd are never touched.
class NodeShutdownPrivateBusTest < Minitest::Test
  Node = Rubernetes::Node
  SM = Node::ShutdownManager
  DBus = Rubernetes::Platform::Linux::DBus

  class API
    attr_reader :nodes

    def initialize
      @nodes = []
      @mutex = Mutex.new
    end

    def register_node(node) = @mutex.synchronize { (@nodes << node).last }
    def renew_lease(lease) = lease
    def last_node = @mutex.synchronize { @nodes.last }
  end

  class Loop
    def start(**) = true
    def stop(**) = true
  end

  def setup
    skip "dbus-daemon is not installed" unless PrivateLogind.available?
    @dir = Dir.mktmpdir("shutdown-bus")
    @daemon = PrivateLogind::Daemon.new(@dir).start
    @conf_dir = File.join(@dir, "logind.conf.d")
    @service = PrivateLogind::Service.new(address: @daemon.address, config_directory: @conf_dir, inhibit_delay_max_sec: 5).start
    @saved_address = ENV.fetch(DBus::SYSTEM_BUS_ADDRESS_ENV, nil)
    ENV[DBus::SYSTEM_BUS_ADDRESS_ENV] = @daemon.address
    SM::Logind.config_directory = @conf_dir
    @runtime = NodeLifecycleFakes::Runtime.new
    @reporter = NodeLifecycleFakes::Reporter.new
    @lifecycle = Node::Lifecycle.new(runtime: @runtime, reporter: @reporter, sleeper: ->(_seconds) {})
    @api = API.new
  end

  def teardown
    @agent&.stop rescue nil
    @service&.stop
    @daemon&.stop
    SM::Logind.config_directory = nil
    ENV[DBus::SYSTEM_BUS_ADDRESS_ENV] = @saved_address if defined?(@saved_address)
    ENV.delete(DBus::SYSTEM_BUS_ADDRESS_ENV) if defined?(@saved_address) && @saved_address.nil?
    FileUtils.rm_rf(@dir) if @dir
  end

  def pod(name, priority: nil, grace: 30)
    spec = {"nodeName" => "node-s", "restartPolicy" => "Always", "terminationGracePeriodSeconds" => grace,
            "containers" => [{"name" => name, "image" => "example/busybox"}]}
    spec["priority"] = priority if priority
    {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => name, "namespace" => "shutdown-e2e", "uid" => "uid-#{name}"},
     "spec" => spec}
  end

  def start_agent(shutdown, pods)
    pods.each { |entry| @lifecycle.start(entry) }
    pod_root = File.join(@dir, "kubelet", "pods")
    FileUtils.mkdir_p(pod_root)
    @agent = Node::Agent.new(node_name: "node-s", api: @api, lifecycle: @lifecycle, sync_loop: Loop.new, sleeper: ->(_) {},
                             pod_root: pod_root, capacity: {"cpu" => "4", "memory" => "8Gi", "pods" => "110"}, shutdown: shutdown)
    @agent.start
    # A test sleeper keeps the agent's loops off; the watch is started here.
    @agent.shutdown_manager.start
    @agent
  end

  def wait_for(what, timeout: 10)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
    until (value = yield)
      flunk "timed out waiting for #{what}" if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
      sleep 0.02
    end
    value
  end

  def ready_condition = @api.last_node.dig("status", "conditions").find { |entry| entry["type"] == "Ready" }

  def kubelet_inhibitors = @service.inhibitors.select { |entry| entry.who == "kubelet" }

  def stops_by_container = @runtime.stopped.to_h

  def test_graceful_shutdown_kills_pods_by_priority_and_gives_logind_back
    pods = [pod("critical", priority: SM::SYSTEM_CRITICAL_PRIORITY), pod("app"), pod("quick", grace: 3), pod("low", priority: -10)]
    start_agent({"grace_period" => "30s", "grace_period_critical_pods" => "10s"}, pods)

    # The inhibit delay is raised with the drop-in and a logind reload, and a
    # delay lock is held.
    lock = wait_for("the inhibitor lock") { kubelet_inhibitors.first }
    assert_equal ["shutdown", "kubelet", "Kubelet needs time to handle node shutdown", "delay"], lock.to_a.first(4)
    assert_equal "# Kubelet logind override\n[Login]\nInhibitDelayMaxSec=30\n", File.read(File.join(@conf_dir, "99-kubelet.conf"))
    assert_equal 30_000_000, @service.inhibit_delay_usec
    assert_equal 1, @service.reloads
    assert_equal ["True", "KubeletReady"], ready_condition.values_at("status", "reason")

    # What `systemd-inhibit --list` asks logind, from another client.
    client = DBus::Connection.system
    rows = client.call(destination: PrivateLogind::LOGIN1, path: PrivateLogind::LOGIN1_PATH, interface: PrivateLogind::MANAGER,
                       member: "ListInhibitors").first
    assert_includes rows.map { |row| row.first(4) }, ["shutdown", "kubelet", "Kubelet needs time to handle node shutdown", "delay"]
    assert_equal 30_000_000, client.get_property(destination: PrivateLogind::LOGIN1, path: PrivateLogind::LOGIN1_PATH,
                                                 interface: PrivateLogind::MANAGER, name: "InhibitDelayMaxUSec")
    client.close

    @service.prepare_for_shutdown(true)
    wait_for("the lock release after the kills") { kubelet_inhibitors.empty? }

    # Non-critical Pods first, each within min(20s, its own grace); the
    # critical group after them within 10s.
    order = @runtime.stopped.map(&:first)
    assert_equal %w[app low quick], order.first(3).sort
    assert_equal "critical", order.last
    assert_equal({"app" => 20, "low" => 20, "quick" => 3, "critical" => 10}, stops_by_container)
    failed = @reporter.statuses.select { |status| status["phase"] == "Failed" }
    assert_equal 4, failed.length
    failed.each do |status|
      assert_equal "Terminated", status["reason"]
      assert_equal SM::SHUTDOWN_MESSAGE, status["message"]
      target = status["conditions"].find { |entry| entry["type"] == "DisruptionTarget" }
      assert_equal ["True", "TerminationByKubelet", SM::SHUTDOWN_MESSAGE], target.values_at("status", "reason", "message")
    end

    # NotReady, published at once; new Pods refused.
    wait_for("Ready=False") { ready_condition["status"] == "False" }
    assert_equal ["False", "KubeletNotReady", "node is shutting down"], ready_condition.values_at("status", "reason", "message")
    decision = @agent.instance_variable_get(:@admission).admit(pod("late"))
    refute decision.accepted
    assert_equal ["NodeShutdown", "Pod was rejected as the node is shutting down."], [decision.reason, decision.message]

    # The start and end times are recorded (state file and gauges).
    state = JSON.parse(File.read(File.join(@dir, "kubelet", SM::STATE_FILE)))
    refute_equal "0001-01-01T00:00:00Z", state["startTime"]
    refute_equal "0001-01-01T00:00:00Z", state["endTime"]
    assert_operator Time.parse(state["endTime"]), :>=, Time.parse(state["startTime"])

    # A cancelled shutdown takes the lock again and the node is Ready again.
    @service.prepare_for_shutdown(false)
    wait_for("the lock after the cancellation") { kubelet_inhibitors.length == 1 }
    assert_nil @agent.shutdown_manager.shutdown_status
    ready = @agent.send(:build_node, ready: true).dig("status", "conditions").find { |entry| entry["type"] == "Ready" }
    assert_equal "True", ready["status"]

    # Stopping the agent releases the lock and removes the drop-in (and the
    # directory it created), and logind is reloaded back to its own delay.
    @agent.stop
    @agent = nil
    assert_empty kubelet_inhibitors
    refute File.exist?(File.join(@conf_dir, "99-kubelet.conf"))
    refute File.exist?(@conf_dir)
    assert_equal 2, @service.reloads
    assert_equal 5_000_000, @service.inhibit_delay_usec
  end

  def test_pod_priority_groups_each_get_their_own_period
    by_priority = [{"priority" => 100_000, "shutdown_grace_period_seconds" => 4},
                   {"priority" => 10_000, "shutdown_grace_period_seconds" => 3},
                   {"priority" => 1_000, "shutdown_grace_period_seconds" => 2},
                   {"priority" => 0, "shutdown_grace_period_seconds" => 1}]
    pods = [pod("p-critical", priority: 100_000), pod("p-high", priority: 10_000), pod("p-medium", priority: 1_000),
            pod("p-low", priority: 0), pod("p-between", priority: 5_000)]
    start_agent({"grace_period_by_pod_priority" => by_priority}, pods)
    wait_for("the inhibitor lock") { kubelet_inhibitors.first }
    assert_equal 10_000_000, @service.inhibit_delay_usec, "sum of the groups' periods"

    @service.prepare_for_shutdown(true)
    wait_for("the lock release after the kills") { kubelet_inhibitors.empty? }
    order = @runtime.stopped.map(&:first)
    assert_equal "p-low", order.first
    assert_equal %w[p-between p-medium], order[1, 2].sort, "5000 falls in the 1000 group"
    assert_equal %w[p-high p-critical], order.last(2)
    assert_equal({"p-low" => 1, "p-medium" => 2, "p-between" => 2, "p-high" => 3, "p-critical" => 4}, stops_by_container)
  end

  def test_the_lock_is_taken_again_after_dbus_restarts
    start_agent({"grace_period" => "30s", "grace_period_critical_pods" => "10s"}, [pod("app")])
    wait_for("the inhibitor lock") { kubelet_inhibitors.first }

    @service.stop
    @daemon.stop
    @daemon.start
    @service = PrivateLogind::Service.new(address: @daemon.address, config_directory: @conf_dir, inhibit_delay_max_sec: 5).start
    # The new logind reads the drop-in the agent left.
    @service.send(:reload)
    wait_for("the lock on the restarted bus", timeout: 15) { kubelet_inhibitors.first }

    @service.prepare_for_shutdown(true)
    wait_for("the lock release after the kills") { kubelet_inhibitors.empty? }
    assert_equal({"app" => 20}, stops_by_container)
  end

  def test_without_a_grace_period_logind_is_never_contacted
    [{}, {"grace_period" => "0s"}, {"grace_period" => "0s", "grace_period_critical_pods" => "0s"},
     {"grace_period_by_pod_priority" => []}].each do |shutdown|
      SM::Logind.stub(:new, ->(*) { flunk "the shutdown manager contacted logind with #{shutdown.inspect}" }) do
        agent = Node::Agent.new(node_name: "node-s", api: API.new, lifecycle: @lifecycle, sync_loop: Loop.new, sleeper: ->(_) {},
                                capacity: {"cpu" => "4", "memory" => "8Gi", "pods" => "110"}, shutdown: shutdown)
        assert_nil agent.shutdown_manager, "upstream default shutdownGracePeriod 0 = no manager (#{shutdown.inspect})"
        agent.start
        agent.stop
      end
    end
    assert_nil Node::Agent.new(node_name: "node-s", api: API.new, lifecycle: @lifecycle, sync_loop: Loop.new, sleeper: ->(_) {}).shutdown_manager
    assert_empty @service.inhibitors
    refute File.exist?(@conf_dir)
    calls = []
    calls << @service.calls.pop until @service.calls.empty?
    assert_empty calls, "nothing reached the (private) logind"
  end
  # Ubuntu's unattended-upgrades ships logind.conf.d/unattended-upgrades-
  # logind-maxdelay.conf (InhibitDelayMaxSec=30); drop-ins apply in name
  # order, so it overrides 99-kubelet.conf and the delay never rises.  As
  # for the kubelet, the manager fails to start once -- one reload, no lock,
  # no retry -- and the node runs on; stopping still takes the drop-in back.
  def test_a_drop_in_logind_overrides_fails_the_start_once
    FileUtils.mkdir_p(@conf_dir)
    File.write(File.join(@conf_dir, "unattended-upgrades-logind-maxdelay.conf"), "[Login]\nInhibitDelayMaxSec=30\n")
    @service.send(:reload)
    errors = []
    pod_root = File.join(@dir, "kubelet", "pods")
    FileUtils.mkdir_p(pod_root)
    @agent = Node::Agent.new(node_name: "node-s", api: @api, lifecycle: @lifecycle, sync_loop: Loop.new, sleeper: ->(_) {},
                             pod_root: pod_root, capacity: {"cpu" => "4", "memory" => "8Gi", "pods" => "110"},
                             shutdown: {"grace_period" => "45s", "grace_period_critical_pods" => "15s"},
                             error_handler: ->(error, during) { errors << [error.message, during] })
    @agent.start
    assert_equal false, @agent.shutdown_manager.start
    assert_equal [["Failed to start node shutdown manager: node shutdown manager was timed out after 5 attempts waiting for " \
                   "logind InhibitDelayMaxSec to update to 45s (ShutdownGracePeriod), current value is 30s", :shutdown_manager]],
                 errors.select { |_, during| during == :shutdown_manager }
    assert File.file?(File.join(@conf_dir, "99-kubelet.conf"))
    sleep 1.5
    assert_equal 2, @service.reloads, "the test's own reload and the manager's one -- no retry"
    assert_empty kubelet_inhibitors
    assert_equal "True", ready_condition["status"]

    @agent.stop
    @agent = nil
    refute File.exist?(File.join(@conf_dir, "99-kubelet.conf"))
    assert File.file?(File.join(@conf_dir, "unattended-upgrades-logind-maxdelay.conf"))
    assert_equal 3, @service.reloads
  end
end
