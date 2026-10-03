# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../../tools/conformance/cluster"

# cluster.json and the pid files remember numbers, not processes.  After a
# reboot the number may be anyone's: `start` must not call that cluster
# "running", and `down` must not signal it.
class ConformanceClusterPidOwnershipTest < Minitest::Test
  def test_a_reused_pid_is_not_ours
    pid = Process.spawn("sleep", "30")
    begin
      assert Conformance::Cluster.alive?(pid)
      refute Conformance::Cluster.owned?(pid, "/srv/rbn-demo/linux-amd64-ipv4-native/config/apiserver-control-0.yml")
      assert_nil Conformance::Cluster.terminate(pid, "apiserver-control-0", "/srv/rbn-demo/linux-amd64-ipv4-native")
      assert Conformance::Cluster.alive?(pid), "terminate must leave a stranger's process alone"
    ensure
      Process.kill("KILL", pid)
      Process.wait(pid)
    end
  end

  def test_our_processes_are_recognised_by_their_configuration_path
    config = "/srv/rbn-demo/linux-amd64-ipv4-native/config/agent-worker-0.yml"
    pid = Process.spawn(RbConfig.ruby, "-e", "trap(\"TERM\") { exit }; sleep 30", "--", "--config", config)
    sleep 0.2 until File.binread("/proc/#{pid}/cmdline").include?("--config")
    begin
      assert Conformance::Cluster.owned?(pid, config)
      assert Conformance::Cluster.owned?(pid, "/srv/rbn-demo/linux-amd64-ipv4-native"), "a pid file knows only the cluster directory"
      refute Conformance::Cluster.owned?(pid, "/srv/rbn-other")
      refute_nil Conformance::Cluster.terminate(pid, "agent-worker-0", config)
      refute Conformance::Cluster.alive?(pid)
    ensure
      begin
        Process.kill("KILL", pid)
        Process.wait(pid)
      rescue Errno::ESRCH, Errno::ECHILD
        nil
      end
    end
  end

  def test_a_dead_pid_is_not_ours
    pid = Process.spawn("true")
    Process.wait(pid)

    refute Conformance::Cluster.owned?(pid, "/")
  end
end
