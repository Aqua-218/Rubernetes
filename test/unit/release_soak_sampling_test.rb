# frozen_string_literal: true

require_relative "../test_helper"
require "tmpdir"
require File.expand_path("../../tools/release/soak", __dir__)

# The soak samples the soaked cluster's processes, named by its pids/*.pid
# files.  Matching every process whose command line merely mentions a daemon
# name made the 2026-10-01 baseline a set of 70 transient pids (shells, test
# runs, other clusters), so any of them ending was an "unexpected exit".
class ReleaseSoakSamplingTest < Minitest::Test
  Soak = Release::Soak

  def test_cluster_processes_come_from_the_pid_files
    Dir.mktmpdir do |root|
      FileUtils.mkdir_p(File.join(root, "pids"))
      File.write(File.join(root, "pids", "apiserver-control-0.pid"), "#{Process.pid}\n")
      File.write(File.join(root, "pids", "agent-worker-0.pid"), "999999999\n")
      File.write(File.join(root, "pids", "broken.pid"), "not a pid\n")
      File.write(File.join(root, "cluster.json"), "{}")

      processes = Soak.cluster_processes(root)

      assert_equal %w[agent-worker-0 apiserver-control-0], processes.map { |entry| entry["name"] }.sort
      live = processes.find { |entry| entry["name"] == "apiserver-control-0" }

      assert_equal Process.pid, live["pid"]
      assert_operator live["rss_kb"], :>, 0
      gone = processes.find { |entry| entry["name"] == "agent-worker-0" }

      assert_equal false, gone["alive"]
      assert_equal 0, gone["rss_kb"]
      assert_equal root, Soak.default_cluster_root(File.join(root, "kubeconfig"))
    end
  end

  def test_no_cluster_root_without_a_cluster_layout
    Dir.mktmpdir do |root|
      assert_nil Soak.default_cluster_root(File.join(root, "kubeconfig"))
    end
    assert_nil Soak.default_cluster_root(nil)
  end

  def test_host_wide_fallback_matches_only_daemon_executables
    bystander = spawn("sh", "-c", "exec sleep 30 # rubernetes-agent rubectl", out: File::NULL)
    sleep 0.2
    pids = Soak.component_processes.map { |entry| entry["pid"] }

    refute_includes pids, bystander, "a process whose arguments mention a daemon name is not a daemon"
  ensure
    Process.kill("KILL", bystander) if bystander
    Process.wait(bystander) if bystander
  end

  def test_sample_is_scoped_and_detects_an_exit
    Dir.mktmpdir do |root|
      FileUtils.mkdir_p(File.join(root, "pids"))
      File.write(File.join(root, "pids", "scheduler.pid"), Process.pid.to_s)
      options = {cluster_root: root, kubeconfig: nil}
      baseline = Soak.collect(options)

      assert_equal root, baseline["scope"]
      File.write(File.join(root, "pids", "scheduler.pid"), "999999999")
      later = Soak.collect(options)
      findings = Hash.new { |hash, key| hash[key] = [] }
      Soak.detect(baseline, later, findings)

      exited = findings["process_exit"].map { |entry| entry["pid"] }

      assert_equal [Process.pid], exited
    end
  end
end
