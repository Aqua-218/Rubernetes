#!/usr/bin/env ruby
# frozen_string_literal: true

# K7 cluster driver for a cluster brought up by tools/conformance/cluster.rb
# (spec/verification/kubernetes-compatibility.md#k7).  k7_lifecycle.rb calls
# it once per stage with the stage id and KUBECONFIG, and once more with
# `<stage>-reversible`; the lane compares the API state before and after.
#
# The driver changes the cluster only through its real processes: it stops a
# process, starts the same executable with the same configuration and waits
# for the component to report healthy again.  A stage it cannot perform on
# this topology exits 2 with the reason on stderr and is reported INCOMPLETE,
# never as a pass.
#
#   RUBERNETES_K7_CLUSTER_ROOT  the <root>/<profile> directory (default: the
#                               directory of KUBECONFIG)
require "fileutils"
require "json"
require "open3"
require "rbconfig"
require "time"
require "yaml"

module K7ClusterDriver
  ROOT = File.expand_path("../..", __dir__)
  KUBECTL = File.join(ROOT, "build/tools/kubectl-v1.36.2")
  NOT_ON_THIS_TOPOLOGY = {
    "single_to_three_node" => "the lane cluster starts with three control nodes and Raft membership changes are " \
                              "not exposed as an operator command (they are exercised in-process by the M5 fault matrix)",
    "memory_to_raft" => "the lane cluster already runs the Raft datastore; a MemoryStore-to-RaftStore migration " \
                        "needs a MemoryStore cluster to start from and no operator migration command exists yet",
    "release_upgrade" => "0.1.0 is the first release: there is no previous release artifact to upgrade from",
    "rollback" => "0.1.0 is the first release: there is no previous release to roll back to"
  }.freeze

  module_function

  def run(argv)
    stage = argv.fetch(0) { abort("usage: k7_cluster_driver.rb <stage>|<stage>-reversible") }
    if stage.end_with?("-reversible")
      base = stage.delete_suffix("-reversible")
      return 1 if NOT_ON_THIS_TOPOLOGY.key?(base)

      return healthy? ? 0 : 1
    end
    if NOT_ON_THIS_TOPOLOGY.key?(stage)
      warn "#{stage}: not performed: #{NOT_ON_THIS_TOPOLOGY.fetch(stage)}"
      return 2
    end

    case stage
    when "apiserver_rolling_restart" then apiserver_rolling_restart
    when "cluster_rolling_restart" then cluster_rolling_restart
    when "controller_leader_loss" then leader_loss("controller-manager")
    when "scheduler_leader_loss" then leader_loss("scheduler")
    when "worker_reboot" then worker_reboot
    when "backup_restore" then backup_restore
    else
      warn "#{stage}: unknown stage"
      return 2
    end
    0
  rescue StandardError => error
    warn "#{stage}: #{error.class}: #{error.message}"
    1
  end

  # ------------------------------------------------------------------ stages

  def apiserver_rolling_restart
    processes.select { |process| process.fetch("executable") == "rubernetes-apiserver" }.each do |process|
      restart!(process, signal: "TERM")
      wait_until("#{process.fetch("name")} healthy", 180) { apiserver_healthy?(process) }
      wait_until("API endpoint ready", 180) { healthy? }
    end
  end

  def leader_loss(component)
    process = processes.find { |entry| entry.fetch("name") == component } ||
              raise("no #{component} process in cluster.json")
    killed_at = Time.now.utc
    restart!(process, signal: "KILL")
    wait_until("#{component} lease renewed after the loss", 180) do
      lease = leases.find { |entry| entry.fetch("holder").to_s.include?(component) }
      lease && Time.iso8601(lease.fetch("renew_time")) > killed_at
    end
  end

  def worker_reboot
    reboot_worker!("worker-2")
  end

  def reboot_worker!(node)
    agent = processes.find { |entry| entry.fetch("name") == "agent-#{node}" } || raise("no agent-#{node} process")
    proxy = processes.find { |entry| entry.fetch("name") == "proxy-#{node}" }
    stop!(agent, signal: "TERM")
    stop!(proxy, signal: "TERM") if proxy
    start!(agent)
    start!(proxy) if proxy
    wait_until("#{node} Ready with a fresh heartbeat", 240) do
      out, _err, status = kubectl("get", "node", node, "-o", "json")
      next false unless status.success?

      ready = JSON.parse(out).dig("status", "conditions")&.find { |condition| condition["type"] == "Ready" }
      ready && ready["status"] == "True" && Time.iso8601(ready["lastHeartbeatTime"]) > Time.now.utc - 30
    end
  end

  # Every process of the cluster, one at a time and never two control nodes
  # together, so a cluster whose processes predate the code under test is
  # brought onto it without losing quorum or a node's Pods: the API servers,
  # then scheduler and controller-manager, then each worker's agent and
  # proxy.  This is the operator "upgrade" procedure of deploy/cluster/README.md
  # applied to a cluster.rb layout.
  def cluster_rolling_restart
    apiserver_rolling_restart
    %w[scheduler controller-manager].each do |component|
      process = processes.find { |entry| entry.fetch("name") == component } || next
      restarted_at = Time.now.utc
      restart!(process, signal: "TERM")
      wait_until("#{component} lease renewed after the restart", 180) do
        lease = leases.find { |entry| entry.fetch("holder").to_s.include?(component) }
        lease && Time.iso8601(lease.fetch("renew_time")) > restarted_at
      end
    end
    workers = processes.select { |entry| entry.fetch("name").start_with?("agent-") }
    workers.map { |entry| entry.fetch("name").delete_prefix("agent-") }.sort.each { |node| reboot_worker!(node) }
  end

  # One control node loses its datastore directory and is rebuilt from a
  # backup taken just before, while the other two keep the quorum: the
  # acknowledged state must come back identical.
  def backup_restore
    process = processes.find { |entry| entry.fetch("name") == "apiserver-control-0" } || raise("no apiserver-control-0 process")
    config = YAML.safe_load_file(process.fetch("config"), aliases: true)
    datastore = config.fetch("processes").fetch("rubernetes-apiserver").fetch("datastore")
    data_dir = datastore.fetch("data_dir")
    backup_dir = File.join(cluster_root, "backups", Time.now.utc.strftime("%Y%m%dT%H%M%SZ"))
    stop!(process, signal: "TERM")
    consensus(<<~RUBY)
      Rubernetes::Consensus::Backup.create(#{data_dir.inspect}, #{backup_dir.inspect})
    RUBY
    aside = "#{data_dir}.pre-restore-#{Process.pid}"
    FileUtils.mv(data_dir, aside)
    consensus(<<~RUBY)
      Rubernetes::Consensus::Backup.restore(#{backup_dir.inspect}, #{data_dir.inspect})
    RUBY
    start!(process)
    wait_until("apiserver-control-0 healthy after restore", 240) { apiserver_healthy?(process) }
    wait_until("API endpoint ready", 180) { healthy? }
    FileUtils.rm_rf(aside)
  end

  # ------------------------------------------------------------- processes

  def cluster_root
    ENV.fetch("RUBERNETES_K7_CLUSTER_ROOT") { File.dirname(File.expand_path(ENV.fetch("KUBECONFIG"))) }
  end

  def descriptor_path = File.join(cluster_root, "cluster.json")

  def processes
    JSON.parse(File.read(descriptor_path)).fetch("processes")
  end

  def pid_of(process)
    pid_file = File.join(cluster_root, "pids", "#{process.fetch("name")}.pid")
    candidates = [File.file?(pid_file) ? File.read(pid_file).to_i : nil, process["pid"].to_i].compact.reject(&:zero?)
    candidates.find do |pid|
      File.read("/proc/#{pid}/cmdline").include?(process.fetch("config"))
    rescue SystemCallError
      false
    end
  end

  def stop!(process, signal:)
    pid = pid_of(process)
    if pid.nil?
      # Already down (a crash before the stage): take the command line from a
      # running process of the same executable so the start is still real.
      sibling = processes.find { |entry| entry.fetch("executable") == process.fetch("executable") && pid_of(entry) }
      raise("#{process.fetch("name")} is not running and no #{process.fetch("executable")} sibling is") if sibling.nil?

      template = pid_of(sibling)
      process["_argv"] = File.read("/proc/#{template}/cmdline").split("\0").map { |arg| arg == sibling.fetch("config") ? process.fetch("config") : arg }
      env = File.read("/proc/#{template}/environ").split("\0").to_h { |entry| entry.split("=", 2) }
      process["_env"] = env.slice(*env.keys.grep(/\A(PATH|HOME|LANG|MALLOC_ARENA_MAX|RUBY_GC_[A-Z_]+|RUBERNETES_[A-Z_0-9]+)\z/))
      return
    end

    argv = File.read("/proc/#{pid}/cmdline").split("\0")
    env = File.read("/proc/#{pid}/environ").split("\0").to_h { |entry| entry.split("=", 2) }
    process["_argv"] = argv
    process["_env"] = env.slice(*env.keys.grep(/\A(PATH|HOME|LANG|MALLOC_ARENA_MAX|RUBY_GC_[A-Z_]+|RUBERNETES_[A-Z_0-9]+)\z/))
    Process.kill(signal, pid)
    wait_until("#{process.fetch("name")} (pid #{pid}) exited", 60) do
      Process.kill(0, pid)
      false
    rescue Errno::ESRCH
      true
    end
  end

  # A cluster inside a network namespace (tools/conformance/netns_env.sh) sees
  # cgroup2 only through the remount that `netns_env.sh exec` performs: a
  # process started with a plain `ip netns exec` finds no cgroup v2 and the
  # node agent refuses to start.  The same entry sequence is used here.
  def start!(process)
    argv = process.fetch("_argv")
    namespace = ENV.fetch("RUBERNETES_M8_NETNS", "").strip
    unless namespace.empty?
      argv = ["ip", "netns", "exec", namespace, "sh", "-c",
              'mountpoint -q /sys/fs/cgroup || mount -t cgroup2 cgroup2 /sys/fs/cgroup; exec "$@"', "_", *argv]
    end
    log = process.fetch("log") { File.join(cluster_root, "logs", "#{process.fetch("name")}.log") }
    pid = Process.spawn(process.fetch("_env"), *argv, chdir: ROOT, pgroup: true, unsetenv_others: true,
                                                      in: File::NULL, out: [log, "a"], err: %i[child out])
    Process.detach(pid)
    record_pid!(process, pid)
    pid
  end

  def restart!(process, signal:)
    stop!(process, signal: signal)
    start!(process)
  end

  def record_pid!(process, pid)
    FileUtils.mkdir_p(File.join(cluster_root, "pids"))
    File.write(File.join(cluster_root, "pids", "#{process.fetch("name")}.pid"), "#{pid}\n")
    descriptor = JSON.parse(File.read(descriptor_path))
    descriptor.fetch("processes").each { |entry| entry["pid"] = pid if entry.fetch("name") == process.fetch("name") }
    File.write(descriptor_path, "#{JSON.pretty_generate(descriptor)}\n")
  end

  # ------------------------------------------------------------- observing

  def kubectl(*)
    Open3.capture3({"KUBECONFIG" => ENV.fetch("KUBECONFIG"), "NO_PROXY" => "*", "no_proxy" => "*"}, KUBECTL, *)
  end

  def healthy?
    out, _err, status = kubectl("get", "--raw", "/readyz")
    status.success? && out.strip == "ok"
  end

  def apiserver_healthy?(process)
    config = YAML.safe_load_file(process.fetch("config"), aliases: true)
    section = config.fetch("processes").fetch("rubernetes-apiserver")
    address = section.fetch("bind_address", "127.0.0.1")
    address = "127.0.0.1" if %w[0.0.0.0 ::].include?(address)
    _out, _err, status = Open3.capture3("curl", "--noproxy", "*", "-k", "-s", "--max-time", "3", "-o", File::NULL, "-w", "%{http_code}",
                                        "https://#{address}:#{section.fetch("port")}/healthz")
    status.success?
  end

  def leases
    out, _err, status = kubectl("get", "leases", "-n", "kube-system", "-o", "json")
    return [] unless status.success?

    JSON.parse(out).fetch("items").map do |item|
      {"name" => item.dig("metadata", "name"), "holder" => item.dig("spec", "holderIdentity"), "renew_time" => item.dig("spec", "renewTime")}
    end
  end

  def consensus(code)
    out, err, status = Open3.capture3(RbConfig.ruby, "-I", File.join(ROOT, "lib"), "-e", "require \"rubernetes/consensus\"\n#{code}", chdir: ROOT)
    raise "consensus helper failed: #{err.lines.last(3).join.strip}" unless status.success?

    out
  end

  def wait_until(what, seconds)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + seconds
    loop do
      return true if yield

      raise "timed out after #{seconds}s waiting for #{what}" if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline

      sleep 1
    end
  end
end

exit(K7ClusterDriver.run(ARGV)) if $PROGRAM_NAME == __FILE__
