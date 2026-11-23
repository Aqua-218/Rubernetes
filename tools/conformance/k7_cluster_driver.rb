#!/usr/bin/env ruby
# frozen_string_literal: true

# K7 cluster driver for a cluster brought up by tools/conformance/cluster.rb
# (spec/verification/kubernetes-compatibility.md#k7).  k7_lifecycle.rb calls
# it once per stage with the stage id and KUBECONFIG. The lane compares
# the API state before and after and records the driver's observations.
#
# A stage it cannot perform on this topology exits 2 with the reason on
# stderr and is reported INCOMPLETE.
#
#   RUBERNETES_K7_CLUSTER_ROOT  the <root>/<profile> directory (default: the
#                               directory of KUBECONFIG)
require "fileutils"
require "json"
require "open3"
require "rbconfig"
require "time"
require "yaml"

require_relative "../../lib/rubernetes/cluster/processes"
require_relative "../../lib/rubernetes/consensus"
require_relative "k7_topology"
require_relative "k7_release"

module K7ClusterDriver
  extend K7Topology
  extend K7Release

  class Unsupported < StandardError; end

  ROOT = File.expand_path("../..", __dir__)
  KUBECTL = File.join(ROOT, "build/tools/kubectl-v1.36.2")

  module_function

  def run(argv)
    stage = argv.fetch(0) { abort("usage: k7_cluster_driver.rb <stage>") }
    evidence = case stage
               when "memory_to_raft" then memory_to_raft
               when "single_to_three_node" then single_to_three_node
               when "release_upgrade" then release_upgrade
               when "rollback" then rollback
               when "apiserver_rolling_restart" then apiserver_rolling_restart
               when "cluster_rolling_restart" then cluster_rolling_restart
               when "controller_leader_loss" then leader_loss("controller-manager")
               when "scheduler_leader_loss" then leader_loss("scheduler")
               when "worker_reboot" then worker_reboot
               when "backup_restore" then backup_restore
               else raise Unsupported, "unknown stage"
               end
    puts JSON.generate(evidence) if evidence.is_a?(Hash)
    0
  rescue Unsupported => error
    warn "#{stage}: #{error.message}"
    2
  rescue StandardError => error
    warn "#{stage}: #{error.class}: #{error.message}"
    1
  end

  # ------------------------------------------------------------------ stages

  def apiserver_rolling_restart
    servers = api_servers
    raise Unsupported, "rolling restart requires at least three Raft control nodes" if servers.length < 3

    servers.each do |process|
      restart!(process, signal: "TERM")
      wait_until("#{process.fetch("name")} healthy", 180) { apiserver_healthy?(process) }
      wait_until("API endpoint ready", 180) { healthy? }
    end
    {"restarted" => servers.map { |server| server.fetch("name") }}
  end

  def leader_loss(component)
    process = processes.find { |entry| entry.fetch("name") == component } ||
              raise("no #{component} process in cluster.json")
    leader_before = leases.find { |entry| entry.fetch("holder").to_s.include?(component) }
    raise "#{component} had no leadership lease before the loss" unless leader_before

    killed_at = Time.now.utc
    restart!(process, signal: "KILL")
    recovered = nil
    wait_until("#{component} lease renewed after the loss", 180) do
      recovered = leases.find { |entry| entry.fetch("name") == leader_before.fetch("name") }
      recovered && Time.iso8601(recovered.fetch("renew_time")) > killed_at
    end
    {"lease" => recovered.fetch("name"), "holder_before" => leader_before.fetch("holder"), "holder_after" => recovered.fetch("holder"),
     "renewed_at" => recovered.fetch("renew_time")}
  end

  def worker_reboot
    node = ENV.fetch("RUBERNETES_K7_REBOOT_NODE", "worker-2")
    command = ENV.fetch("RUBERNETES_K7_WORKER_REBOOT", nil)
    raise Unsupported, "set RUBERNETES_K7_WORKER_REBOOT to a worker VM reboot executable" unless command && File.file?(command) && File.executable?(command)

    before = kubectl_object("get", "node", node)
    raise Unsupported, "worker #{node} must be Ready before reboot" if before.nil? || !ready_node?(before)

    boot_id = before.dig("status", "nodeInfo", "bootID")
    nodes = kubectl_object("get", "nodes").fetch("items")
    local_boot_id = File.read("/proc/sys/kernel/random/boot_id").strip
    other_ids = nodes.filter_map do |entry|
      entry.dig("status", "nodeInfo", "bootID") unless entry.dig("metadata", "name") == node
    end
    if boot_id.to_s.empty? || boot_id == local_boot_id || other_ids.include?(boot_id)
      raise Unsupported, "worker #{node} does not have a distinct kernel boot ID"
    end

    uid = before.dig("metadata", "uid")
    started_at = Time.now.utc
    _out, err, status = Open3.capture3(command, node, boot_id, chdir: ROOT)
    raise "worker VM reboot command failed: #{err.strip}" unless status.success?

    new_boot_id = nil
    wait_until("#{node} Ready after a new kernel boot and heartbeat", 240) do
      current = kubectl_object("get", "node", node)
      next false unless current && current.dig("metadata", "uid") == uid && ready_node?(current)
      next false unless fresh_worker_lease?(node, since: started_at)

      new_boot_id = current.dig("status", "nodeInfo", "bootID")
      !new_boot_id.to_s.empty? && !([boot_id, local_boot_id] + other_ids).include?(new_boot_id)
    end
    {"worker" => node, "worker_uid" => uid, "boot_id_before" => boot_id, "boot_id_after" => new_boot_id}
  end

  def restart_worker_processes!(node)
    agent = processes.find { |entry| entry.fetch("name") == "agent-#{node}" } || raise("no agent-#{node} process")
    proxy = processes.find { |entry| entry.fetch("name") == "proxy-#{node}" }
    stop!(agent, signal: "TERM")
    stop!(proxy, signal: "TERM") if proxy
    since = Time.now.utc
    start!(agent)
    start!(proxy) if proxy
    wait_for_component!(agent, since)
    wait_for_component!(proxy, since) if proxy
  end

  # Restart the existing daemon commands. Keep at least two API servers
  # running, then restart the controller, scheduler and worker processes.
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
    workers.map { |entry| entry.fetch("name").delete_prefix("agent-") }.sort.each { |node| restart_worker_processes!(node) }
  end

  # One control node loses its datastore directory and is rebuilt from a
  # backup taken just before, while the other two keep the quorum: the
  # acknowledged state must come back identical.
  def backup_restore
    process = api_servers.first || raise("no API server in the cluster")
    datastore = YAML.safe_load_file(process.fetch("config")).dig("processes", "rubernetes-apiserver", "datastore")
    raise Unsupported, "backup and restore requires the Raft datastore" unless datastore.fetch("type") == "raft"

    data_dir = cluster_data_directory(datastore)
    backup_dir = File.join(cluster_root, "backups", Time.now.utc.strftime("%Y%m%dT%H%M%S.%6NZ"))
    with_checkpoint do |checkpoint|
      verify_checkpoint!(checkpoint)
      console(process, "raft.snapshot!; :done")
      stop!(process, signal: "TERM")
      aside = "#{data_dir}.pre-restore-#{Process.pid}"
      begin
        Rubernetes::Consensus::Backup.create(data_dir, backup_dir)
        FileUtils.mv(data_dir, aside)
        Rubernetes::Consensus::Backup.restore(backup_dir, data_dir)
        restored = raft_snapshot(data_dir)
        verify_durable_checkpoint!(restored, checkpoint)
        start!(process)
        wait_until("#{process.fetch("name")} ready after restore", 240) { apiserver_healthy?(process) }
        verify_checkpoint!(checkpoint)
      rescue StandardError
        if File.directory?(aside)
          stop!(process, signal: "TERM") if pid_of(process)
          FileUtils.rm_rf(data_dir)
          FileUtils.mv(aside, data_dir)
        end
        start!(process) unless pid_of(process)
        raise
      end
      FileUtils.rm_rf(aside)
      {"restored_replica" => process.fetch("name"), "backup_directory" => backup_dir,
       "restored_snapshot_revision" => restored.fetch("revision"), "checkpoint_uid" => checkpoint.fetch("uid")}
    end
  end

  # ------------------------------------------------------------- processes

  def cluster_root
    File.expand_path(ENV.fetch("RUBERNETES_K7_CLUSTER_ROOT") { File.dirname(File.expand_path(ENV.fetch("KUBECONFIG"))) })
  end

  def descriptor_path = File.join(cluster_root, "cluster.json")

  def processes
    JSON.parse(File.read(descriptor_path)).fetch("processes")
  end

  def api_servers
    processes.select { |process| process.fetch("executable") == "rubernetes-apiserver" }
  end

  def pid_of(process)
    pid_file = File.join(cluster_root, "pids", "#{process.fetch("name")}.pid")
    candidates = [File.file?(pid_file) ? File.read(pid_file).to_i : nil, process["pid"].to_i].compact.reject(&:zero?)
    candidates.find { |pid| process_alive?(pid, process) }
  end

  def process_alive?(pid, process)
    Rubernetes::Cluster::Processes.alive?(pid) && File.binread("/proc/#{pid}/cmdline").split("\0").include?(process.fetch("config"))
  rescue SystemCallError
    false
  end

  def capture_process!(process)
    pid = pid_of(process)
    raise "#{process.fetch("name")} is not running" unless pid

    argv = File.read("/proc/#{pid}/cmdline").split("\0")
    env = File.read("/proc/#{pid}/environ").split("\0").to_h { |entry| entry.split("=", 2) }
    process["_argv"] = argv
    process["_env"] = env.slice(*env.keys.grep(/\A(PATH|HOME|LANG|MALLOC_ARENA_MAX|RUBY_GC_[A-Z_]+|RUBERNETES_[A-Z_0-9]+)\z/))
    pid
  end

  def stop!(process, signal:)
    pid = capture_process!(process)
    Process.kill(signal, pid)
    wait_for_exit!(process, pid)
  end

  def wait_for_exit!(process, pid)
    wait_until("#{process.fetch("name")} (pid #{pid}) exited", 60) { !process_alive?(pid, process) }
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
    update_descriptor! do |descriptor|
      entry = descriptor.fetch("processes").find { |candidate| candidate.fetch("name") == process.fetch("name") }
      entry["pid"] = pid
    end
  end

  def update_descriptor!
    descriptor = JSON.parse(File.binread(descriptor_path))
    yield descriptor
    Tempfile.create(["cluster-", ".json"], cluster_root) do |file|
      file.write("#{JSON.pretty_generate(descriptor)}\n")
      file.close
      File.rename(file.path, descriptor_path)
    end
  end

  # ------------------------------------------------------------- observing

  def kubectl(*, kubeconfig: ENV.fetch("KUBECONFIG"))
    Open3.capture3({"KUBECONFIG" => kubeconfig, "NO_PROXY" => "*", "no_proxy" => "*"}, KUBECTL, "--request-timeout=10s", *)
  end

  def kubectl_object(*)
    out, _err, status = kubectl(*, "-o", "json")
    JSON.parse(out) if status.success?
  end

  def healthy?(kubeconfig: ENV.fetch("KUBECONFIG"))
    out, _err, status = kubectl("get", "--raw", "/readyz", kubeconfig: kubeconfig)
    status.success? && out.strip == "ok"
  end

  def apiserver_healthy?(process)
    replica = process.fetch("name").sub("apiserver-", "kubeconfig-")
    pid_of(process) && healthy?(kubeconfig: File.join(cluster_root, replica))
  end

  def ready_node?(node)
    ready = node.dig("status", "conditions")&.find { |condition| condition["type"] == "Ready" }
    ready && ready["status"] == "True"
  end

  def fresh_worker_lease?(node, since:)
    lease = kubectl_object("get", "lease", node, "--namespace", "kube-node-lease")
    renewed_at = lease&.dig("spec", "renewTime")
    renewed_at && lease.dig("spec", "holderIdentity") == node && Time.iso8601(renewed_at) >= since
  end

  def wait_for_component!(process, since)
    name = process.fetch("name")
    wait_until("#{name} ready following restart", 240) do
      next false unless pid_of(process)

      case process.fetch("executable")
      when "rubernetes-apiserver" then apiserver_healthy?(process)
      when "rubernetes-agent"
        worker = name.delete_prefix("agent-")
        node = kubectl_object("get", "node", worker)
        node && ready_node?(node) && fresh_worker_lease?(worker, since: since)
      when "rubernetes-proxy"
        serving = YAML.safe_load_file(process.fetch("config")).dig("processes", "rubernetes-proxy", "serving")
        _out, _err, status = Open3.capture3("curl", "--noproxy", "*", "--fail", "--silent", "--max-time", "3",
                                            "http://#{serving.fetch("bind_address")}:#{serving.fetch("port")}/healthz")
        status.success?
      else
        lease = leases.find { |entry| entry.fetch("holder").to_s.include?(name) }
        lease && Time.iso8601(lease.fetch("renew_time")) >= since
      end
    end
  end

  def leases
    out, _err, status = kubectl("get", "leases", "-n", "kube-system", "-o", "json")
    return [] unless status.success?

    JSON.parse(out).fetch("items").map do |item|
      {"name" => item.dig("metadata", "name"), "holder" => item.dig("spec", "holderIdentity"), "renew_time" => item.dig("spec", "renewTime")}
    end
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
