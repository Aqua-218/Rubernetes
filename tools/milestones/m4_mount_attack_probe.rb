#!/usr/bin/env ruby
# frozen_string_literal: true

require "fileutils"
require "json"
require "open3"
require "rbconfig"
require "tmpdir"
require_relative "m4_probe_support"

def m4_proc_start_time_ticks(pid)
  value = File.binread("/proc/#{Integer(pid)}/stat", 16 * 1024)
  closing_parenthesis = value.rindex(")")
  raise "process stat has no closing command name" unless closing_parenthesis

  start_time = Integer(value.byteslice(closing_parenthesis + 2..).to_s.split.fetch(19))
  raise "process start time is invalid" unless start_time.positive?

  start_time
end

def m4_mount_namespace_inode(pid = Process.pid)
  File.stat("/proc/#{Integer(pid)}/ns/mnt").ino
end

def m4_read_mountinfo(pid = Process.pid)
  File.binread("/proc/#{Integer(pid)}/mountinfo").lines.map(&:chomp)
end

def m4_mountinfo_line(pid, target)
  escaped = target.to_s.gsub("\\", "\\\\").gsub(" ", "\\040").gsub("\t", "\\011")
  m4_read_mountinfo(pid).find do |line|
    fields = line.split(" - ", 2).first.to_s.split(" ")
    fields.length >= 5 && fields[4] == escaped
  end
end

def m4_native_target_identity(pid, target, mount_identity)
  stat = File.stat(target)
  line = m4_mountinfo_line(pid, target)
  raise "native mount is absent from child mountinfo" unless line

  {
    "path" => File.expand_path(target),
    "device" => stat.dev,
    "inode" => stat.ino,
    "mode" => stat.mode,
    "mount_id" => Integer(mount_identity.fetch("mountId")),
    "device_major_minor" => mount_identity.fetch("deviceId").to_s,
    "filesystem" => mount_identity.fetch("filesystem").to_s,
    "mountinfo_line" => line
  }
end

# A bind mount keeps the superblock identity of its source (filesystem,
# device, kernel source); only the bound path is added so the record shows
# which directory the node bound.  Overriding the filesystem name would make
# the durable identity disagree with the kernel readback at unmount time.
def m4_native_bind_result(result, source)
  result.merge(
    "sourceIdentity" => File.expand_path(source.to_s),
    "bindSource" => File.expand_path(source.to_s)
  )
end

def m4_write_marker(path, value)
  temporary = "#{path}.tmp-#{Process.pid}"
  begin
    File.open(temporary, File::WRONLY | File::CREAT | File::EXCL, 0o600) do |file|
      file.write(JSON.generate(value))
      file.flush
      file.fsync
    end
    File.rename(temporary, path)
    directory = File.open(File.dirname(path), File::RDONLY)
    directory.fsync
    directory.close
  rescue SystemCallError, IOError
    File.delete(temporary) if temporary && File.exist?(temporary)
    raise
  ensure
    File.delete(temporary) if temporary && File.exist?(temporary)
  end
end

def m4_wait_for_parent_release!(release_path)
  sleep 0.05 until File.file?(release_path)
end

def m4_native_manager(data_dir, filesystem_adapter, mount_adapter)
  manager_class = M4ProbeSupport.constant("Rubernetes::Volume::Manager")
  path_security_class = M4ProbeSupport.constant("Rubernetes::Volume::PathSecurity")
  openat2_class = M4ProbeSupport.constant("Rubernetes::Platform::Linux::Openat2")
  raise "production volume manager is unavailable" unless manager_class.is_a?(Class)
  raise "descriptor-capable volume path security is unavailable" unless path_security_class.is_a?(Class) && openat2_class.is_a?(Class)

  openat2 = openat2_class.new(root: "/", strict: true)
  path_security = path_security_class.new(root: "/", adapter: openat2, require_openat2: true)
  manager_class.new(data_dir: data_dir, root: File.join(data_dir, "volumes"), adapter: filesystem_adapter,
                    mount_adapter: mount_adapter, path_security: path_security, fsync: true)
end

def m4_native_crash_child!
  data_dir = File.expand_path(ARGV.fetch(1))
  filesystem_class = M4ProbeSupport.constant("Rubernetes::Volume::FilesystemAdapter")
  native_class = M4ProbeSupport.constant("Rubernetes::Volume::NativeMountAdapter")
  linux_mount_class = M4ProbeSupport.constant("Rubernetes::Platform::Linux::Mount")
  raise "production FilesystemAdapter is unavailable" unless filesystem_class.is_a?(Class)
  raise "production NativeMountAdapter is unavailable" unless native_class.is_a?(Class)
  raise "production Linux mount adapter is unavailable" unless linux_mount_class.is_a?(Class)

  linux_mount_class.new.make_private(target: "/", recursive: true, resource_id: "m4-native-crash:private")
  mount_root = File.join(data_dir, "mounts")
  filesystem_adapter = filesystem_class.new(root: mount_root, fsync: true)
  host_source = File.join(data_dir, "host-source")
  FileUtils.mkdir_p(host_source)
  stage_path = File.join(data_dir, "m4-crash-stage")
  marker_path = File.join(data_dir, "crash-child-ready.json")
  release_path = File.join(data_dir, "crash-child-release")
  boundary_class = Class.new(native_class) do
    define_method(:initialize) do |marker_path:, release_path:|
      super()
      @marker_path = marker_path
      @release_path = release_path
    end

    define_method(:mount) do |**kwargs|
      result = super(**kwargs)
      target = kwargs.fetch(:target)
      target_identity = m4_native_target_identity(Process.pid, target, result)
      child = {
        "pid" => Process.pid,
        "start_time_ticks" => m4_proc_start_time_ticks(Process.pid),
        "mount_namespace_inode" => m4_mount_namespace_inode(Process.pid),
        "path" => "/proc/#{Process.pid}/ns/mnt"
      }
      effect_boundary = {
        "name" => "native_mount_complete_before_node_record_commit",
        "phase" => "after_effect_before_durable_commit",
        "operation" => "NodeStageVolume",
        "syscall" => "mount(2)",
        "observed" => true,
        "pid" => child.fetch("pid"),
        "start_time_ticks" => child.fetch("start_time_ticks"),
        "mount_namespace_inode" => child.fetch("mount_namespace_inode"),
        "target" => target_identity.fetch("path"),
        "mount_id" => target_identity.fetch("mount_id"),
        "target_device" => target_identity.fetch("device"),
        "target_inode" => target_identity.fetch("inode")
      }
      observation = {
        "operation" => "NodeStageVolume",
        "child" => child,
        "effect_boundary" => effect_boundary,
        "target" => target_identity,
        "mountinfo" => m4_read_mountinfo(Process.pid)
      }
      m4_write_marker(@marker_path, {
        "volume_id" => "m4-crash-volume",
        "state" => "Attached",
        "operation" => "NodeStageVolume",
        "measurement_source" => "native_mount_namespace",
        "mount_adapter_class" => self.class.superclass.name,
        "backend_adapter_class" => filesystem_adapter.class.name,
        "observation" => observation,
        "observation_sha256" => M4ProbeSupport.digest(observation),
        "effect_boundary_sha256" => M4ProbeSupport.digest(effect_boundary),
        "child_identity_sha256" => M4ProbeSupport.digest(child),
        "target_identity_sha256" => M4ProbeSupport.digest(target_identity),
        "mountinfo_sha256" => Digest::SHA256.hexdigest(observation.fetch("mountinfo").join("\n"))
      })
      m4_wait_for_parent_release!(@release_path)
      m4_native_bind_result(result, kwargs.fetch(:source))
    end

  end
  native_adapter = boundary_class.new(marker_path: marker_path, release_path: release_path)
  manager = m4_native_manager(data_dir, filesystem_adapter, native_adapter)
  volume_id = manager.create_volume({"id" => "m4-crash-volume", "name" => "m4-crash-volume", "backend" => "hostPath",
                                     "path" => host_source, "type" => "Directory",
                                     "accessModes" => ["ReadWriteOnce"]}, token: "m4-crash-create")
  manager.publish(volume_id, "m4-crash-node", token: "m4-crash-attach")
  manager.stage(volume_id, stage_path, token: "m4-crash-stage", node: "m4-crash-node")
  raise "native crash child returned before the parent killed it"
end

def m4_native_restart_child!
  data_dir = File.expand_path(ARGV.fetch(1))
  filesystem_class = M4ProbeSupport.constant("Rubernetes::Volume::FilesystemAdapter")
  native_class = M4ProbeSupport.constant("Rubernetes::Volume::NativeMountAdapter")
  linux_mount_class = M4ProbeSupport.constant("Rubernetes::Platform::Linux::Mount")
  raise "production FilesystemAdapter is unavailable" unless filesystem_class.is_a?(Class)
  raise "production NativeMountAdapter is unavailable" unless native_class.is_a?(Class)
  linux_mount_class.new.make_private(target: "/", recursive: true, resource_id: "m4-native-restart:private")
  filesystem_adapter = filesystem_class.new(root: File.join(data_dir, "mounts"), fsync: true)
  restart_adapter_class = Class.new(native_class) do
    define_method(:initialize) do
      super()
      @bind_sources = {}
    end

    define_method(:mount) do |**kwargs|
      result = super(**kwargs)
      @bind_sources[File.expand_path(kwargs.fetch(:target).to_s)] = File.expand_path(kwargs.fetch(:source).to_s)
      m4_native_bind_result(result, kwargs.fetch(:source))
    end

    define_method(:list_mounts) do
      super().map do |entry|
        source = @bind_sources[File.expand_path(entry.fetch("target").to_s)]
        source ? entry.merge("sourceIdentity" => source, "bindSource" => source) : entry
      end
    end

  end
  native_adapter = restart_adapter_class.new
  manager = m4_native_manager(data_dir, filesystem_adapter, native_adapter)
  recovery = manager.recover(observed_mounts: [])
  stage_path = File.join(data_dir, "m4-crash-stage")
  publish_path = File.join(data_dir, "m4-crash-publish")
  manager.stage("m4-crash-volume", stage_path, token: "m4-crash-restart-stage", node: "m4-crash-node")
  stage = manager.volume("m4-crash-volume").stages.fetch(stage_path)
  manager.node_publish("m4-crash-volume", {"metadata" => {"uid" => "m4-crash-pod"}}, publish_path,
                       readonly: false, token: "m4-crash-restart-publish", node: "m4-crash-node")
  publish = manager.volume("m4-crash-volume").publishes.values.find { |entry| entry["target"] == publish_path }
  raise "native restart child did not persist stage identity" unless stage.is_a?(Hash)
  raise "native restart child did not persist publish identity" unless publish.is_a?(Hash)
  observation = {
    "operation" => %w[NodeStageVolume NodePublishVolume],
    "child" => {"pid" => Process.pid, "start_time_ticks" => m4_proc_start_time_ticks(Process.pid),
                 "mount_namespace_inode" => m4_mount_namespace_inode(Process.pid),
                 "path" => "/proc/#{Process.pid}/ns/mnt"},
    "stage_target" => m4_native_target_identity(Process.pid, stage_path, stage),
    "publish_target" => m4_native_target_identity(Process.pid, publish_path, publish),
    "mountinfo" => m4_read_mountinfo(Process.pid),
    "recovery_unknown_count" => Array(recovery.unknown).length
  }
  marker_path = File.join(data_dir, "restart-child-ready.json")
  release_path = File.join(data_dir, "restart-child-release")
  m4_write_marker(marker_path, {
    "passed" => recovery.unknown.empty?,
    "measurement_source" => "native_mount_namespace",
    "operations" => observation.fetch("operation"),
    "observation" => observation,
    "observation_sha256" => M4ProbeSupport.digest(observation),
    "child_identity_sha256" => M4ProbeSupport.digest(observation.fetch("child")),
    "mountinfo_sha256" => Digest::SHA256.hexdigest(observation.fetch("mountinfo").join("\n"))
  })
  m4_wait_for_parent_release!(release_path)
  manager.node_unpublish("m4-crash-volume", {"metadata" => {"uid" => "m4-crash-pod"}}, publish_path,
                          token: "m4-crash-restart-unpublish")
  manager.unstage("m4-crash-volume", stage_path, token: "m4-crash-restart-unstage", node: "m4-crash-node")
  manager.unpublish("m4-crash-volume", "m4-crash-node", token: "m4-crash-restart-detach")
  manager.delete_volume("m4-crash-volume", token: "m4-crash-restart-delete")
end

if ARGV.first == "--m4-native-crash-child"
  M3ProbeSupport.load_production!
  m4_native_crash_child!
  exit 0
elsif ARGV.first == "--m4-native-restart-child"
  M3ProbeSupport.load_production!
  m4_native_restart_child!
  exit 0
end

def m4_read_json_marker(path)
  return nil unless File.file?(path)

  JSON.parse(File.binread(path))
rescue JSON::ParserError, SystemCallError
  nil
end

def m4_wait_for_json_marker(path, wait_thr, timeout: 15)
  deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
  loop do
    marker = m4_read_json_marker(path)
    return marker if marker.is_a?(Hash)
    break if wait_thr.join(0)
    break if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline

    sleep 0.05
  end
  m4_read_json_marker(path)
end

def m4_process_alive_with_identity?(identity)
  return false unless identity.is_a?(Hash) && identity["pid"].is_a?(Integer) && identity["start_time_ticks"].is_a?(Integer)

  m4_proc_start_time_ticks(identity.fetch("pid")) == identity.fetch("start_time_ticks")
rescue StandardError
  false
end

def m4_kill_child!(identity, signal: "KILL")
  return false unless m4_process_alive_with_identity?(identity)

  Process.kill(signal, identity.fetch("pid"))
  true
rescue Errno::ESRCH
  false
end

def m4_abort_wait_process!(wait_thr)
  return nil unless wait_thr

  unless wait_thr.join(0)
    begin
      # Each unshare invocation is placed in its own process group so a
      # marker timeout cannot leave the forked node worker waiting forever.
      Process.kill("KILL", -wait_thr.pid)
    rescue Errno::ESRCH
      begin
        Process.kill("KILL", wait_thr.pid)
      rescue Errno::ESRCH
        nil
      end
    end
  end
  wait_thr.value
rescue StandardError
  nil
end

def m4_wait_for_process_exit!(wait_thr, timeout: 15)
  return nil unless wait_thr

  return wait_thr.value if wait_thr.join(timeout)

  m4_abort_wait_process!(wait_thr)
end

def m4_run_native_crash_recovery!(root, errors)
  native_class = M4ProbeSupport.constant("Rubernetes::Volume::NativeMountAdapter")
  filesystem_class = M4ProbeSupport.constant("Rubernetes::Volume::FilesystemAdapter")
  unless native_class.is_a?(Class) && filesystem_class.is_a?(Class)
    errors << "native mount crash evidence is unavailable: production native and filesystem adapters are missing"
    return {"passed" => false, "available" => false, "incomplete_reason" => "native adapters unavailable"}
  end
  unless Process.respond_to?(:clock_gettime) && RbConfig::CONFIG.fetch("host_os").include?("linux") && system("command -v unshare >/dev/null 2>&1")
    errors << "native mount crash evidence is unavailable: Linux unshare is not available"
    return {"passed" => false, "available" => false, "incomplete_reason" => "Linux mount namespace capability unavailable"}
  end

  crash_root = Dir.mktmpdir("rubernetes-m4-node-crash", root)
  marker_path = File.join(crash_root, "crash-child-ready.json")
  command = ["unshare", "--mount", "--fork", RbConfig.ruby, "-I", File.join(M3ProbeSupport::ROOT, "lib"),
             File.expand_path(__FILE__), "--m4-native-crash-child", crash_root]
  stdin = stdout = stderr = wait_thr = nil
  restart_stdin = restart_stdout = restart_stderr = restart_wait = nil
  marker = nil
  child_status = nil
  begin
    stdin, stdout, stderr, wait_thr = Open3.popen3(*command, chdir: M3ProbeSupport::ROOT, pgroup: true)
    stdin.close
    marker = m4_wait_for_json_marker(marker_path, wait_thr)
    unless marker.is_a?(Hash)
      child_status = m4_abort_wait_process!(wait_thr)
      error_text = stderr.read.to_s.strip
      reason = error_text.empty? ? "native child did not publish an effect-boundary marker" : error_text
      errors << "native mount crash evidence is incomplete: #{reason}"
      return {"passed" => false, "available" => false, "child_command" => command,
              "child_exit_status" => child_status&.exitstatus, "child_signal" => child_status&.termsig,
              "child_stderr" => error_text}
    end

    observation = marker["observation"]
    child_identity = observation.is_a?(Hash) ? observation["child"] : nil
    unless m4_process_alive_with_identity?(child_identity)
      errors << "native mount crash evidence is incomplete: child PID/start-time binding is not live before SIGKILL"
      m4_abort_wait_process!(wait_thr)
      return {"passed" => false, "available" => false, "marker" => marker, "child_command" => command}
    end
    killed = m4_kill_child!(child_identity)
    child_status = m4_wait_for_process_exit!(wait_thr)
    raise "native crash child did not exit after SIGKILL" unless child_status
    child_stdout = stdout.read.to_s
    child_stderr = stderr.read.to_s
    child_killed = killed && !m4_process_alive_with_identity?(child_identity)

    filesystem_adapter = filesystem_class.new(root: File.join(crash_root, "mounts"), fsync: true)
    native_adapter = native_class.new
    crash_manager = m4_native_manager(crash_root, filesystem_adapter, native_adapter)
    recovery_report = crash_manager.recover(observed_mounts: [])
    durable_after_recovery = crash_manager.volume("m4-crash-volume").to_h
    restart_marker_path = File.join(crash_root, "restart-child-ready.json")
    restart_release_path = File.join(crash_root, "restart-child-release")
    restart_command = ["unshare", "--mount", "--fork", RbConfig.ruby, "-I", File.join(M3ProbeSupport::ROOT, "lib"),
                       File.expand_path(__FILE__), "--m4-native-restart-child", crash_root]
    restart_stdin, restart_stdout, restart_stderr, restart_wait = Open3.popen3(*restart_command, chdir: M3ProbeSupport::ROOT, pgroup: true)
    restart_stdin.close
    restart_marker = m4_wait_for_json_marker(restart_marker_path, restart_wait)
    restart_status = nil
    restart_stdout_text = ""
    restart_stderr_text = ""
    restart_passed = false
    restart_child_live = false
    if restart_marker.is_a?(Hash)
      restart_child = restart_marker.dig("observation", "child")
      restart_child_live = m4_process_alive_with_identity?(restart_child)
      if restart_child_live
        File.open(restart_release_path, File::WRONLY | File::CREAT | File::EXCL, 0o600) { |file| file.write("continue\n") }
      end
    end
    unless restart_child_live
      errors << "native mount restart evidence is incomplete: restart child PID/start-time binding is not live"
      m4_abort_wait_process!(restart_wait)
    end
    restart_status = m4_wait_for_process_exit!(restart_wait)
    raise "native restart child did not exit" unless restart_status
    restart_stdout_text = restart_stdout.read.to_s
    restart_stderr_text = restart_stderr.read.to_s
    restart_passed = restart_status.success? && restart_marker.is_a?(Hash) && restart_marker["passed"] == true &&
                     restart_marker["measurement_source"] == "native_mount_namespace" &&
                     restart_marker.fetch("operations", []).sort == %w[NodePublishVolume NodeStageVolume]
    errors << "native mount restart did not complete NodeStageVolume and NodePublishVolume" unless restart_passed

    post_restart_manager = m4_native_manager(crash_root, filesystem_adapter, native_adapter)
    cleanup_passed = post_restart_manager.list_volumes.empty? && post_restart_manager.mount_ledger.entries.empty?
    errors << "native mount crash recovery left durable volume ownership behind" unless cleanup_passed
    {
      "passed" => child_killed && recovery_report.unknown.empty? && durable_after_recovery["state"] == "Attached" &&
                  restart_passed && cleanup_passed,
      "available" => true,
      "measurement_source" => "native_mount_namespace",
      "mode" => "native_mount_namespace",
      "operation" => "NodeStageVolume",
      "mount_adapter_class" => native_class.name,
      "backend_adapter_class" => filesystem_class.name,
      "child_command" => command,
      "child_exit_status" => child_status.exitstatus,
      "child_signal" => child_status.termsig,
      "child_killed" => child_killed,
      "child_stdout" => child_stdout,
      "child_stderr" => child_stderr,
      "marker" => marker,
      "observation" => observation,
      "observation_sha256" => marker["observation_sha256"],
      "effect_boundary_sha256" => marker["effect_boundary_sha256"],
      "child_identity_sha256" => marker["child_identity_sha256"],
      "target_identity_sha256" => marker["target_identity_sha256"],
      "mountinfo_sha256" => marker["mountinfo_sha256"],
      "signal" => "SIGKILL",
      "recovery" => {
        "unknown_count" => recovery_report.unknown.length,
        "errors" => M4ProbeSupport.normalize(recovery_report.errors),
        "state_after_recovery" => durable_after_recovery["state"]
      },
      "restart" => {
        "performed" => restart_passed,
        "command" => restart_command,
        "exit_status" => restart_status.exitstatus,
        "signal" => restart_status.termsig,
        "stdout" => restart_stdout_text,
        "stderr" => restart_stderr_text,
        "marker" => restart_marker || {}
      },
      "cleanup_passed" => cleanup_passed
    }
  rescue StandardError => error
    errors << "native mount crash recovery measurement failed: #{error.class}: #{error.message}"
    {"passed" => false, "available" => true, "measurement_source" => "native_mount_namespace",
     "mode" => "native_mount_namespace", "error" => "#{error.class}: #{error.message}",
     "child_command" => command, "marker" => marker || {}}
  ensure
    m4_abort_wait_process!(wait_thr) if wait_thr && !wait_thr.join(0)
    m4_abort_wait_process!(restart_wait) if restart_wait && !restart_wait.join(0)
    begin
      stdin&.close unless stdin&.closed?
    rescue IOError
      nil
    end
    begin
      stdout&.close unless stdout&.closed?
      stderr&.close unless stderr&.closed?
      restart_stdin&.close unless restart_stdin&.closed?
      restart_stdout&.close unless restart_stdout&.closed?
      restart_stderr&.close unless restart_stderr&.closed?
    rescue IOError
      nil
    end
  end
end

M4ProbeSupport.run_report(kind: "m4_mount_attack_corpus", adapter_name: "mount-attack-corpus-probe") do |_input, errors|
  security_class = M4ProbeSupport.constant("Rubernetes::Volume::PathSecurity")
  manager_class = M4ProbeSupport.constant("Rubernetes::Volume::Manager")
  adapter_class = M4ProbeSupport.constant("Rubernetes::Volume::FilesystemAdapter")
  unless [security_class, manager_class, adapter_class].all? { |klass| klass.is_a?(Class) }
    errors << "production volume path-security and attach state modules are unavailable"
    next {"measurement_source" => "missing_production_module", "cases" => []}
  end

  Dir.mktmpdir("rubernetes-m4-mount-attacks") do |temporary|
    root = File.join(temporary, "root")
    FileUtils.mkdir_p(root)
    security = security_class.new(root: root, require_openat2: false)
    outcomes = {}
    begin
      security.validate!("../../etc/passwd")
      outcomes["mount_traversal"] = false
    rescue StandardError
      outcomes["mount_traversal"] = true
    end
    begin
      security.validate_host_path!("/etc/passwd")
      outcomes["host_path_escape"] = false
    rescue StandardError
      outcomes["host_path_escape"] = true
    end

    adapter = adapter_class.new(root: File.join(temporary, "mounts"), tmpfs: true)
    manager = manager_class.new(data_dir: File.join(temporary, "manager"), root: File.join(temporary, "volumes"),
                                adapter: adapter, mount_adapter: adapter)
    volume_id = manager.create_volume({"id" => "m4-race-volume", "backend" => "emptyDir",
                                      "accessModes" => ["ReadWriteOnce"]}, token: "m4-race-create")
    race_results = Queue.new
    threads = %w[m4-node-a m4-node-b].map do |node|
      Thread.new do
        begin
          manager.publish(volume_id, node, token: "m4-race-#{node}")
          race_results << [node, :attached]
        rescue StandardError => error
          race_results << [node, :blocked, error.class.name]
        end
      end
    end
    threads.each(&:join)
    results = 2.times.map { race_results.pop }
    attached = results.count { |entry| entry[1] == :attached }
    blocked = results.count { |entry| entry[1] == :blocked }
    outcomes["attach_race"] = attached == 1 && blocked == 1

    manager.unpublish(volume_id, results.find { |entry| entry[1] == :attached }.fetch(0), token: "m4-race-cleanup") if attached == 1
    manager.delete_volume(volume_id, token: "m4-race-delete")

    crash_recovery = m4_run_native_crash_recovery!(temporary, errors)
    if crash_recovery["observation"].is_a?(Hash)
      crash_recovery["runner_sha256"] = M4ProbeSupport.report_runner_sha256
      crash_recovery["binding"] = {
        "runner_sha256" => crash_recovery["runner_sha256"],
        "child_identity_sha256" => crash_recovery["child_identity_sha256"],
        "observation_sha256" => crash_recovery["observation_sha256"]
      }
      crash_recovery["binding_sha256"] = M4ProbeSupport.digest(crash_recovery["binding"])
    end
    outcomes["node_crash_double_attach"] = crash_recovery["passed"] == true

    cases = %w[mount_traversal host_path_escape attach_race node_crash_double_attach].map do |id|
      passed = outcomes.fetch(id, false)
      errors << "mount attack #{id} was not blocked" unless passed
      source = id == "node_crash_double_attach" ? "native_mount_namespace" : "production_module"
      {"id" => id, "case" => id, "passed" => passed, "blocked" => passed, "attempt_count" => 1,
       "measurement_source" => source}
    end
    kernel_observation = M4ProbeSupport.run_observed_worker(
      worker: File.join(M3ProbeSupport::ROOT, "test/conformance/kubernetes/m4_volume_observation/attack_worker.rb"),
      env_keys: %w[RUBERNETES_M4_MOUNT_OBSERVATION_COMMAND RUBERNETES_M4_MOUNT_SYSCALL_COMMAND],
      label: "mountinfo/syscall/container attack observation runner", scenario: "m4-mount-attack-corpus",
      required_observations: %w[mountinfo syscalls containers], errors: errors
    )
    {
      "measurement_source" => "production_module",
      "adapter_classes" => %w[Rubernetes::Volume::PathSecurity Rubernetes::Volume::Manager Rubernetes::Volume::NativeMountAdapter],
      "cases" => cases,
      "live_escape_count" => outcomes["mount_traversal"] ? 0 : 1,
      "host_path_escape_count" => outcomes["host_path_escape"] ? 0 : 1,
      "attach_race_count" => outcomes["attach_race"] ? 0 : 1,
      "double_attach_count" => outcomes["node_crash_double_attach"] ? 0 : 1,
      "node_crash_recovery" => crash_recovery,
      "difference_count" => 0,
      "kernel_observation" => kernel_observation || {}
    }
  end
end
