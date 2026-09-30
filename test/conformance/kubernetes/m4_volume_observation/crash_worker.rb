#!/usr/bin/env ruby
# frozen_string_literal: true

# Node-agent worker for the M4 volume crash runner.  It runs the production
# Volume::Manager with the production NativeMountAdapter/NativeDeviceAdapter
# inside a private mount namespace (the runner starts it under
# `unshare --mount --propagation private`).  Kill points are cooperative
# markers: the worker writes `step-<name>.json` and blocks until the runner
# either releases it or SIGKILLs it.  Nothing here fakes an identity; every
# recorded mount/device identity comes from the adapters' kernel readback.

require "digest"
require "fileutils"
require "json"
require "optparse"

ROOT = File.expand_path("../../../..", __dir__)
$LOAD_PATH.unshift(File.join(ROOT, "lib")) unless $LOAD_PATH.include?(File.join(ROOT, "lib"))
require "rubernetes/volume"
require "rubernetes/platform/linux/openat2"

module M4CrashWorker
  module_function

  def proc_start_time_ticks(pid = Process.pid)
    value = File.binread("/proc/#{pid}/stat", 16 * 1024)
    closing = value.rindex(")")
    Integer(value.byteslice((closing + 2)..).to_s.split.fetch(19))
  end

  def identity
    {"pid" => Process.pid, "start_time_ticks" => proc_start_time_ticks,
     "mount_namespace_inode" => File.stat("/proc/self/ns/mnt").ino, "path" => "/proc/#{Process.pid}/ns/mnt"}
  end

  def write_marker(control_dir, name, payload)
    path = File.join(control_dir, "step-#{name}.json")
    temporary = "#{path}.tmp-#{Process.pid}"
    File.open(temporary, File::WRONLY | File::CREAT | File::EXCL, 0o600) do |file|
      file.write(JSON.generate(payload.merge("step" => name, "worker" => identity,
                                             "mountinfo" => File.binread("/proc/self/mountinfo").lines.map(&:chomp))))
      file.flush
      file.fsync
    end
    File.rename(temporary, path)
    path
  end

  def wait_for_release(control_dir, name)
    release = File.join(control_dir, "step-#{name}.release")
    sleep 0.02 until File.file?(release)
    JSON.parse(File.binread(release))
  end

  # Marker + wait.  When the runner kills the worker here the process never
  # returns from this call; that is the point.
  def checkpoint(control_dir, name, payload = {})
    write_marker(control_dir, name, payload)
    wait_for_release(control_dir, name)
  end

  def mount_lines_under(root)
    File.binread("/proc/self/mountinfo").lines.map(&:chomp).select do |line|
      target = line.split[4].to_s.gsub(/\\([0-7]{3})/) { Regexp.last_match(1).to_i(8).chr }
      target == root || target.start_with?("#{root}/")
    end
  end

  def build_manager(data_dir, control_dir:, kill_point:)
    Rubernetes::Platform::Linux::Mount.new.make_private(target: "/", recursive: true, resource_id: "m4-crash-worker:private")
    openat2 = Rubernetes::Platform::Linux::Openat2.new(root: "/", strict: true)
    path_security = Rubernetes::Volume::PathSecurity.new(root: "/", adapter: openat2, require_openat2: true)
    uuid_resolver = Rubernetes::Volume::FilesystemUuidResolver.new
    mount_adapter = if kill_point == "after_effect_before_commit"
                      BoundaryMountAdapter.new(control_dir: control_dir, filesystem_uuid_resolver: uuid_resolver)
                    else
                      Rubernetes::Volume::NativeMountAdapter.new(filesystem_uuid_resolver: uuid_resolver)
                    end
    device_adapter = Rubernetes::Volume::NativeDeviceAdapter.new
    Rubernetes::Volume::Manager.new(
      data_dir: data_dir, root: File.join(data_dir, "volumes"), adapter: mount_adapter,
      mount_adapter: mount_adapter, device_adapter: device_adapter, path_security: path_security,
      require_real_readback: true, fsync: true
    )
  end

  # The production adapter with one cooperative checkpoint between the
  # kernel effect (mount visible in mountinfo) and the manager's durable
  # commit.  The identity it returns is the unmodified production readback.
  class BoundaryMountAdapter < Rubernetes::Volume::NativeMountAdapter
    def initialize(control_dir:, **)
      super(**)
      @control_dir = control_dir
      @armed = true
    end

    def mount(**kwargs)
      result = super
      if @armed && kwargs[:stage] == true
        @armed = false
        M4CrashWorker.checkpoint(@control_dir, "after_effect_before_commit",
                                 "operation" => "NodeStageVolume", "target" => kwargs.fetch(:target),
                                 "identity" => result.to_h.select do |key, _|
                                   %w[mountId deviceId root target filesystem kernelSource options readonly bind mountApi].include?(key)
                                 end,
                                 "effect_boundary" => {"phase" => "after_effect_before_durable_commit", "syscall" => result["mountApi"] == "open_tree" ? "open_tree/move_mount" : "mount(2)"})
      end
      result
    end
  end
end

options = {role: "node-a", kill_point: "none", backend: "emptyDir", node: "node-a"}
OptionParser.new do |parser|
  parser.on("--role ROLE") { |value| options[:role] = value }
  parser.on("--data-dir DIR") { |value| options[:data_dir] = File.expand_path(value) }
  parser.on("--control-dir DIR") { |value| options[:control_dir] = File.expand_path(value) }
  parser.on("--kill-point POINT") { |value| options[:kill_point] = value }
  parser.on("--backend NAME") { |value| options[:backend] = value }
  parser.on("--node NAME") { |value| options[:node] = value }
  parser.on("--volume-id ID") { |value| options[:volume_id] = value }
  parser.on("--backing-file PATH") { |value| options[:backing_file] = File.expand_path(value) }
end.parse!(ARGV)

data_dir = options.fetch(:data_dir)
control_dir = options.fetch(:control_dir)
FileUtils.mkdir_p(data_dir)
FileUtils.mkdir_p(control_dir)
volume_id = options[:volume_id] || "m4-crash-#{options[:backend].downcase}"
stage_path = File.join(data_dir, "stage")
target_path = File.join(data_dir, "target")
pod = {"metadata" => {"uid" => "m4-crash-pod"}}
result = {"role" => options[:role], "kill_point" => options[:kill_point], "backend" => options[:backend],
          "worker" => M4CrashWorker.identity, "steps" => []}

begin
  manager = M4CrashWorker.build_manager(data_dir, control_dir: control_dir, kill_point: options[:kill_point])
  case options[:role]
  when "node-a"
    # Fresh lifecycle up to the requested kill point.
    spec = case options[:backend]
           when "emptyDir"
             {"id" => volume_id, "name" => volume_id, "backend" => "emptyDir", "medium" => "Memory",
              "sizeLimit" => "4Mi", "accessModes" => ["ReadWriteOnce"]}
           when "loopDM"
             {"id" => volume_id, "name" => volume_id, "backend" => "loopDM", "path" => options.fetch(:backing_file),
              "size" => File.size(options.fetch(:backing_file)), "fsType" => "ext4", "accessModes" => ["ReadWriteOnce"]}
           else
             raise ArgumentError, "unsupported crash backend #{options[:backend]}"
           end
    manager.create_volume(spec, token: "#{volume_id}-create")
    manager.publish(volume_id, options[:node], token: "#{volume_id}-attach")
    result["steps"] << "attached"
    record = manager.volume(volume_id)
    if options[:kill_point] == "before_effect"
      M4CrashWorker.checkpoint(control_dir, "before_effect",
                               "operation" => "NodeStageVolume", "state" => record.state,
                               "backend_result" => record.spec["backendResult"])
    end
    manager.stage(volume_id, stage_path, token: "#{volume_id}-stage", node: options[:node])
    result["steps"] << "staged"
    manager.node_publish(volume_id, pod, target_path, readonly: false, token: "#{volume_id}-publish", node: options[:node])
    result["steps"] << "published"
    File.write(File.join(target_path, "payload"), "m4-crash-payload")
    record = manager.volume(volume_id)
    if options[:kill_point] == "after_commit"
      M4CrashWorker.checkpoint(control_dir, "after_commit",
                               "operation" => "NodePublishVolume", "state" => record.state,
                               "stage" => record.stages.fetch(stage_path), "publish" => record.publishes.values.first,
                               "mounts_under_root" => M4CrashWorker.mount_lines_under(data_dir))
    end
    manager.node_unpublish(volume_id, pod, target_path, token: "#{volume_id}-unpublish")
    manager.unstage(volume_id, stage_path, token: "#{volume_id}-unstage", node: options[:node])
    manager.unpublish(volume_id, options[:node], token: "#{volume_id}-detach")
    manager.delete_volume(volume_id, token: "#{volume_id}-delete")
    result["steps"] << "deleted"
    result["mounts_under_root_at_exit"] = M4CrashWorker.mount_lines_under(data_dir)
  when "restart"
    # The agent restarts on the same durable state after SIGKILL.
    before = manager.volume(volume_id).to_h
    recovery = manager.recover
    after = manager.volume(volume_id)
    result["recovery"] = {
      "state_before" => before["state"], "state_after_recovery" => after.state,
      "unknown_count" => recovery.unknown.length, "unknown" => recovery.unknown,
      "owned" => recovery.owned, "missing" => recovery.missing, "orphans_under_root" => recovery.orphans.select do |entry|
                                                                  entry["target"].to_s.start_with?(data_dir)
                                                                end,
      "identity_mismatches" => recovery.identity_mismatches, "actions" => recovery.actions, "errors" => recovery.errors,
      "operations" => manager.operations.entries.map(&:to_h)
    }
    M4CrashWorker.checkpoint(control_dir, "recovered", "recovery" => result["recovery"],
                                                       "mounts_under_root" => M4CrashWorker.mount_lines_under(data_dir))
    # Finish the lifecycle from whatever durable state recovery left.
    record = manager.volume(volume_id)
    manager.stage(volume_id, stage_path, token: "#{volume_id}-restart-stage", node: options[:node]) unless record.stages.key?(stage_path)
    record = manager.volume(volume_id)
    unless record.publishes.values.any? { |entry| entry["target"] == target_path }
      manager.node_publish(volume_id, pod, target_path, readonly: false, token: "#{volume_id}-restart-publish", node: options[:node])
    end
    record = manager.volume(volume_id)
    result["restart_identities"] = {"stage" => record.stages.fetch(stage_path), "publish" => record.publishes.values.find do |entry|
      entry["target"] == target_path
    end}
    M4CrashWorker.checkpoint(control_dir, "restart_published", "identities" => result["restart_identities"],
                                                               "mounts_under_root" => M4CrashWorker.mount_lines_under(data_dir))
    manager.node_unpublish(volume_id, pod, target_path, token: "#{volume_id}-restart-unpublish")
    manager.unstage(volume_id, stage_path, token: "#{volume_id}-restart-unstage", node: options[:node])
    manager.unpublish(volume_id, options[:node], token: "#{volume_id}-restart-detach")
    manager.delete_volume(volume_id, token: "#{volume_id}-restart-delete")
    result["steps"] << "deleted"
    result["mounts_under_root_at_exit"] = M4CrashWorker.mount_lines_under(data_dir)
    result["ledger_entries_at_exit"] = manager.mount_ledger.entries
    result["volumes_at_exit"] = manager.list_volumes.map(&:to_h)
  when "second-node"
    # Another node tries to take the volume while node-a's attachment is
    # still durable.  ReadWriteOnce fencing must reject it without any effect.
    outcome = begin
      manager.publish(volume_id, options[:node], token: "#{volume_id}-second-node-attach")
      {"attached" => true}
    rescue Rubernetes::Volume::MultiAttachError => error
      {"attached" => false, "error_class" => error.class.name, "message" => error.message}
    rescue Rubernetes::Volume::StateUnknownError => error
      {"attached" => false, "error_class" => error.class.name, "message" => error.message}
    end
    result["second_node"] = outcome.merge("state" => manager.volume(volume_id).state,
                                          "attachments" => manager.volume(volume_id).attachments.keys)
  else
    raise ArgumentError, "unsupported role #{options[:role]}"
  end
  result["passed"] = true
rescue StandardError => error
  result["passed"] = false
  result["error"] = {"class" => error.class.name, "message" => error.message, "backtrace" => Array(error.backtrace).first(12)}
  causes = []
  cause = error.cause
  while cause && causes.length < 5
    causes << {"class" => cause.class.name, "message" => cause.message, "backtrace" => Array(cause.backtrace).first(6)}
    cause = cause.cause
  end
  result["error"]["causes"] = causes unless causes.empty?
end
puts JSON.generate(result)
exit(result["passed"] ? 0 : 1)
