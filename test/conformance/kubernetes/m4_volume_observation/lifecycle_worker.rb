#!/usr/bin/env ruby
# frozen_string_literal: true

# Observation-mode worker for the M4 volume runner.  It drives the production
# volume lifecycle (emptyDir Memory tmpfs, loop + device-mapper ext4, and a
# projected volume rotating generations) with the production
# NativeMountAdapter/NativeDeviceAdapter inside a private mount namespace and
# publishes one phase marker per lifecycle state.  Each marker carries only
# identities the adapters read back from the kernel; the observer verifies
# them independently through /proc/<pid>/mountinfo, statfs(2), /sys/block,
# an nsenter reader, a tight-loop projected reader, and strace.
#
# Protocol (runner_contract.json "observation.phase_marker"): the worker
# writes phase-NNN.json and blocks until phase-NNN.release exists.  The probe
# that starts this worker passes its pid/start time to the observation runner
# and writes `done` after the runner returns so the worker can exit.

require "digest"
require "fileutils"
require "json"
require "open3"
require "optparse"

ROOT = File.expand_path("../../../..", __dir__)
$LOAD_PATH.unshift(File.join(ROOT, "lib")) unless $LOAD_PATH.include?(File.join(ROOT, "lib"))
require "rubernetes/volume"
require "rubernetes/platform/linux/openat2"
require "rubernetes/platform/linux/mount"
require_relative "worker_support"

module M4LifecycleWorker
  SYSCALL_NAMES = %w[mount umount2 openat2 open_tree move_mount mount_setattr fsopen fsconfig fsmount].freeze
  # Every mount-family syscall the production adapters issue is expected to
  # succeed; any failing call is left unclaimed and therefore reported.
  SYSCALL_CLAIMS = SYSCALL_NAMES.map { |name| {"name" => name, "return_class" => "success", "count" => "any"} }.freeze
  PROJECTED_FILE = "config.txt"

  module_function

  def projected_body(generation)
    body = "generation=#{generation}\n" + ("m4-projected-payload\n" * 8)
    "gen=#{generation}\n#{body}\nsha256=#{Digest::SHA256.hexdigest(body)}"
  end
end

options = {rotation_seconds: 1.5, done_timeout: 30}
OptionParser.new do |parser|
  parser.on("--control-dir DIR") { |value| options[:control_dir] = File.expand_path(value) }
  parser.on("--root DIR") { |value| options[:root] = File.expand_path(value) }
  parser.on("--rotation-seconds SECONDS") { |value| options[:rotation_seconds] = Float(value) }
  parser.on("--done-timeout SECONDS") { |value| options[:done_timeout] = Float(value) }
end.parse!(ARGV)

control_dir = options.fetch(:control_dir)
root = options.fetch(:root)
FileUtils.mkdir_p(control_dir)
FileUtils.mkdir_p(root)
data_dir = File.join(root, "data")
FileUtils.mkdir_p(data_dir)

identity = M4WorkerSupport.identity
M4WorkerSupport.write_json(File.join(control_dir, "worker.json"), identity)
result = {"role" => "lifecycle", "worker" => identity, "root" => root, "phases" => [], "steps" => []}
phase_number = 0

publish_phase = lambda do |name, expected, final: false, rotation: nil|
  phase_number += 1
  marker = {"phase" => phase_number, "name" => name, "final" => final, "worker" => M4WorkerSupport.identity,
            "expected" => expected.merge("syscalls" => M4LifecycleWorker::SYSCALL_CLAIMS)}
  marker["rotation"] = rotation if rotation
  M4WorkerSupport.write_json(File.join(control_dir, format("phase-%03d.json", phase_number)), marker)
  result["phases"] << {"phase" => phase_number, "name" => name,
                       "mounts_under_root" => M4WorkerSupport.mount_lines_under(root).length}
  M4WorkerSupport.wait_for_file(File.join(control_dir, format("phase-%03d.release", phase_number)))
end

begin
  manager = M4WorkerSupport.build_manager(data_dir)
  pod = {"metadata" => {"uid" => "m4-lifecycle-pod"}}
  node = "m4-node-a"

  # Phase 1: emptyDir (medium Memory) attached, staged, and published.
  empty_id = "m4-lifecycle-emptydir"
  manager.create_volume({"id" => empty_id, "name" => empty_id, "backend" => "emptyDir", "medium" => "Memory",
                         "sizeLimit" => "8Mi", "accessModes" => ["ReadWriteOnce"]}, token: "#{empty_id}-create")
  manager.publish(empty_id, node, token: "#{empty_id}-attach")
  empty_stage = File.join(data_dir, "stage-emptydir")
  empty_target = File.join(data_dir, "target-emptydir")
  manager.stage(empty_id, empty_stage, token: "#{empty_id}-stage", node: node)
  manager.node_publish(empty_id, pod, empty_target, readonly: false, token: "#{empty_id}-publish", node: node)
  File.binwrite(File.join(empty_target, "payload"), "m4-lifecycle-emptydir-payload\n" * 32)
  record = manager.volume(empty_id)
  empty_source_identity = record.spec.dig("backendResult", "mountIdentity")
  empty_source = record.spec.dig("backendResult", "source")
  empty_claims = [
    M4WorkerSupport.mount_claim(empty_source_identity, target: empty_source),
    M4WorkerSupport.mount_claim(record.stages.fetch(empty_stage), target: empty_stage),
    M4WorkerSupport.mount_claim(record.publishes.values.find { |entry| entry["target"] == empty_target }, target: empty_target)
  ]
  result["steps"] << "emptydir_published"
  publish_phase.call("emptydir_published",
                     {"mounts" => empty_claims,
                      "files" => [M4WorkerSupport.file_claim(File.join(empty_target, "payload"))],
                      "statfs" => [{"path" => empty_target, "typeName" => "tmpfs"}],
                      "reader" => [File.join(empty_target, "payload")]})

  # Phase 2: loop + device-mapper (ext4) attached, staged, and published.
  backing = File.join(data_dir, "loopdm.img")
  File.open(backing, File::WRONLY | File::CREAT | File::EXCL, 0o600) { |file| file.truncate(8 * 1024 * 1024) }
  _stdout, stderr, status = Open3.capture3("mkfs.ext4", "-q", "-F", backing)
  raise "mkfs.ext4 failed: #{stderr}" unless status.success?

  loop_id = "m4-lifecycle-loopdm"
  manager.create_volume({"id" => loop_id, "name" => loop_id, "backend" => "loopDM", "path" => backing,
                         "size" => File.size(backing), "fsType" => "ext4", "accessModes" => ["ReadWriteOnce"]},
                        token: "#{loop_id}-create")
  manager.publish(loop_id, node, token: "#{loop_id}-attach")
  loop_stage = File.join(data_dir, "stage-loopdm")
  loop_target = File.join(data_dir, "target-loopdm")
  manager.stage(loop_id, loop_stage, token: "#{loop_id}-stage", node: node)
  manager.node_publish(loop_id, pod, loop_target, readonly: false, token: "#{loop_id}-publish", node: node)
  File.binwrite(File.join(loop_target, "payload"), "m4-lifecycle-loopdm-payload\n" * 32)
  record = manager.volume(loop_id)
  loop_device = record.spec.dig("backendResult", "loop")
  dm_device = record.spec.dig("backendResult", "deviceMapper")
  device_claims = [
    {"kind" => "loop", "path" => loop_device["path"], "deviceId" => loop_device["deviceId"], "backingPath" => loop_device["backingPath"]},
    {"kind" => "device-mapper", "path" => dm_device["path"], "name" => dm_device["name"], "uuid" => dm_device["uuid"],
     "deviceId" => dm_device["deviceId"]}
  ]
  loop_claims = [
    M4WorkerSupport.mount_claim(record.stages.fetch(loop_stage), target: loop_stage),
    M4WorkerSupport.mount_claim(record.publishes.values.find { |entry| entry["target"] == loop_target }, target: loop_target)
  ]
  result["steps"] << "loopdm_published"
  publish_phase.call("loopdm_published",
                     {"mounts" => empty_claims + loop_claims,
                      "devices" => device_claims,
                      "files" => [M4WorkerSupport.file_claim(File.join(empty_target, "payload")),
                                  M4WorkerSupport.file_claim(File.join(loop_target, "payload"))],
                      "statfs" => [{"path" => empty_target, "typeName" => "tmpfs"}, {"path" => loop_target, "typeName" => "ext4"}],
                      "reader" => [File.join(empty_target, "payload"), File.join(loop_target, "payload")]})

  # Phase 3/4: projected generations rotate on the tmpfs while an independent
  # in-namespace reader checks that every observed generation is complete.
  projection_root = File.join(empty_target, "projected")
  writer = Rubernetes::Volume::AtomicWriter.new(projection_root, fsync: false)
  generation = 1
  writer.write({M4LifecycleWorker::PROJECTED_FILE => M4LifecycleWorker.projected_body(generation)})
  projected_path = File.join(projection_root, M4LifecycleWorker::PROJECTED_FILE)
  result["steps"] << "projected_rotation_start"
  publish_phase.call("projected_rotation_start",
                     {"mounts" => empty_claims + loop_claims, "devices" => device_claims,
                      "files" => [M4WorkerSupport.file_claim(projected_path)], "reader" => [projected_path]},
                     rotation: {"start" => {"root" => projection_root, "files" => [M4LifecycleWorker::PROJECTED_FILE]}})
  rotation_deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + options[:rotation_seconds]
  while Process.clock_gettime(Process::CLOCK_MONOTONIC) < rotation_deadline
    generation += 1
    writer.write({M4LifecycleWorker::PROJECTED_FILE => M4LifecycleWorker.projected_body(generation)})
  end
  result["projected_generations_written"] = generation
  result["steps"] << "projected_rotation_stop"
  publish_phase.call("projected_rotation_stop",
                     {"mounts" => empty_claims + loop_claims, "devices" => device_claims,
                      "files" => [M4WorkerSupport.file_claim(projected_path)], "reader" => [projected_path]},
                     rotation: {"stop" => true})

  # Phase 5: everything torn down; nothing may remain mounted or attached.
  manager.node_unpublish(loop_id, pod, loop_target, token: "#{loop_id}-unpublish")
  manager.unstage(loop_id, loop_stage, token: "#{loop_id}-unstage", node: node)
  manager.unpublish(loop_id, node, token: "#{loop_id}-detach")
  manager.delete_volume(loop_id, token: "#{loop_id}-delete")
  manager.node_unpublish(empty_id, pod, empty_target, token: "#{empty_id}-unpublish")
  manager.unstage(empty_id, empty_stage, token: "#{empty_id}-unstage", node: node)
  manager.unpublish(empty_id, node, token: "#{empty_id}-detach")
  manager.delete_volume(empty_id, token: "#{empty_id}-delete")
  result["steps"] << "deleted"
  result["mounts_under_root_at_exit"] = M4WorkerSupport.mount_lines_under(root)
  result["ledger_entries_at_exit"] = manager.mount_ledger.entries
  result["volumes_at_exit"] = manager.list_volumes.map(&:to_h)
  publish_phase.call("unmounted_final",
                     {"absent" => [empty_source, empty_stage, empty_target, loop_stage, loop_target],
                      "absent_devices" => [loop_device["path"], dm_device["path"]]},
                     final: true)
  result["passed"] = true
rescue StandardError => error
  result["passed"] = false
  result["error"] = {"class" => error.class.name, "message" => error.message, "backtrace" => Array(error.backtrace).first(12)}
  causes = []
  cause = error.cause
  while cause && causes.length < 5
    causes << {"class" => cause.class.name, "message" => cause.message}
    cause = cause.cause
  end
  result["error"]["causes"] = causes unless causes.empty?
end

# Stay alive (with the namespace intact) until the probe has collected the
# observation, so the observer's final namespace check sees this process.
M4WorkerSupport.wait_for_file(File.join(control_dir, "done"), timeout: options[:done_timeout]) if result["passed"]
puts JSON.generate(result)
exit(result["passed"] ? 0 : 1)
