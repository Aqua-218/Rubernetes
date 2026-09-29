#!/usr/bin/env ruby
# frozen_string_literal: true

# Observation-mode worker for the M4 mount-attack corpus.  It drives the
# production volume stack (Volume::Manager, PathSecurity with openat2,
# NativeMountAdapter) inside a private mount namespace while an attacker
# rewrites the filesystem underneath it, and publishes one phase marker per
# attack so the external observer can prove from /proc/<pid>/mountinfo, an
# nsenter reader, and strace that no attack produced a mount, that the legit
# mounts were untouched, and which syscalls the production code issued.
#
# Attacks:
#   symlink_target   - the publish target is replaced by a symlink to /etc
#   subpath_escape   - a subPath that climbs out of the staged volume
#   host_path_escape - a hostPath volume pointing outside the security root
#   attach_race      - a second node attaches a ReadWriteOnce volume
#
# Protocol: identical to lifecycle_worker.rb (phase-NNN.json / .release,
# worker.json on start, `done` to exit).

require "digest"
require "fileutils"
require "json"
require "optparse"

ROOT = File.expand_path("../../../..", __dir__)
$LOAD_PATH.unshift(File.join(ROOT, "lib")) unless $LOAD_PATH.include?(File.join(ROOT, "lib"))
require "rubernetes/volume"
require "rubernetes/platform/linux/openat2"
require "rubernetes/platform/linux/mount"
require_relative "worker_support"

module M4AttackWorker
  SYSCALL_NAMES = %w[mount umount2 openat2 open_tree move_mount mount_setattr fsopen fsconfig fsmount].freeze
  SUCCESS_CLAIMS = SYSCALL_NAMES.map { |name| {"name" => name, "return_class" => "success", "count" => "any"} }.freeze
  # Failing openat2(2) calls are the production defence in action: the
  # kernel refuses symlink resolution (ELOOP) and root escapes (EXDEV) under
  # RESOLVE_NO_SYMLINKS / RESOLVE_BENEATH.  Any other failure stays unclaimed.
  ATTACK_CLAIMS = (SUCCESS_CLAIMS + [
    {"name" => "openat2", "return_class" => "-1 ELOOP", "count" => "any"},
    {"name" => "openat2", "return_class" => "-1 EXDEV", "count" => "any"},
    {"name" => "openat2", "return_class" => "-1 ENOENT", "count" => "any"},
    {"name" => "openat2", "return_class" => "-1 ENOTDIR", "count" => "any"}
  ]).freeze
end

options = {done_timeout: 30}
OptionParser.new do |parser|
  parser.on("--control-dir DIR") { |value| options[:control_dir] = File.expand_path(value) }
  parser.on("--root DIR") { |value| options[:root] = File.expand_path(value) }
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
result = {"role" => "attack", "worker" => identity, "root" => root, "phases" => [], "attacks" => {}}
phase_number = 0

publish_phase = lambda do |name, expected, final: false, claims: M4AttackWorker::SUCCESS_CLAIMS|
  phase_number += 1
  marker = {"phase" => phase_number, "name" => name, "final" => final, "worker" => M4WorkerSupport.identity,
            "expected" => expected.merge("syscalls" => claims)}
  M4WorkerSupport.write_json(File.join(control_dir, format("phase-%03d.json", phase_number)), marker)
  result["phases"] << {"phase" => phase_number, "name" => name,
                       "mounts_under_root" => M4WorkerSupport.mount_lines_under(root).length}
  M4WorkerSupport.wait_for_file(File.join(control_dir, format("phase-%03d.release", phase_number)))
end

# An attack passes when the production code refuses it with a security or
# access-mode error; anything else (success, or an unrelated crash) fails.
attempt = lambda do |name, refused_by, &block|
  outcome = begin
    block.call
    {"refused" => false, "outcome" => "accepted"}
  rescue *refused_by => error
    {"refused" => true, "outcome" => "refused", "error_class" => error.class.name, "message" => error.message}
  rescue StandardError => error
    {"refused" => false, "outcome" => "unexpected_error", "error_class" => error.class.name, "message" => error.message}
  end
  result["attacks"][name] = outcome
  outcome
end

begin
  manager = M4WorkerSupport.build_manager(data_dir)
  pod = {"metadata" => {"uid" => "m4-attack-pod"}}
  attacker_pod = {"metadata" => {"uid" => "m4-attacker-pod"}}
  node = "m4-node-a"
  volume_id = "m4-attack-volume"
  manager.create_volume({"id" => volume_id, "name" => volume_id, "backend" => "emptyDir", "medium" => "Memory",
                         "sizeLimit" => "8Mi", "accessModes" => ["ReadWriteOnce"]}, token: "#{volume_id}-create")
  manager.publish(volume_id, node, token: "#{volume_id}-attach")
  stage = File.join(data_dir, "stage")
  target = File.join(data_dir, "target")
  manager.stage(volume_id, stage, token: "#{volume_id}-stage", node: node)
  manager.node_publish(volume_id, pod, target, readonly: false, token: "#{volume_id}-publish", node: node)
  File.binwrite(File.join(target, "payload"), "m4-attack-payload\n" * 16)
  record = manager.volume(volume_id)
  source = record.spec.dig("backendResult", "source")
  legit_claims = [
    M4WorkerSupport.mount_claim(record.spec.dig("backendResult", "mountIdentity"), target: source),
    M4WorkerSupport.mount_claim(record.stages.fetch(stage), target: stage),
    M4WorkerSupport.mount_claim(record.publishes.values.find { |entry| entry["target"] == target }, target: target)
  ]
  payload_claim = M4WorkerSupport.file_claim(File.join(target, "payload"))
  base_expected = lambda do |absent|
    {"mounts" => legit_claims, "absent" => absent, "files" => [payload_claim], "reader" => [File.join(target, "payload")]}
  end
  publish_phase.call("volume_published", base_expected.call([]))

  # Attack 1: the target directory is swapped for a symlink to /etc before
  # NodePublishVolume runs for a second pod.
  attack_dir = File.join(data_dir, "attack")
  FileUtils.mkdir_p(attack_dir)
  symlink_target = File.join(attack_dir, "target-link")
  File.symlink("/etc", symlink_target)
  attempt.call("symlink_target", [Rubernetes::Volume::PathSecurityError, Rubernetes::Volume::SecurityError]) do
    manager.node_publish(volume_id, attacker_pod, symlink_target, readonly: false, token: "#{volume_id}-attack-symlink", node: node)
  end
  publish_phase.call("symlink_target_attack", base_expected.call([symlink_target, "/etc"]), claims: M4AttackWorker::ATTACK_CLAIMS)

  # Attack 2: a subPath that climbs out of the staged volume.
  escape_target = File.join(attack_dir, "subpath-target")
  attempt.call("subpath_escape", [Rubernetes::Volume::PathSecurityError, Rubernetes::Volume::SecurityError, Rubernetes::Volume::ValidationError]) do
    manager.node_publish(volume_id, attacker_pod, escape_target, readonly: false, token: "#{volume_id}-attack-subpath",
                         node: node, sub_path: "../../../../etc")
  end
  publish_phase.call("subpath_escape_attack", base_expected.call([symlink_target, escape_target, "/etc"]), claims: M4AttackWorker::ATTACK_CLAIMS)

  # Attack 3: a hostPath volume pointing outside the configured security root.
  scoped_root = File.join(data_dir, "scoped")
  FileUtils.mkdir_p(scoped_root)
  scoped_openat2 = Rubernetes::Platform::Linux::Openat2.new(root: scoped_root, strict: true)
  scoped_security = Rubernetes::Volume::PathSecurity.new(root: scoped_root, adapter: scoped_openat2, require_openat2: true)
  scoped_manager = M4WorkerSupport.build_manager(File.join(data_dir, "scoped-manager"), path_security: scoped_security,
                                                 root: File.join(scoped_root, "volumes"))
  attempt.call("host_path_escape", [Rubernetes::Volume::PathSecurityError, Rubernetes::Volume::SecurityError, Rubernetes::Volume::ValidationError]) do
    scoped_manager.create_volume({"id" => "m4-attack-hostpath", "name" => "m4-attack-hostpath", "backend" => "hostPath",
                                  "path" => "/etc", "type" => "Directory"}, token: "m4-attack-hostpath-create")
  end
  publish_phase.call("host_path_escape_attack", base_expected.call([symlink_target, escape_target, "/etc"]), claims: M4AttackWorker::ATTACK_CLAIMS)

  # Attack 4: a second node attaches the ReadWriteOnce volume.
  attempt.call("attach_race", [Rubernetes::Volume::MultiAttachError]) do
    manager.publish(volume_id, "m4-node-b", token: "#{volume_id}-attack-attach")
  end
  publish_phase.call("attach_race_attack", base_expected.call([symlink_target, escape_target]))

  # Teardown: the legitimate lifecycle still completes.
  manager.node_unpublish(volume_id, pod, target, token: "#{volume_id}-unpublish")
  manager.unstage(volume_id, stage, token: "#{volume_id}-unstage", node: node)
  manager.unpublish(volume_id, node, token: "#{volume_id}-detach")
  manager.delete_volume(volume_id, token: "#{volume_id}-delete")
  result["mounts_under_root_at_exit"] = M4WorkerSupport.mount_lines_under(root)
  result["ledger_entries_at_exit"] = manager.mount_ledger.entries
  result["volumes_at_exit"] = manager.list_volumes.map(&:to_h)
  publish_phase.call("unmounted_final", {"absent" => [source, stage, target, symlink_target, escape_target]}, final: true)
  refused = result["attacks"].values.all? { |outcome| outcome["refused"] == true }
  result["passed"] = refused && result["mounts_under_root_at_exit"].empty?
  result["error"] = {"class" => "AttackNotRefused", "message" => "attacks not refused: #{result["attacks"].reject { |_, o| o["refused"] }.keys.join(", ")}"} unless refused
rescue StandardError => error
  result["passed"] = false
  result["error"] = {"class" => error.class.name, "message" => error.message, "backtrace" => Array(error.backtrace).first(12)}
end

M4WorkerSupport.wait_for_file(File.join(control_dir, "done"), timeout: options[:done_timeout]) if result["passed"]
puts JSON.generate(result)
exit(result["passed"] ? 0 : 1)
