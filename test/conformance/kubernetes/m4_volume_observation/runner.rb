#!/usr/bin/env ruby
# frozen_string_literal: true

# External M4 volume observation and crash runner.
#
# `--mode observation` (RUBERNETES_M4_VOLUME_OBSERVATION_COMMAND): the probe
# has already started its lifecycle worker inside a private mount namespace
# and passes the worker identity and a control directory on stdin.  This
# process attaches strace to the worker, then drives the worker phase by
# phase: for every phase it reads /proc/<pid>/mountinfo, statfs(2) through
# /proc/<pid>/root, file digests, loop/dm sysfs identities, runs an
# independent reader with nsenter inside the worker namespace, and compares
# each observation against the worker's claim by content digest.
#
# `--mode crash` (RUBERNETES_M4_VOLUME_CRASH_COMMAND /
# RUBERNETES_M4_SNAPSHOT_RECOVERY_COMMAND): self-contained.  It starts
# crash_worker.rb (production Volume::Manager + NativeMountAdapter +
# NativeDeviceAdapter) under unshare, SIGKILLs it at each cooperative effect
# point, verifies from the host that no mount or device leaked, that a second
# node cannot attach the fenced volume, restarts the agent on the same durable
# state and verifies recovery and cleanup.  It also drives snapshot create /
# restore with independent digests and proves a tampered catalog and an
# interrupted restore both fail closed.

require "digest"
require "fileutils"
require "json"
require "open3"
require "optparse"
require "rbconfig"
require "tmpdir"

require_relative "observer_support"
require File.join(__dir__, "..", "..", "..", "..", "lib", "rubernetes", "volume", "record_files")

module M4VolumeObservationRunner
  RUNNER_PATH = File.expand_path(__FILE__).freeze
  WORKER_PATH = File.expand_path("crash_worker.rb", __dir__).freeze
  IMPLEMENTATION = "test/conformance/kubernetes/m4_volume_observation/runner.rb"
  KILL_POINTS = %w[before_effect after_effect_before_commit after_commit].freeze
  CRASH_BACKENDS = %w[emptyDir loopDM].freeze

  module_function

  def parse_request
    raw = $stdin.read.to_s
    return {} if raw.strip.empty?

    request = JSON.parse(raw, max_nesting: 256)
    raise ArgumentError, "runner request must be an object" unless request.is_a?(Hash)

    request
  end

  def observation(request)
    errors = []
    worker = request["worker"]
    control_dir = request["control_dir"].to_s
    root = request["root"].to_s
    unless worker.is_a?(Hash) && worker["pid"].is_a?(Integer) && worker["start_time_ticks"].is_a?(Integer)
      raise ArgumentError, "observation request must identify the worker pid and start time"
    end
    raise ArgumentError, "observation request must name an existing control directory" unless File.directory?(control_dir)
    raise ArgumentError, "observation request must name the mount root" unless root.start_with?("/")

    live_worker = M4ObserverSupport.process_identity(worker["pid"])
    raise ArgumentError, "worker #{worker["pid"]} start time does not match the request" unless live_worker["start_time_ticks"] == worker["start_time_ticks"]

    errors << "worker shares the runner's mount namespace; no private namespace evidence" if
      live_worker["mount_namespace_inode"] == File.stat("/proc/self/ns/mnt").ino

    observer = M4ObserverSupport::PhaseObserver.new(control_dir: control_dir, worker: live_worker, root: root,
                                                    marker_timeout: Integer(request.fetch("marker_timeout", 180)))
    observed = observer.run
    errors.concat(observed.fetch("errors"))
    rotation = observed["projected_rotation"]
    if rotation.is_a?(Hash) && !rotation.key?("error")
      errors << "projected rotation reader observed a partial generation" unless rotation["partial_generation_observed_count"] == 0
      errors << "projected rotation reader observed a missing generation file" unless rotation["missing_count"] == 0
      errors << "projected rotation reader did not run inside the worker mount namespace" unless
        rotation["mount_namespace_inode"] == live_worker["mount_namespace_inode"]
      errors << "projected rotation reader performed too few reads to be meaningful" unless rotation["reads"].to_i >= 100
      errors << "projected rotation reader saw fewer than two generations" unless rotation["generations_observed"].to_i >= 2
    elsif request["require_rotation"] == true
      errors << "projected rotation reader produced no result"
    end
    containers = observed.fetch("container_observation")
    errors << "no independent in-namespace reader observation was produced" if containers.empty?
    errors << "no mountinfo comparison was produced" if observed.fetch("mountinfo").empty?
    errors << "no syscall observation was produced" if observed.fetch("syscalls").empty?
    observed.merge(
      "scenario" => request["scenario"], "worker" => live_worker, "root" => root,
      "kernel_backed" => true, "measurement_source" => "external_kernel_observation",
      "mountinfo_source" => "/proc/#{live_worker["pid"]}/mountinfo", "statfs_source" => "/proc/#{live_worker["pid"]}/root",
      "errors" => errors
    )
  end

  # ---------------------------------------------------------------- crash --

  class CrashScenario
    attr_reader :errors, :records

    def initialize(work_dir)
      @work_dir = work_dir
      @errors = []
      @records = []
      @host_ns = File.stat("/proc/self/ns/mnt").ino
    end

    def run
      CRASH_BACKENDS.each do |backend|
        KILL_POINTS.each do |point|
          @records << kill_and_restart(backend, point)
        end
      end
      @records << snapshot_scenarios
      {"errors" => @errors, "kill_points" => @records.first(CRASH_BACKENDS.length * KILL_POINTS.length),
       "snapshot" => @records.last}
    end

    private

    def spawn_worker(role:, data_dir:, control_dir:, kill_point:, backend:, node:, backing_file: nil, volume_id: nil)
      command = ["unshare", "--mount", "--propagation", "private", "--fork", "--", RbConfig.ruby, WORKER_PATH,
                 "--role", role, "--data-dir", data_dir, "--control-dir", control_dir, "--kill-point", kill_point,
                 "--backend", backend, "--node", node]
      command += ["--backing-file", backing_file] if backing_file
      command += ["--volume-id", volume_id] if volume_id
      stdout_read, stdout_write = IO.pipe
      stderr_read, stderr_write = IO.pipe
      pid = Process.spawn(*command, in: File::NULL, out: stdout_write, err: stderr_write, pgroup: true, chdir: M4ObserverSupport::ROOT)
      stdout_write.close
      stderr_write.close
      {"pid" => pid, "command" => command, "stdout" => stdout_read, "stderr" => stderr_read, "control_dir" => control_dir}
    end

    # unshare --fork keeps the worker as its child; the marker carries the
    # worker's own pid/start time, which is what SIGKILL must target.
    def wait_step(process, name, timeout: 120)
      path = File.join(process.fetch("control_dir"), "step-#{name}.json")
      M4ObserverSupport.wait_for(timeout: timeout) do
        if File.file?(path)
          begin
            JSON.parse(File.binread(path))
          rescue JSON::ParserError
            nil
          end
        elsif (reaped = Process.waitpid2(process.fetch("pid"), Process::WNOHANG))
          # The worker exited before writing the marker; keep its status so
          # finish() does not wait for an already reaped child.
          process["status"] = reaped.last
          break nil
        end
      end
    end

    def release_step(process, name)
      File.write(File.join(process.fetch("control_dir"), "step-#{name}.release"),
                 JSON.generate("released_at" => M4ObserverSupport.iso8601_now))
    end

    def finish(process, timeout: 120)
      deadline = M4ObserverSupport.monotonic + timeout
      status = process["status"]
      loop do
        break if status

        _pid, status = begin
          Process.waitpid2(process.fetch("pid"), Process::WNOHANG)
        rescue Errno::ECHILD
          [process.fetch("pid"), process["status"]]
        end
        break if status

        if M4ObserverSupport.monotonic > deadline
          begin
            Process.kill("KILL", -process.fetch("pid"))
          rescue Errno::ESRCH
            nil
          end
          _pid, status = Process.waitpid2(process.fetch("pid"))
          break
        end
        sleep 0.05
      end
      stdout = process.fetch("stdout").read
      stderr = process.fetch("stderr").read
      process.fetch("stdout").close
      process.fetch("stderr").close
      document = begin
        JSON.parse(stdout.lines.last.to_s)
      rescue JSON::ParserError
        nil
      end
      {"exit_status" => status.exitstatus, "signal" => status.termsig, "stdout" => document, "stderr" => stderr}
    end

    def kill_worker(process, worker_identity)
      unless M4ObserverSupport.process_alive?(worker_identity)
        @errors << "worker #{worker_identity["pid"]} was not alive at the kill point"
        return false
      end
      Process.kill("KILL", worker_identity.fetch("pid"))
      gone = M4ObserverSupport.wait_for(timeout: 30) { !M4ObserverSupport.process_alive?(worker_identity) }
      finish(process)
      gone == true
    end

    def host_mounts_under(root)
      M4ObserverSupport.mounts_under(Process.pid, root)
    end

    # Devices are matched by the identities the production adapter derives
    # from this scenario's inputs: the loop by its backing file, the dm by the
    # name NativeDeviceAdapter derives from the volume id.
    def devices_for(backing_file, volume_id: nil)
      loops = M4ObserverSupport.loop_devices.select { |device| device["backingPath"] == backing_file }
      dm_name = volume_id && "rubernetes-#{Digest::SHA256.hexdigest(volume_id.to_s)[0, 32]}"
      dms = M4ObserverSupport.dm_devices.select do |device|
        dm_name ? device["name"] == dm_name : device["name"].start_with?("rubernetes-")
      end
      {"loop" => loops, "dm" => dms}
    end

    def prepare_backing_file(path, size: 8 * 1024 * 1024)
      File.open(path, File::WRONLY | File::CREAT | File::EXCL, 0o600) { |file| file.truncate(size) }
      _stdout, stderr, status = Open3.capture3("mkfs.ext4", "-q", "-F", path)
      raise "mkfs.ext4 failed: #{stderr}" unless status.success?

      path
    end

    # The durable volume store is a map keyed by volume id (older layouts
    # wrapped it in {"volumes" => ...} or used an array).
    # The node keeps one file per record (Volume::RecordFiles); a store an
    # older agent left as a single file is read the same way.
    def durable_volume_entries(path)
      Rubernetes::Volume::RecordFiles.read(path)
    end

    def kill_and_restart(backend, point)
      label = "#{backend}:#{point}"
      scenario_dir = File.join(@work_dir, "crash-#{backend}-#{point}")
      data_dir = File.join(scenario_dir, "data")
      control_dir = File.join(scenario_dir, "control")
      FileUtils.mkdir_p(control_dir)
      backing_file = backend == "loopDM" ? prepare_backing_file(File.join(scenario_dir, "backing.img")) : nil
      record = {"backend" => backend, "kill_point" => point, "data_dir" => data_dir}
      # Every scenario owns a distinct volume id so a leftover loop/dm device
      # from one kill point can never be mistaken for (or block) another.
      volume_id = "m4-crash-#{backend.downcase}-#{point.tr("_", "-")}"
      record["volume_id"] = volume_id
      before_host = host_mounts_under(scenario_dir)
      backing_file ? devices_for(backing_file, volume_id: volume_id) : nil

      process = spawn_worker(role: "node-a", data_dir: data_dir, control_dir: control_dir, kill_point: point,
                             backend: backend, node: "node-a", backing_file: backing_file, volume_id: volume_id)
      marker = wait_step(process, point)
      unless marker.is_a?(Hash)
        result = finish(process)
        @errors << "#{label}: worker did not reach the kill point (#{result["stderr"].to_s.strip.lines.last})"
        return record.merge("passed" => false, "worker_result" => result)
      end
      worker_identity = marker.fetch("worker")
      record["worker"] = worker_identity
      record["marker"] = marker.reject { |key, _| key == "mountinfo" }
      record["marker_mountinfo_sha256"] = Digest::SHA256.hexdigest(Array(marker["mountinfo"]).join("\n"))
      # Independent view of the worker namespace at the kill point.
      namespace_mounts = M4ObserverSupport.mounts_under(worker_identity["pid"], data_dir)
      record["mounts_in_worker_namespace_at_kill"] = namespace_mounts.map { |entry| M4ObserverSupport.stable_identity(entry) }
      record["worker_namespace_is_private"] = worker_identity["mount_namespace_inode"] != @host_ns
      @errors << "#{label}: worker did not run in a private mount namespace" unless record["worker_namespace_is_private"]
      @errors << "#{label}: no kernel mount was visible in the worker namespace at the kill point" if (point != "before_effect") && namespace_mounts.empty?
      if marker["identity"].is_a?(Hash)
        claimed = marker["identity"]
        observed = namespace_mounts.find { |entry| entry["target"] == claimed["target"] }
        comparison = M4ObserverSupport.comparison("effect-boundary:#{label}",
                                                  claimed.slice("target", "mountId", "deviceId", "root", "filesystem", "kernelSource"),
                                                  observed ? M4ObserverSupport.stable_identity(observed).slice("target", "mountId",
                                                                                                               "deviceId", "root", "filesystem",
                                                                                                               "kernelSource") : {
                                                                                                                 "target" => claimed["target"],
                                                                                                                 "mounted" => false
                                                                                                               })
        record["effect_boundary_comparison"] = comparison
        @errors << "#{label}: production readback at the effect boundary does not match the kernel" unless comparison["passed"]
      end
      record["devices_at_kill"] = backing_file ? devices_for(backing_file, volume_id: volume_id) : nil

      record["killed"] = kill_worker(process, worker_identity)
      @errors << "#{label}: SIGKILL did not terminate the worker" unless record["killed"]
      after_host = host_mounts_under(scenario_dir)
      record["host_mounts_under_scenario_after_kill"] = after_host.map { |entry| entry["line"] }
      @errors << "#{label}: orphan mounts leaked into the host namespace" unless after_host.length == before_host.length
      if backing_file
        record["devices_after_kill"] = devices_for(backing_file, volume_id: volume_id)
        # Loop/dm devices are not namespaced; the crash leaves them attached
        # and the restart below must reclaim them from the durable record.
        record["orphan_devices_after_kill"] = record["devices_after_kill"]["loop"].length + record["devices_after_kill"]["dm"].length
      end

      durable_entries = durable_volume_entries(File.join(data_dir, "volumes.json"))
      record["durable_state_after_kill"] = durable_entries.map do |entry|
        entry.is_a?(Hash) ? entry.slice("id", "state", "generation", "attachments") : entry
      end

      # A second node races for the volume while node-a's attachment is durable.
      second = spawn_worker(role: "second-node", data_dir: data_dir, control_dir: File.join(scenario_dir, "second-control"),
                            kill_point: "none", backend: backend, node: "node-b", backing_file: backing_file, volume_id: volume_id)
      second_result = finish(second)
      second_node = second_result["stdout"].is_a?(Hash) ? second_result["stdout"]["second_node"] : nil
      record["second_node"] = second_node
      unless second_node.is_a?(Hash) && second_node["attached"] == false && second_node["error_class"] == "Rubernetes::Volume::MultiAttachError"
        @errors << "#{label}: a second node was able to attach (or not fenced by MultiAttachError) after the crash: " \
                   "#{second_result["stderr"].to_s.strip.lines.last}"
      end

      restart = spawn_worker(role: "restart", data_dir: data_dir, control_dir: File.join(scenario_dir, "restart-control"),
                             kill_point: "none", backend: backend, node: "node-a", backing_file: backing_file, volume_id: volume_id)
      recovered = wait_step(restart, "recovered")
      if recovered.is_a?(Hash)
        record["recovery"] = recovered["recovery"]
        record["restart_worker"] = recovered["worker"]
        recovery = recovered["recovery"] || {}
        @errors << "#{label}: recovery left unknown operations" unless recovery["unknown_count"] == 0
        @errors << "#{label}: restart worker did not get a fresh private mount namespace" if
          recovered.dig("worker", "mount_namespace_inode") == @host_ns
        release_step(restart, "recovered")
        published = wait_step(restart, "restart_published")
        if published.is_a?(Hash)
          restart_mounts = M4ObserverSupport.mounts_under(recovered.dig("worker", "pid"), data_dir)
          identities = published["identities"] || {}
          %w[stage publish].each do |key|
            claimed = identities[key]
            next unless claimed.is_a?(Hash)

            observed = restart_mounts.find { |entry| entry["target"] == claimed["target"] }
            comparison = M4ObserverSupport.comparison("restart:#{label}:#{key}",
                                                      {"target" => claimed["target"], "mountId" => claimed["mountId"],
                                                       "deviceId" => claimed["deviceId"], "root" => claimed["root"], "filesystem" => claimed["filesystem"],
                                                       "kernelSource" => claimed["kernelSource"]},
                                                      observed ? M4ObserverSupport.stable_identity(observed).slice("target", "mountId",
                                                                                                                   "deviceId", "root", "filesystem",
                                                                                                                   "kernelSource") : {
                                                                                                                     "target" => claimed["target"],
                                                                                                                     "mounted" => false
                                                                                                                   })
            record["restart_#{key}_comparison"] = comparison
            @errors << "#{label}: restarted #{key} identity does not match the kernel" unless comparison["passed"]
          end
          release_step(restart, "restart_published")
        else
          @errors << "#{label}: restart worker did not re-stage/publish"
        end
      else
        @errors << "#{label}: restart worker did not report recovery"
      end
      restart_result = finish(restart)
      record["restart_result"] = restart_result.merge("stdout" => restart_result["stdout"]&.reject { |key, _| key == "worker" })
      @errors << "#{label}: restart lifecycle failed: #{restart_result["stderr"].to_s.strip.lines.last}" unless restart_result["exit_status"] == 0
      final_host = host_mounts_under(scenario_dir)
      record["host_mounts_under_scenario_after_restart"] = final_host.map { |entry| entry["line"] }
      @errors << "#{label}: mounts remain in the host namespace after restart cleanup" unless final_host.length == before_host.length
      if backing_file
        record["devices_after_restart"] = devices_for(backing_file, volume_id: volume_id)
        leaked = record["devices_after_restart"]["loop"].length + record["devices_after_restart"]["dm"].length
        @errors << "#{label}: loop/dm devices were not reclaimed after restart" unless leaked.zero?
        record["devices_reclaimed"] = leaked.zero? && record["orphan_devices_after_kill"].to_i.positive?
      end
      durable_after = durable_volume_entries(File.join(data_dir, "volumes.json"))
      ledger_after = durable_volume_entries(File.join(data_dir, "mounts.json"))
      record["durable_volumes_after_restart"] = durable_after.length
      record["ledger_entries_after_restart"] = ledger_after.length
      @errors << "#{label}: durable volume or ledger entries remain after cleanup" unless durable_after.empty? && ledger_after.empty?
      record["passed"] = @errors.none? { |error| error.start_with?("#{label}:") }
      record
    end

    # Snapshot create/restore with independent digests, then a tampered
    # catalog and an interrupted restore; both must fail closed.
    def snapshot_scenarios
      dir = File.join(@work_dir, "snapshot")
      data_dir = File.join(dir, "data")
      FileUtils.mkdir_p(data_dir)
      $LOAD_PATH.unshift(File.join(M4ObserverSupport::ROOT, "lib")) unless $LOAD_PATH.include?(File.join(M4ObserverSupport::ROOT, "lib"))
      require "rubernetes/volume"
      require "rubernetes/platform/linux/openat2"
      openat2 = Rubernetes::Platform::Linux::Openat2.new(root: "/", strict: true)
      security = Rubernetes::Volume::PathSecurity.new(root: "/", adapter: openat2, require_openat2: true)
      adapter = Rubernetes::Volume::NativeMountAdapter.new
      manager = Rubernetes::Volume::Manager.new(data_dir: data_dir, root: File.join(data_dir, "volumes"), adapter: adapter,
                                                mount_adapter: adapter, path_security: security, require_real_readback: true, fsync: true)
      record = {"scenario" => "snapshot-restore-crash-recovery", "comparisons" => []}
      files = {"payload.bin" => Random.new(42).bytes(65_536), "nested/config.txt" => "m4-snapshot-config\n" * 64}
      source_id = manager.create_volume({"id" => "m4-snap-source", "name" => "m4-snap-source", "backend" => "emptyDir"},
                                        token: "snap-create")
      source_root = File.join(data_dir, "volumes", source_id)
      files.each do |relative, bytes|
        path = File.join(source_root, relative)
        FileUtils.mkdir_p(File.dirname(path))
        File.binwrite(path, bytes)
      end
      expected_digests = files.to_h { |relative, bytes| [relative, Digest::SHA256.hexdigest(bytes)] }
      snapshot_id = manager.create_snapshot(source_id, token: "snap-take")
      snapshot = manager.snapshot_manager.fetch(snapshot_id)
      catalog = JSON.parse(File.binread(File.join(data_dir, "snapshots.json")))
      catalog_digests = catalog.dig(snapshot_id, "metadata", "contentSha256")
      record["comparisons"] << M4ObserverSupport.comparison("snapshot_create",
                                                            {"operation" => "CreateSnapshot", "source_volume_id" => source_id, "ready_to_use" => true,
                                                             "content_sha256" => expected_digests},
                                                            {"operation" => "CreateSnapshot", "source_volume_id" => snapshot.source_id,
                                                             "ready_to_use" => snapshot.ready_to_use, "content_sha256" => catalog_digests},
                                                            "operation" => "CreateSnapshot", "snapshot_id" => snapshot_id)
      restored_id = manager.restore(snapshot_id, spec: {"id" => "m4-snap-restored", "name" => "m4-snap-restored", "backend" => "emptyDir"},
                                                 token: "snap-restore")
      restored_root = File.join(data_dir, "volumes", restored_id)
      restored_digests = files.keys.to_h { |relative| [relative, Digest::SHA256.file(File.join(restored_root, relative)).hexdigest] }
      record["comparisons"] << M4ObserverSupport.comparison("snapshot_restore",
                                                            {"operation" => "RestoreSnapshot", "source_snapshot_id" => snapshot_id,
                                                             "content_sha256" => expected_digests, "state" => "Provisioned"},
                                                            {"operation" => "RestoreSnapshot",
                                                             "source_snapshot_id" => manager.volume(restored_id).spec.dig("backendResult",
                                                                                                                          "restoredFrom"),
                                                             "content_sha256" => restored_digests,
                                                             "state" => manager.volume(restored_id).state},
                                                            "operation" => "RestoreSnapshot", "restored_volume_id" => restored_id)
      manager.delete_volume(restored_id, token: "snap-delete-restored")

      # Tamper with the catalog at rest: flip one byte of one file payload.
      pristine_catalog = File.binread(File.join(data_dir, "snapshots.json"))
      tampered = JSON.parse(pristine_catalog)
      content = tampered.fetch(snapshot_id).fetch("content")
      key = "nested/config.txt"
      content[key] = content[key].sub("m4-snapshot-config", "m4-snapshot-CORRUPT")
      File.binwrite(File.join(data_dir, "snapshots.json"), JSON.generate(tampered))
      tampered_manager = Rubernetes::Volume::Manager.new(data_dir: data_dir, root: File.join(data_dir, "volumes"), adapter: adapter,
                                                         mount_adapter: adapter, path_security: security, require_real_readback: true, fsync: true)
      tamper_outcome = begin
        tampered_manager.restore(snapshot_id, spec: {"id" => "m4-snap-tampered", "name" => "m4-snap-tampered", "backend" => "emptyDir"},
                                              token: "snap-restore-tampered")
        {"restored" => true}
      rescue Rubernetes::Volume::SnapshotIntegrityError => error
        {"restored" => false, "error_class" => error.class.name, "message" => error.message}
      end
      tampered_volume_exists = tampered_manager.list_volumes.any? { |volume| volume.id == "m4-snap-tampered" }
      record["comparisons"] << M4ObserverSupport.comparison("crash_recovery",
                                                            {"operation" => "CrashRecovery", "tampered_restore_refused" => true, "tampered_volume_registered" => false,
                                                             "interrupted_restore_state" => "Unknown", "interrupted_volume_usable" => false,
                                                             "interrupted_worker_killed" => true},
                                                            {"operation" => "CrashRecovery", "tampered_restore_refused" => tamper_outcome["restored"] == false && tamper_outcome["error_class"] == "Rubernetes::Volume::SnapshotIntegrityError",
                                                             "tampered_volume_registered" => tampered_volume_exists}.merge(interrupted_restore(data_dir, snapshot_id, pristine_catalog)),
                                                            "operation" => "CrashRecovery", "tamper" => tamper_outcome)
      manager.delete_volume(source_id, token: "snap-delete-source")
      record["passed"] = record["comparisons"].all? { |entry| entry["passed"] }
      unless record["passed"]
        @errors << "snapshot scenarios failed: #{record["comparisons"].reject do |entry|
          entry["passed"]
        end.map { |entry| entry["id"] }.join(", ")}"
      end
      record
    rescue StandardError => error
      @errors << "snapshot scenarios raised #{error.class}: #{error.message}"
      {"scenario" => "snapshot-restore-crash-recovery", "comparisons" => [], "passed" => false,
       "error" => {"class" => error.class.name, "message" => error.message}}
    end

    # Simulate a crash in the middle of a restore: the durable record is
    # written before content, so a killed agent must leave it fenced.
    def interrupted_restore(data_dir, snapshot_id, pristine_catalog)
      # Undo the tamper so this restore is legitimate up to the interruption.
      File.binwrite(File.join(data_dir, "snapshots.json"), pristine_catalog)
      script = <<~RUBY
        $LOAD_PATH.unshift(#{File.join(M4ObserverSupport::ROOT, "lib").inspect})
        require "rubernetes/volume"
        require "rubernetes/platform/linux/openat2"
        openat2 = Rubernetes::Platform::Linux::Openat2.new(root: "/", strict: true)
        security = Rubernetes::Volume::PathSecurity.new(root: "/", adapter: openat2, require_openat2: true)
        adapter = Rubernetes::Volume::NativeMountAdapter.new
        manager = Rubernetes::Volume::Manager.new(data_dir: #{data_dir.inspect}, root: #{File.join(data_dir, "volumes").inspect}, adapter: adapter,
                                                  mount_adapter: adapter, path_security: security, require_real_readback: true, fsync: true)
        backend_class = Rubernetes::Volume::EmptyDirBackend
        # Interrupt after the durable record exists and before content is complete.
        backend_class.prepend(Module.new do
          def restore(content: nil, content_sha256: nil)
            Process.kill("KILL", Process.pid)
            sleep 5
          end
        end)
        manager.restore(#{snapshot_id.inspect}, spec: {"id" => "m4-snap-interrupted", "name" => "m4-snap-interrupted", "backend" => "emptyDir"}, token: "snap-restore-interrupted")
      RUBY
      _stdout, _stderr, status = Open3.capture3(RbConfig.ruby, "-e", script, chdir: M4ObserverSupport::ROOT)
      killed = status.signaled? && status.termsig == 9
      entry = durable_volume_entries(File.join(data_dir, "volumes.json")).find do |volume|
        volume.is_a?(Hash) && volume["id"] == "m4-snap-interrupted"
      end
      usable = begin
        require "rubernetes/volume"
        openat2 = Rubernetes::Platform::Linux::Openat2.new(root: "/", strict: true)
        security = Rubernetes::Volume::PathSecurity.new(root: "/", adapter: openat2, require_openat2: true)
        adapter = Rubernetes::Volume::NativeMountAdapter.new
        manager = Rubernetes::Volume::Manager.new(data_dir: data_dir, root: File.join(data_dir, "volumes"), adapter: adapter,
                                                  mount_adapter: adapter, path_security: security, require_real_readback: true, fsync: true)
        manager.recover
        begin
          manager.publish("m4-snap-interrupted", "node-a", token: "interrupted-attach")
          true
        rescue Rubernetes::Volume::StateUnknownError
          false
        end
      end
      {"interrupted_restore_state" => entry && entry["state"], "interrupted_volume_usable" => usable,
       "interrupted_worker_killed" => killed}.tap do |observed|
        observed["interrupted_restore_state"] = "not-recorded" if entry.nil?
      end
    end
  end

  def crash(request)
    work_dir = Dir.mktmpdir("rubernetes-m4-volume-crash")
    scenario = CrashScenario.new(work_dir)
    result = scenario.run
    result.merge(
      "scenario" => request["scenario"] || "snapshot-restore-crash-recovery", "work_dir" => work_dir,
      "comparisons" => Array(result.dig("snapshot", "comparisons")) + Array(result["kill_points"]).filter_map do |entry|
        entry["effect_boundary_comparison"]
      end,
      "kernel_backed" => true, "measurement_source" => "external_kernel_observation",
      "mount_adapter_class" => "Rubernetes::Volume::NativeMountAdapter",
      "device_adapter_class" => "Rubernetes::Volume::NativeDeviceAdapter"
    )
  ensure
    FileUtils.remove_entry(work_dir) if work_dir && File.directory?(work_dir) && result && result["errors"].to_a.empty?
  end

  def main
    mode = "observation"
    OptionParser.new do |parser|
      parser.on("--mode MODE") { |value| mode = value }
    end.parse!(ARGV)
    started_at = M4ObserverSupport.iso8601_now
    request = parse_request
    document = case mode
               when "observation" then observation(request)
               when "crash" then crash(request)
               else raise ArgumentError, "unsupported runner mode #{mode}"
               end
    errors = Array(document["errors"])
    provenance = M4ObserverSupport.runner_provenance(RUNNER_PATH, implementation: IMPLEMENTATION, started_at: started_at)
    document = document.merge(
      "schema_version" => 1, "suite" => "m4-volume-observation", "mode" => mode,
      "executed" => true, "runner" => provenance, "runner_sha256" => provenance.fetch("runner_sha256"),
      "request_sha256" => M4ObserverSupport.digest(request), "errors" => errors,
      "failure_count" => errors.length, "passed" => errors.empty?
    )
    document["document_sha256"] = M4ObserverSupport.digest(document)
    puts JSON.generate(document)
    exit(errors.empty? ? 0 : 1)
  rescue StandardError => error
    warn "#{error.class}: #{error.message}"
    warn error.backtrace.first(10).join("\n")
    exit 2
  end
end

M4VolumeObservationRunner.main if $PROGRAM_NAME == __FILE__
