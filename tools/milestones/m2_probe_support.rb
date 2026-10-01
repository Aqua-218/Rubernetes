# frozen_string_literal: true

# Shared helpers for M2 adapters.  Adapters never convert an unavailable
# profile into a successful result; they emit a complete, machine-readable
# INCOMPLETE report and exit non-zero.

require "English"
require "digest"
require "fileutils"
require "json"
require "net/http"
require "open3"
require "rbconfig"
require "socket"
require "tmpdir"
require "time"
require "timeout"
require "uri"

require_relative "../../lib/rubernetes/cleanup"
require_relative "m2_gate"

module M2ProbeSupport
  # Landlock read/execute roots for the pulled workload image.  The pinned
  # busybox image is dynamically linked (/lib64/ld-linux-x86-64.so.2), so the
  # loader and libraries must be executable alongside /bin; /blocked, which
  # sits outside every root, is the denial witness.
  PROBE_LANDLOCK_ROOTS = %w[/bin /lib /lib64 /usr /etc].freeze
  ROOT = File.expand_path("../..", __dir__).freeze
  # Generator runs use a root-level mktemp directory. The anchored suffix
  # avoids excluding arbitrary source directories with a shared prefix.
  SOURCE_EXCLUSIONS = %r{\A(?:\.git|artifacts|build|pkg|tmp|\.bundle)(?:/|\z)|\Aa11-generated\.[A-Za-z0-9]{6,}/|\Aapps/[^/]+/(?:log|tmp|storage)/}
  REQUIRED_ARCHITECTURES = M2Gate::REQUIRED_ARCHITECTURES
  RESOURCE_KINDS = M2Gate::REQUIRED_RESOURCE_KINDS

  # Minimal API/sync ports used only to exercise the production Node::Agent
  # startup barrier in the privileged crash harness. They intentionally do not
  # synthesize runtime state or lifecycle outcomes.
  class NativeAgentAPI
    attr_reader :watch_count

    def initialize
      @events = []
      @pods = []
      @resource_version = 0
      @watch_count = 0
      @mutex = Mutex.new
    end

    def register_node(node)
      node
    end

    def renew_lease(lease)
      lease
    end

    def publish(pod, type: "ADDED")
      @mutex.synchronize do
        @resource_version += 1
        value = JSON.parse(JSON.generate(pod))
        value["metadata"] ||= {}
        value["metadata"]["resourceVersion"] = @resource_version.to_s
        @pods.reject! { |item| item.dig("metadata", "uid") == value.dig("metadata", "uid") }
        @pods << value
        @events << {"type" => String(type).upcase, "object" => value, "resourceVersion" => @resource_version.to_s}
        value
      end
    end

    def list(**_options)
      @mutex.synchronize do
        {"items" => JSON.parse(JSON.generate(@pods)),
         "metadata" => {"resourceVersion" => @resource_version.to_s}}
      end
    end

    def watch(**_options)
      @mutex.synchronize do
        @watch_count += 1
        values = @events
        @events = []
        JSON.parse(JSON.generate(values))
      end
    end
  end

  NativeAgentSession = Data.define(:agent, :runtime, :lifecycle) do
    def metadata
      start_time = M2ProbeSupport.process_start_time(Process.pid)
      {
        "ready" => agent.ready?,
        "registered" => agent.registered?,
        "agent_pid" => Process.pid,
        "agent_start_time" => start_time,
        "agent_process_identity" => "process:node-agent:#{Process.pid}:#{start_time}",
        "agent_class" => agent.class.name,
        "sync_loop_class" => agent.sync_loop.class.name,
        "lifecycle_class" => lifecycle.class.name,
        "runtime_class" => runtime.class.name,
        "runtime_profile" => runtime.profile.to_s,
        "recovery" => agent.recovery_report
      }
    end
  end

  # Production image acquisition for every M2 probe.  The digest-pinned
  # busybox from the Kubernetes v1.36.2 lock is pulled through the
  # production registry client, digest-verified, and unpacked by the
  # production layer extractor (whiteouts, hardlinks, symlink fencing) into
  # a cache under build/.  One pull serves a whole probe process, including
  # the 1000 ledger cycles and every forked crash worker.
  class PinnedImageCache
    LOCK_PATH = File.join(File.expand_path("../..", __dir__), "third_party/locks/kubernetes-v1.36.2.json").freeze
    CACHE_ROOT = File.join(File.expand_path("../..", __dir__), "build/m2-image-cache").freeze

    def initialize(lock_path: LOCK_PATH, cache_root: CACHE_ROOT)
      @lock_path = lock_path
      @cache_root = cache_root
      @mutex = Mutex.new
      @image = nil
      @resolver = nil
      @pulled_in = nil
    end

    # `registry.k8s.io/e2e-test-images/busybox@sha256:<linux/amd64 digest>`
    def reference
      @reference ||= begin
        lock = JSON.parse(File.binread(@lock_path))
        busybox = lock.fetch("runner_support_images").fetch("busybox")
        digest = busybox.fetch("platforms").fetch("linux/amd64")
        raise "Kubernetes lock busybox digest is invalid" unless digest.match?(/\Asha256:[0-9a-f]{64}\z/)

        "#{busybox.fetch("reference").sub(%r{:[^:/]+\z}, "")}@#{digest}"
      end
    end

    def digest
      reference.split("@", 2).last
    end

    # Node::Lifecycle resolver port.  Only the locked reference is
    # resolvable, so a probe cannot quietly substitute another image.
    def resolve(value, **_options)
      raise "M2 probes resolve only the locked busybox image, not #{value.inspect}" unless String(value) == reference

      image
    end

    def release(_image)
      true
    end

    def image
      @mutex.synchronize { @image ||= pull! }
    end

    def rootfs
      image.rootfs
    end

    def resolved_hash
      value = image.to_h
      raise "resolved image carries no raw manifest" unless value["manifest_raw"].is_a?(String)

      value
    end

    def aggregate_digest
      "sha256:#{Digest::SHA256.hexdigest(JSON.generate([digest].sort))}"
    end

    # Sandbox input for Runtime::Native#run_sandbox: the runtime derives the
    # lowerdir from the resolved rootfs and verifies the pinned manifest.
    def runtime_input(id:, lowerdirs: [], **extra)
      {"id" => id, "resolved_images" => [resolved_hash], "image_digest" => aggregate_digest,
       "lowerdirs" => Array(lowerdirs)}.merge(extra)
    end

    def container_spec(id:, command:, **extra)
      {"id" => id, "image" => reference, "command" => Array(command)}.merge(extra)
    end

    def provenance
      {
        "reference" => reference,
        "digest" => digest,
        "lock_path" => @lock_path.delete_prefix("#{File.expand_path("../..", __dir__)}/"),
        "rootfs" => rootfs,
        "manifest_sha256" => Digest::SHA256.hexdigest(resolved_hash.fetch("manifest_raw")),
        "layer_digests" => image.manifest.layers.map { |layer| layer.digest.to_s },
        "resolver_class" => "Rubernetes::Image::Resolver",
        "puller_class" => "Rubernetes::Image::Puller",
        "extractor_class" => "Rubernetes::Image::LayerExtractor",
        "verifier_class" => "Rubernetes::Image::PinnedImageVerifier",
        "pulled_in_pid" => @pulled_in
      }
    end

    def close
      resolver = @mutex.synchronize { @resolver }
      current = @mutex.synchronize { @image }
      return true unless resolver && current && @pulled_in == Process.pid

      resolver.release(current)
      @mutex.synchronize { @image = nil }
      true
    end

    private

    def pull!
      require "rubernetes/image"
      FileUtils.mkdir_p(@cache_root, mode: 0o700)
      client = Rubernetes::Image::RegistryClient.new(reference)
      puller = Rubernetes::Image::Puller.new(registry_client: client, store_root: File.join(@cache_root, "blobs"))
      staging_root = File.join(@cache_root, "stages")
      # Stages left by killed probe workers (SIGKILL matrix, aborted runs) are reclaimed
      # the same way the agent does at boot; otherwise build/m2-image-cache grows forever.
      FileUtils.mkdir_p(staging_root, mode: 0o700)
      Rubernetes::Image::Resolver.reclaim_abandoned_stages(staging_root: staging_root)
      @resolver = Rubernetes::Image::Resolver.new(puller: puller, staging_root: staging_root)
      image = @resolver.resolve(reference)
      raise "pulled image digest #{image.digest} is not the locked digest" unless image.digest.to_s == digest

      Rubernetes::Image::PinnedImageVerifier.new.verify(image: {"resolved_images" => [image.to_h]}, digest: aggregate_digest)
      @pulled_in = Process.pid
      image
    end
  end

  module_function

  def pinned_image
    @pinned_image ||= begin
      cache = PinnedImageCache.new
      at_exit { cache.close }
      cache
    end
  end

  def image_verifier
    require "rubernetes/image"
    Rubernetes::Image::PinnedImageVerifier.new
  end

  # Kernel-derived identity of one live container, read from procfs and
  # cgroupfs by the caller rather than reported by the runtime.
  def kernel_identity_for(runtime, container_id, name: nil)
    status = runtime.container_status(container_id)
    process = status.fetch("process") || {}
    pid = process["workload_pid"]
    raise "container #{container_id} has no live workload pid" unless pid

    cgroup_path = status.dig("cgroup", "path")
    proc_status = File.binread("/proc/#{pid}/status")
    fields = proc_status.each_line.with_object({}) do |line, result|
      key, value = line.split(":", 2)
      result[key] = value.to_s.strip if value
    end
    mountinfo = File.binread("/proc/#{pid}/mountinfo")
    root_line = mountinfo.each_line.to_a.reverse.find { |line| line.split.fetch(4, nil) == "/" }
    {
      "name" => name,
      "container_id" => container_id,
      "pid" => Integer(pid),
      "start_time" => process["workload_start_time"].to_s,
      "observed_start_time" => process_start_time(pid),
      "executable_digest" => process["workload_executable_digest"],
      "creation_method" => process["workload_creation_method"],
      "clone_flags" => process["workload_clone_flags"],
      "namespaces" => %w[mnt pid net uts ipc cgroup user].to_h { |ns| [ns, File.readlink("/proc/#{pid}/ns/#{ns}")] },
      "cgroup_path" => cgroup_path,
      "cgroup_inode" => cgroup_path ? File.stat(cgroup_path).ino : nil,
      "cgroup_membership" => File.readlines("/proc/#{pid}/cgroup", chomp: true),
      "root_mount_id" => root_line ? Integer(root_line.split.fetch(0)) : nil,
      "root_filesystem" => root_line ? root_line.split(" - ", 2).last.split.first : nil,
      "mount_count" => mountinfo.lines.length,
      "mountinfo_sha256" => Digest::SHA256.hexdigest(mountinfo),
      "status" => fields.slice("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb", "NoNewPrivs", "Seccomp", "NSpid", "Uid", "Gid"),
      "readiness" => process["workload_security"]
    }
  end

  def pidfd_count(pid = "self")
    Dir.children("/proc/#{pid}/fd").count do |fd|
      File.readlink("/proc/#{pid}/fd/#{fd}").include?("pidfd")
    rescue SystemCallError
      false
    end
  end

  # Independent leak scan of kernel state after a run.  It never consults the
  # runtime ledger: mounts come from every live process's mountinfo, cgroups
  # from the cgroup2 tree, processes from /proc, and pidfds from this
  # process's descriptor table.
  def kernel_leak_scan(sandbox_root:, sandbox_prefixes:, pidfd_baseline:)
    prefixes = Array(sandbox_prefixes).map(&:to_s).reject(&:empty?)
    root = File.expand_path(sandbox_root)
    mounts = []
    processes = []
    Dir.children("/proc").grep(/\A\d+\z/).each do |pid|
      begin
        File.foreach("/proc/#{pid}/mountinfo") do |line|
          mounts << {"pid" => Integer(pid), "line" => line.strip} if line.include?(root)
        end
      rescue SystemCallError
        next
      end
      begin
        cgroup = File.read("/proc/#{pid}/cgroup")
        if cgroup.include?("/rubernetes/") && prefixes.any? { |prefix| cgroup.include?("/#{prefix}") }
          processes << {"pid" => Integer(pid), "cgroup" => cgroup.strip, "comm" => begin
            File.read("/proc/#{pid}/comm").strip
          rescue StandardError
            nil
          end}
        end
      rescue SystemCallError
        next
      end
    end
    cgroups = prefixes.flat_map do |prefix|
      Dir.glob(File.join("/sys/fs/cgroup/rubernetes", "*", "#{prefix}*")).select { |path| File.directory?(path) }
    end.uniq.sort
    temp = Dir.glob(File.join(root, "*"))
    after = pidfd_count
    {
      "source" => "procfs+cgroupfs",
      "sandbox_root" => root,
      "sandbox_prefixes" => prefixes,
      "mounts" => mounts,
      "cgroups" => cgroups,
      "processes" => processes,
      "temp" => temp,
      "pidfd_before" => Integer(pidfd_baseline),
      "pidfd_after" => after,
      "pidfd_delta" => after - Integer(pidfd_baseline),
      "leak_count" => mounts.length + cgroups.length + processes.length + temp.length + [after - Integer(pidfd_baseline), 0].max
    }
  end

  def source_identity(root = ROOT)
    root = File.expand_path(root)
    paths = Dir.glob(File.join(root, "**/*"), File::FNM_DOTMATCH).select do |path|
      next false unless File.file?(path)

      relative = path.delete_prefix("#{root}/")
      !relative.match?(SOURCE_EXCLUSIONS)
    end.sort
    entries = paths.map do |path|
      {
        "path" => path.delete_prefix("#{root}/"),
        "sha256" => Digest::SHA256.file(path).hexdigest,
        "bytes" => File.size(path)
      }
    end
    {
      "sha256" => M2Gate.canonical_inventory_digest(entries),
      "file_count" => entries.length,
      "entries" => entries
    }
  end

  def input_context(current)
    expected_sha = ENV.fetch("RUBERNETES_M2_INPUT_SHA256", nil)
    expected_count = ENV.fetch("RUBERNETES_M2_INPUT_FILE_COUNT", nil)
    errors = []
    errors << "RUBERNETES_M2_INPUT_SHA256 must be a lowercase SHA-256 digest" if expected_sha && !M2Gate::SHA256_PATTERN.match?(expected_sha)
    parsed_count = begin
      Integer(expected_count, 10) if expected_count
    rescue ArgumentError, TypeError
      nil
    end
    errors << "RUBERNETES_M2_INPUT_FILE_COUNT must be a positive integer" if expected_count && (!parsed_count || parsed_count <= 0)
    input_sha = expected_sha && M2Gate::SHA256_PATTERN.match?(expected_sha) ? expected_sha : current.fetch("sha256")
    input_file_count = parsed_count && parsed_count.positive? ? parsed_count : current.fetch("file_count")
    stable = current.fetch("sha256") == input_sha && current.fetch("file_count") == input_file_count
    errors << "source input changed before probe execution" unless stable
    {
      "sha256" => input_sha,
      "file_count" => input_file_count,
      "stable" => stable,
      "errors" => errors
    }
  end

  def adapter_metadata(name)
    runner = File.expand_path($PROGRAM_NAME)
    raise "probe runner is not a regular file" unless File.file?(runner) && !File.symlink?(runner)

    {
      "name" => name,
      "version" => "1",
      "runner_sha256" => Digest::SHA256.file(runner).hexdigest
    }
  end

  def report_base(kind, input, adapter:, passed:, status:, errors: [], **fields)
    timestamp = Time.now.utc.iso8601(6)
    measurement_source = fields.delete(:measurement_source) || fields.delete("measurement_source")
    provenance = {
      "source_sha256" => input.fetch("sha256"),
      "source_file_count" => input.fetch("file_count"),
      "mode" => "production",
      "self_comparison" => false,
      "measurement_source" => measurement_source,
      "runner_sha256" => adapter.fetch("runner_sha256"),
      "command" => [RbConfig.ruby, File.expand_path($PROGRAM_NAME)],
      "command_kind" => "ruby_probe",
      "process_id" => Process.pid,
      "measurement_id" => "#{kind}-#{Process.pid}-#{Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)}",
      "started_at" => timestamp,
      "finished_at" => timestamp
    }
    provenance["provenance_sha256"] = M2Gate.canonical_document_digest(provenance, excluded_keys: ["provenance_sha256"])
    {
      "schema_version" => 1,
      "milestone" => "M2",
      "kind" => kind,
      "adapter" => adapter,
      "input_sha256" => input.fetch("sha256"),
      "input_file_count" => input.fetch("file_count"),
      "input_stable" => input.fetch("stable"),
      "attempt_count" => 1,
      "retry_count" => 0,
      "unexpected_skip_count" => 0,
      "unclassified_count" => 0,
      "flake_count" => 0,
      "failure_count" => passed ? 0 : 1,
      "passed" => passed,
      "status" => status,
      "errors" => Array(errors).map(&:to_s),
      "measurement_level" => fields.delete(:measurement_level) || fields.delete("measurement_level") || "L0",
      "measurement_source" => measurement_source,
      "provenance" => provenance
    }.merge(fields)
  end

  def run_probe(kind, adapter_name)
    current = source_identity
    input = input_context(current)
    errors = input.fetch("errors").dup
    payload = {}
    begin
      payload = yield(current, input) if errors.empty?
    rescue StandardError => error
      errors << "#{error.class}: #{error.message}"
    end
    payload = {} unless payload.is_a?(Hash)
    payload_errors = Array(payload.delete("errors")).map(&:to_s)
    errors.concat(payload_errors)
    declared_passed = payload.delete("passed")
    passed = errors.empty? && (declared_passed.nil? || declared_passed == true)
    report = report_base(
      kind,
      input,
      adapter: adapter_metadata(adapter_name),
      passed: passed,
      status: passed ? "PASS" : "INCOMPLETE",
      errors: errors,
      **payload
    )
    report["report_sha256"] = M2Gate.canonical_document_digest(report, excluded_keys: ["report_sha256"])
    puts(JSON.pretty_generate(report))
    exit(passed ? 0 : 1)
  end

  def unavailable_profile(architecture, error)
    {
      "architecture" => architecture,
      "available" => false,
      "status" => "INCOMPLETE",
      "passed" => false,
      "skip" => false,
      "profile_sha256" => Digest::SHA256.hexdigest("unavailable:#{architecture}:#{error}"),
      "levels" => M2Gate::REQUIRED_LEVELS.map do |level|
        {
          "level" => level,
          "status" => "INCOMPLETE",
          "passed" => false,
          "attempt_count" => 1,
          "failure_count" => 1,
          "unexpected_skip_count" => 0,
          "unclassified_count" => 0,
          "evidence_sha256" => Digest::SHA256.hexdigest("unavailable:#{architecture}:#{level}")
        }
      end
    }
  end

  def unavailable_kernel_profile(architecture, error)
    {
      "architecture" => architecture,
      "available" => false,
      "status" => "INCOMPLETE",
      "passed" => false,
      "skip" => false,
      "profile_sha256" => Digest::SHA256.hexdigest("kernel-unavailable:#{architecture}:#{error}"),
      "objects" => [],
      "inventory_sha256" => Digest::SHA256.hexdigest(""),
      "baseline_sha256" => Digest::SHA256.hexdigest("baseline:#{architecture}"),
      "final_sha256" => Digest::SHA256.hexdigest("final:#{architecture}"),
      "difference_count" => 1,
      "live_leak_count" => 1,
      "orphan_count" => 1
    }
  end

  def architecture_name
    cpu = RbConfig::CONFIG.fetch("host_cpu")
    case cpu
    when "amd64", "x86_64" then "x86_64"
    when "arm64", "aarch64" then "aarch64"
    else cpu
    end
  end

  def l3_available?
    require "rubernetes/runtime/native"

    cgroup = Rubernetes::Platform::Linux::CgroupV2.new.probe
    security = Rubernetes::Platform::Linux::Security::CapabilityProbe.new.call
    cgroup.available? && security.available?(:no_new_privs) &&
      security.available?(:seccomp) && security.available?(:landlock)
  rescue StandardError
    false
  end

  # Start an actual production Native sandbox/container under a real Node
  # Agent, SIGKILL that Agent while the final workload is alive, and replay the
  # exact Native ownership WAL in a fresh Agent.  A parent-side observer reads
  # procfs, cgroupfs and the holder's mountinfo; it never changes liveness bits.
  def measure_sigkill_matrix(effect_points:, image_digest:)
    Array(effect_points).map do |effect_point|
      measure_sigkill_point(effect_point, image_digest: image_digest)
    end
  end

  def measure_sigkill_point(effect_point, image_digest:)
    require File.join(ROOT, "lib/rubernetes/runtime/native")

    point = String(effect_point)
    raise "unknown Native effect point #{point.inspect}" unless M2Gate::REQUIRED_EFFECT_POINTS.include?(point)

    worker_pid = nil
    restart_pid = nil
    guard_runtime = nil
    guard_sandbox = nil
    Dir.mktmpdir("rubernetes-m2-sigkill-") do |directory|
      image = pinned_image
      image.image
      observer = NativeKernelObserver.new(directory: directory)
      guard_runtime, guard_sandbox, _guard_container = start_guard_workload(
        directory: directory, observer: observer
      )
      request_id = "sigkill-#{effect_point}-sandbox"
      native_wal_path = File.join(directory, "native-agent.wal")
      worker_pid = fork do
        worker_observer = NativeKernelObserver.new(directory: directory)
        session = nil
        effect_hook = lambda do |effect_point:, sandbox:, operation:, transition:|
          next unless effect_point == point

          manifest = worker_observer.capture_effect(
            runtime: session.runtime, sandbox: sandbox, role: "victim",
            agent_pid: Process.pid, effect_point: effect_point
          )
          observed_inventory = worker_observer.list_resources.select do |resource|
            resource.dig("metadata", "observer_role") == "victim"
          end
          checkpoint = native_effect_checkpoint(
            effect_point, operation: operation, transition: transition,
                          inventory: observed_inventory, request_id: request_id
          )
          metadata = session.metadata.merge(
            "request_id" => request_id,
            "effect_point" => effect_point,
            "sandbox_id" => sandbox.id,
            "native_wal_path" => native_wal_path,
            "checkpoint" => checkpoint,
            "liveness_pid" => manifest.fetch("liveness_pid"),
            "liveness_start_time" => manifest.fetch("liveness_start_time")
          )
          # The hook is the durable effect barrier, not the kill itself.
          # Let the Native state machine finish its remaining setup, then
          # start one real workload and publish a second, independent
          # readiness record.  The parent never kills an Agent before
          # this workload identity has been observed from /proc/cgroup.
          write_json_fsync(File.join(directory, "ready-#{point}.json"), checkpoint)
          Thread.current[:m2_sigkill_checkpoint] = metadata
        end
        session = start_native_agent(
          directory: directory, observer: worker_observer, effect_hook: effect_hook
        )
        runtime = session.runtime
        sandbox_id = "m2-agent-crash-#{safe_probe_component(effect_point)}"
        runtime.run_sandbox(image.runtime_input(id: sandbox_id), request_id: request_id)
        sandbox = runtime.sandbox(sandbox_id)
        container = runtime.create_container(sandbox, image.container_spec(id: "victim", command: ["/bin/busybox", "sleep", "3600"]))
        container = runtime.start_container(container, request_id: "#{request_id}:workload")
        # Replace the pre-workload observer manifest with a fresh kernel
        # readback.  The checkpoint retains the exact pre-effect digest;
        # this manifest proves the live workload that must not be deleted
        # accidentally when the Agent is killed.
        worker_observer.capture(
          runtime: runtime, sandbox: sandbox, container: container,
          role: "victim", agent_pid: Process.pid
        )
        actual_inventory = worker_observer.list_resources.select do |resource|
          resource.dig("metadata", "observer_role") == "victim"
        end
        assert_unique_inventory_identities!(actual_inventory, "Native SIGKILL workload inventory")
        actual_process = actual_inventory.find { |resource| resource["kind"] == "process" }
        raise "Native SIGKILL workload process was not observed" unless actual_process

        process_metadata = actual_process.fetch("metadata")
        actual_workload = {
          "pid" => process_metadata.fetch("pid"),
          "start_time" => process_metadata.fetch("start_time").to_s,
          "command" => process_metadata.fetch("command"),
          "executable_digest" => process_metadata.fetch("executable_digest"),
          "cgroup_path" => process_metadata.fetch("cgroup_path"),
          "cgroup_membership" => process_metadata.fetch("cgroup_membership"),
          "pid_namespace" => process_metadata.fetch("pid_namespace"),
          "mount_namespace" => process_metadata.fetch("mount_namespace"),
          "workload_pidfd" => process_metadata.fetch("workload_pidfd"),
          "workload_pidfd_link" => process_metadata.fetch("workload_pidfd_link"),
          "creation_method" => process_metadata.fetch("creation_method"),
          "clone_flags" => process_metadata.fetch("clone_flags")
        }
        checkpoint_metadata = Thread.current[:m2_sigkill_checkpoint] || {}
        metadata = checkpoint_metadata.merge(
          "actual_workload" => actual_workload,
          "workload_pid" => actual_workload.fetch("pid"),
          "workload_start_time" => actual_workload.fetch("start_time"),
          "workload_command" => actual_workload.fetch("command"),
          "workload_executable_digest" => actual_workload.fetch("executable_digest"),
          "workload_creation_method" => actual_workload.fetch("creation_method"),
          "workload_clone_flags" => actual_workload.fetch("clone_flags")
        )
        write_json_fsync(File.join(directory, "worker.json"), metadata)
        write_json_fsync(File.join(directory, "workload-ready.json"), actual_workload)
        loop { sleep 1 }
      rescue Exception => error # rubocop:disable Lint/RescueException -- crash child must persist diagnostics
        write_json_fsync(File.join(directory, "worker-error.json"), {
                           "class" => error.class.name,
                           "message" => error.message
                         })
        exit!(70)
      end

      worker_metadata_path = File.join(directory, "worker.json")
      ready_path = File.join(directory, "ready-#{effect_point}.json")
      wait_for_file(worker_metadata_path, worker_pid, error_path: File.join(directory, "worker-error.json"))
      wait_for_file(ready_path, worker_pid, error_path: File.join(directory, "worker-error.json"))
      worker_metadata = parse_json_file(worker_metadata_path)
      checkpoint = parse_json_file(ready_path)
      inventory_at_kill = observer.list_resources
      assert_unique_inventory_identities!(inventory_at_kill, "Native SIGKILL inventory at kill")
      wal_before_sha256 = file_digest(native_wal_path)
      Process.kill("KILL", worker_pid)
      _waited_pid, status = Process.wait2(worker_pid)
      worker_pid = nil
      victim_namespace = inventory_at_kill.find do |resource|
        resource["kind"] == "namespace" && resource.dig("metadata", "observer_role") == "victim"
      end
      if victim_namespace
        wait_for_process_identity_exit(
          victim_namespace.dig("metadata", "pid"),
          victim_namespace.dig("metadata", "start_time")
        )
      end
      actual_workload = worker_metadata["actual_workload"]
      if actual_workload.is_a?(Hash)
        wait_for_process_identity_exit(
          actual_workload.fetch("pid"),
          actual_workload.fetch("start_time")
        )
      end
      inventory_before = observer.list_resources
      assert_unique_inventory_identities!(inventory_before, "Native SIGKILL inventory before recovery")

      restart_result_path = File.join(directory, "restart-result.json")
      restart_pid = fork do
        restart_observer = NativeKernelObserver.new(directory: directory)
        begin
          session = start_native_agent(directory: directory, observer: restart_observer)
          operation = session.runtime.ledger.operation_for_request(request_id)
          write_json_fsync(restart_result_path, {
                             "wal_replayed" => !operation.nil?,
                             "replayed_operation_state" => operation&.state,
                             "replayed_request_ids" => {request_id => !operation.nil?},
                             "inventory_before" => inventory_before,
                             "inventory_after" => restart_observer.list_resources,
                             "recovery" => session.agent.recovery_report,
                             "native_agent" => session.metadata
                           })
          exit!(0)
        rescue Exception => error # rubocop:disable Lint/RescueException
          write_json_fsync(restart_result_path, {
                             "wal_replayed" => false,
                             "inventory_before" => inventory_before,
                             "inventory_after" => restart_observer.list_resources,
                             "recovery" => {"errors" => ["#{error.class}: #{error.message}"]},
                             "error" => "#{error.class}: #{error.message}"
                           })
          exit!(71)
        end
      end
      restart_process_pid = restart_pid
      _restarted_pid, restart_status = Process.wait2(restart_pid)
      restart_pid = nil
      restart_result = parse_json_file(restart_result_path)
      inventory_after = observer.list_resources
      assert_unique_inventory_identities!(inventory_after, "Native SIGKILL inventory after recovery")
      wal_after_sha256 = file_digest(native_wal_path)
      result = {
        "effect_point" => effect_point,
        "crash_checkpoint" => checkpoint,
        "signal" => "SIGKILL",
        "measurement_id" => request_id,
        "wal_path" => native_wal_path,
        "native_wal_path" => native_wal_path,
        "wal_kind" => "rubernetes_native_ownership_ledger",
        "target_pid" => worker_metadata.fetch("agent_pid"),
        "target_start_time" => worker_metadata.fetch("agent_start_time").to_s,
        "actual_workload" => worker_metadata.fetch("actual_workload"),
        "kernel_observer" => {
          "external" => true, "observer_pid" => Process.pid,
          "inventory_at_kill" => inventory_at_kill,
          "inventory_at_kill_sha256" => digest_json(inventory_at_kill)
        },
        "restart_pid" => restart_process_pid,
        "restart_process" => "fork",
        "kill_observed" => status.signaled? && status.termsig == Signal.list.fetch("KILL"),
        "restart_observed" => restart_status.success? && restart_result["error"].nil?,
        "wal_replayed" => restart_result["wal_replayed"] == true,
        "replayed_operation_state" => restart_result["replayed_operation_state"],
        "replayed_request_ids" => restart_result.fetch("replayed_request_ids", {}),
        "wait_status" => {
          "signaled" => status.signaled?,
          "signal" => status.signaled? ? "SIG#{Signal.signame(status.termsig)}" : nil,
          "exit_status" => status.exited? ? status.exitstatus : nil
        },
        "wal_before_sha256" => wal_before_sha256,
        "wal_after_sha256" => wal_after_sha256,
        "wal_changed" => wal_before_sha256 != wal_after_sha256,
        "inventory_before" => inventory_before,
        "inventory_after" => inventory_after,
        "inventory_before_sha256" => digest_json(inventory_before),
        "inventory_after_sha256" => digest_json(inventory_after),
        "live_wrong_deletion_count" => observer.live_guard_present? ? 0 : 1,
        "dead_residual_count" => observer.dead_residual_count,
        "recovery" => restart_result.fetch("recovery", {}),
        "native_agent" => restart_result.fetch("native_agent", {}),
        "measurement_source" => "production_native_agent_sigkill"
      }
      result["restart_exit_status"] = restart_status.exitstatus if restart_status.exited?
      result["restart_error"] = restart_result["error"] if restart_result["error"]
      result["evidence_sha256"] = M2Gate.canonical_document_digest(result, excluded_keys: ["evidence_sha256"])
      result
    ensure
      terminate_child(worker_pid)
      terminate_child(restart_pid)
      cleanup_guard_workload(guard_runtime, guard_sandbox)
    end
  rescue StandardError => error
    {
      "effect_point" => effect_point,
      "signal" => "SIGKILL",
      "measurement_id" => "sigkill-error-#{effect_point}-#{Process.pid}",
      "wal_path" => "",
      "wal_changed" => false,
      "target_pid" => 0,
      "target_start_time" => "",
      "restart_pid" => Process.pid,
      "restart_process" => "fork",
      "kill_observed" => false,
      "restart_observed" => false,
      "wal_replayed" => false,
      "wait_status" => {"signaled" => false, "signal" => nil, "exit_status" => nil},
      "wal_before_sha256" => Digest::SHA256.hexdigest(""),
      "wal_after_sha256" => Digest::SHA256.hexdigest(""),
      "inventory_before_sha256" => Digest::SHA256.hexdigest(""),
      "inventory_after_sha256" => Digest::SHA256.hexdigest(""),
      "live_wrong_deletion_count" => 1,
      "dead_residual_count" => 1,
      "native_agent" => {"ready" => false, "error" => "Native Agent process did not reach recovery barrier"},
      "measurement_source" => "production_native_agent_sigkill",
      "error" => "#{error.class}: #{error.message}"
    }.tap do |result|
      result["evidence_sha256"] = M2Gate.canonical_document_digest(result, excluded_keys: ["evidence_sha256"])
    end
  end

  EFFECT_OPERATIONS = {
    "workspace_allocated" => "sandbox.workspace.prepare",
    "isolation_created" => "sandbox.isolation.create",
    "resources_attached" => "sandbox.resources.attach",
    "workload_stopped" => "sandbox.workload_gate.close"
  }.freeze

  def native_effect_checkpoint(effect_point, operation:, transition:, inventory:, request_id:)
    state = String(operation.respond_to?(:state) ? operation.state : operation.fetch("state"))
    transition_hash = transition.respond_to?(:to_h) ? transition.to_h : transition
    expected_state = effect_point.split("_").map(&:capitalize).join
    raise "effect hook #{effect_point} observed state #{state}" unless state == expected_state
    raise "effect hook #{effect_point} was not bound to a state transition" unless transition_hash["event"] == "state_transition"
    raise "effect hook #{effect_point} transition target changed" unless transition_hash.dig("payload", "to") == expected_state

    victim_inventory = Array(inventory)
    assert_unique_inventory_identities!(victim_inventory, "Native effect checkpoint inventory")
    transition_evidence = {
      "sequence" => transition_hash.fetch("sequence"),
      "operation_id" => transition_hash.fetch("operation_id"),
      "event" => transition_hash.fetch("event"),
      "from" => transition_hash.dig("payload", "from"),
      "to" => transition_hash.dig("payload", "to"),
      "state" => transition_hash.dig("payload", "state"),
      "digest" => transition_hash.fetch("digest")
    }
    token_input = [request_id, effect_point, transition_evidence.fetch("sequence"),
                   transition_evidence.fetch("digest")].join("\0")
    {
      "effect_point" => effect_point,
      "native_state" => state,
      "actual_operation" => EFFECT_OPERATIONS.fetch(effect_point),
      "operation_id" => operation.respond_to?(:id) ? operation.id : operation.fetch("id"),
      "request_id" => request_id,
      "workload_gate" => "closed",
      "workload_process_count" => victim_inventory.count { |resource| resource["kind"] == "process" },
      # Keep the effect-boundary inventory separate from the later workload
      # readback.  A SIGKILL report must prove both: the exact kernel objects
      # present at the durable transition and the actual clone3 workload that
      # was alive when the Agent died.
      "effect_inventory" => victim_inventory,
      "kernel_inventory_sha256" => digest_json(victim_inventory),
      "wal_transition" => transition_evidence,
      "barrier_token" => Digest::SHA256.hexdigest(token_input)
    }
  end

  def safe_probe_component(value)
    Digest::SHA256.hexdigest(String(value))[0, 20]
  end

  def start_guard_workload(directory:, observer:)
    sandbox_root = File.join(directory, "guard-sandboxes")
    adapters = Rubernetes::Platform::Linux::NativeAdapters.for_profile(
      profile: :l3, sandbox_root: sandbox_root, cgroup_root: "/sys/fs/cgroup",
      architecture: architecture_name
    )
    runtime = Rubernetes::Runtime::Native.new(
      profile: :l3, l3: true, adapters: adapters.merge(image: image_verifier),
      sandbox_root: sandbox_root, cgroup_root: "/sys/fs/cgroup",
      log_root: File.join(directory, "guard-logs"),
      journal_path: File.join(directory, "guard-native.wal"),
      security_context: {"allow_privilege_escalation" => false, "seccomp" => "RuntimeDefault"}
    )
    sandbox_id = "m2-live-guard-#{safe_probe_component(directory)}"
    key = runtime.run_sandbox(pinned_image.runtime_input(id: sandbox_id), request_id: "#{sandbox_id}-sandbox")
    sandbox = runtime.sandbox(key)
    container = runtime.create_container(
      sandbox,
      pinned_image.container_spec(id: "guard", command: ["/bin/busybox", "sleep", "3600"]),
      request_id: "#{sandbox_id}-create"
    )
    container = runtime.start_container(container, request_id: "#{sandbox_id}-start")
    observer.capture(runtime: runtime, sandbox: sandbox, container: container,
                     role: "guard", agent_pid: Process.pid)
    [runtime, sandbox, container]
  end

  def cleanup_guard_workload(runtime, sandbox)
    return unless runtime && sandbox

    runtime.stop_sandbox(sandbox, timeout: 1) if runtime.sandboxes.any? { |entry| entry["id"] == sandbox.id }
    runtime.remove_sandbox(sandbox) if runtime.sandboxes.any? { |entry| entry["id"] == sandbox.id }
  rescue StandardError
    nil
  end

  def wait_for_process_identity_exit(pid, start_time, timeout: 5.0)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
    while process_start_time(pid).to_s == start_time.to_s
      raise "workload #{pid} survived Agent SIGKILL" if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline

      sleep 0.01
    end
    true
  end

  def actual_workload_evidence(metadata, inventory)
    process = Array(inventory).find do |entry|
      entry["kind"] == "process" && entry.dig("metadata", "observer_role") == "victim"
    end || {}
    values = process.fetch("metadata", {})
    {
      "pid" => metadata.fetch("workload_pid"),
      "start_time" => metadata.fetch("workload_start_time").to_s,
      "command" => metadata.fetch("workload_command"),
      "executable_digest" => metadata.fetch("workload_executable_digest"),
      "cgroup_path" => values["cgroup_path"],
      "cgroup_membership" => values["cgroup_membership"],
      "pid_namespace" => values["pid_namespace"],
      "mount_namespace" => values["mount_namespace"],
      "workload_pidfd" => values["workload_pidfd"],
      "workload_pidfd_link" => values["workload_pidfd_link"],
      "creation_method" => metadata.fetch("workload_creation_method"),
      "clone_flags" => metadata.fetch("workload_clone_flags")
    }
  end

  def inventory_measurement_from(matrix)
    raw_matrix = Array(matrix)
    raw_matrix.each_with_index do |entry, index|
      assert_unique_inventory_identities!(Array(entry["inventory_before"]), "SIGKILL inventory before entry #{index}")
      assert_unique_inventory_identities!(Array(entry["inventory_after"]), "SIGKILL inventory after entry #{index}")
    end
    before = raw_matrix.flat_map { |entry| Array(entry["inventory_before"]) }
    after = raw_matrix.flat_map { |entry| Array(entry["inventory_after"]) }
    assert_unique_inventory_identities!(before, "SIGKILL aggregate inventory before")
    assert_unique_inventory_identities!(after, "SIGKILL aggregate inventory after")
    before_keys = inventory_keys(before)
    after_keys = inventory_keys(after)
    diff = {
      "added" => (after_keys - before_keys).sort,
      "removed" => (before_keys - after_keys).sort,
      "retained" => (after_keys & before_keys).sort
    }
    observed_kinds = (before + after).filter_map { |entry| entry["kind"] }.uniq.sort
    missing_kinds = (RESOURCE_KINDS - observed_kinds).sort
    measurement = {
      "source" => "real_adapter",
      "measurement_source" => "production_native_agent_sigkill",
      "measurement_id" => "inventory-#{Process.pid}-#{Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)}",
      "before" => before,
      "after" => after,
      "diff" => diff,
      "inventory_diff_sha256" => M2Gate.canonical_document_digest({"before" => before, "after" => after, "diff" => diff}),
      "resource_kinds" => observed_kinds,
      "required_resource_kinds" => RESOURCE_KINDS,
      "missing_resource_kinds" => missing_kinds,
      "profile_status" => missing_kinds.empty? ? "PASS" : "INCOMPLETE",
      "live_leak_count" => dead_residuals(after),
      "orphan_count" => 0,
      "live_wrong_deletion_count" => 0
    }
    raw_matrix.each do |entry|
      next unless entry.is_a?(Hash)

      entry["inventory_measurement_id"] = measurement.fetch("measurement_id")
      if entry.key?("evidence_sha256")
        entry["evidence_sha256"] =
          M2Gate.canonical_document_digest(entry, excluded_keys: ["evidence_sha256"])
      end
    end
    measurement
  end

  # Exercise the production Native L3 boundary for every lifecycle cycle.
  # Each iteration creates a fresh OverlayFS mount namespace, cgroups,
  # workload process and pidfds, then proves those exact kernel identities are
  # absent after stop/delete.  The returned inventory is therefore evidence
  # from real adapters, not a ResourceLedger state-machine simulation.
  class NativeEffectFault < StandardError
    attr_reader :effect_point, :token

    def initialize(effect_point, token)
      @effect_point = String(effect_point)
      @token = String(token)
      super("injected Native effect fault #{@effect_point} token=#{@token}")
    end
  end

  # Count identities that were already observed in an earlier Native cycle and
  # remember every identity in the supplied inventory for the next cycle.
  def record_resource_reuse(entries, seen_identities)
    assert_unique_inventory_identities!(entries, "Native lifecycle cycle inventory")
    Array(entries).count do |entry|
      identity = entry.fetch("identity")
      reused = seen_identities.key?(identity)
      seen_identities[identity] = true
      reused
    end
  end

  def measure_native_l3_cycles(count: 1_000, fault_points: [])
    require "rubernetes/runtime/native"

    total = Integer(count)
    raise "Native L3 cycle count must be positive" unless total.positive?

    planned_faults = Array(fault_points).map(&:to_s)
    unknown_faults = planned_faults - M2Gate::REQUIRED_EFFECT_POINTS
    raise "unknown Native fault points: #{unknown_faults.join(", ")}" unless unknown_faults.empty?
    raise "Native fault point count exceeds cycle count" if planned_faults.length > total
    raise "production Native L3 cycles require root" unless Process.uid.zero?

    image = pinned_image
    image.image
    cycles = []
    acquired_inventory = []
    residual_inventory = []
    seen_identities = {}
    reuse_count = 0
    leak_scan = nil
    limits_evidence = nil
    pidfd_baseline = pidfd_count
    Dir.mktmpdir("rubernetes-m2-native-cycles-") do |directory|
      sandbox_root = File.join(directory, "sandboxes")
      adapters = Rubernetes::Platform::Linux::NativeAdapters.for_profile(
        profile: :l3, sandbox_root: sandbox_root, cgroup_root: "/sys/fs/cgroup",
        architecture: architecture_name
      )
      observer = NativeKernelObserver.new(directory: File.join(directory, "kernel-observer"))
      runtime = nil
      armed_fault = nil
      fault_capture = nil
      effect_hook = lambda do |effect_point:, sandbox:, operation:, transition:|
        next unless armed_fault && armed_fault.fetch("effect_point") == effect_point

        role = armed_fault.fetch("role")
        manifest = observer.capture_effect(
          runtime: runtime, sandbox: sandbox, role: role,
          agent_pid: Process.pid, effect_point: effect_point
        )
        active = observer.list_resources.select do |resource|
          resource.dig("metadata", "observer_role") == role
        end
        assert_unique_inventory_identities!(active, "Native effect fault active inventory")
        checkpoint = native_effect_checkpoint(
          effect_point, operation: operation, transition: transition,
                        inventory: active, request_id: armed_fault.fetch("request_id")
        )
        token = Digest::SHA256.hexdigest([
          armed_fault.fetch("cycle"), effect_point,
          checkpoint.dig("wal_transition", "digest")
        ].join("\0"))
        fault_capture = {
          "cycle" => armed_fault.fetch("cycle"),
          "effect_point" => effect_point,
          "token" => token,
          "role" => role,
          "checkpoint" => checkpoint,
          "active_inventory" => active,
          "manifest_sha256" => M2Gate.canonical_document_digest(manifest)
        }
        raise NativeEffectFault.new(effect_point, token)
      end
      runtime = Rubernetes::Runtime::Native.new(
        profile: :l3, l3: true,
        adapters: adapters.merge(
          image: image_verifier,
          observer: observer,
          cleaner: ->(resource) { observer.cleanup_resource(resource) },
          effect_hook: effect_hook
        ),
        sandbox_root: sandbox_root, cgroup_root: "/sys/fs/cgroup",
        log_root: File.join(directory, "logs"),
        journal_path: File.join(directory, "journal.jsonl"),
        memory_qos: true,
        security_context: {"allow_privilege_escalation" => false, "seccomp" => "RuntimeDefault"}
      )
      limits_evidence = ledger_limits_evidence

      (1..total).each do |cycle_number|
        sandbox_id = format("m2-native-cycle-%04d", cycle_number)
        fault_point = planned_faults[cycle_number - 1]
        armed_fault = if fault_point
                        {"cycle" => cycle_number, "effect_point" => fault_point,
                         "role" => format("fault-%04d", cycle_number), "request_id" => sandbox_id}
                      end
        fault_capture = nil
        started_at = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        sandbox = nil
        begin
          sandbox_id = runtime.run_sandbox(image.runtime_input(id: sandbox_id, spec: LEDGER_POD_SPEC), request_id: sandbox_id)
          sandbox = runtime.sandbox(sandbox_id)
          container = runtime.create_container(sandbox, image.container_spec(
            id: "main", command: ["/bin/busybox", "sleep", "3600"],
            resources: LEDGER_CONTAINER_RESOURCES, pids_limit: LEDGER_PIDS_LIMIT
          ))
          container = runtime.start_container(container)
          active = native_cycle_inventory(sandbox, container, expected_limits: limits_evidence.fetch("expected"),
                                                              expected_pod_limits: limits_evidence.fetch("expected_pod"))
          assert_unique_inventory_identities!(active, "Native L3 cycle #{cycle_number} active inventory")
          cycle_reuse_count = record_resource_reuse(active, seen_identities)
          reuse_count += cycle_reuse_count
          acquired_inventory.concat(active)

          runtime.stop_sandbox(sandbox, timeout: 2)
          runtime.remove_sandbox(sandbox)
          residual = native_cycle_residual_inventory(sandbox, container)
          assert_unique_inventory_identities!(residual, "Native L3 cycle #{cycle_number} residual inventory")
          residual_inventory.concat(residual)
          passed = residual.empty? && runtime.sandboxes.none? { |entry| entry.fetch("id") == sandbox_id } && cycle_reuse_count.zero?
          cycles << {
            "cycle" => cycle_number,
            "operations" => %w[create start stop delete],
            "status" => passed ? "PASS" : "FAIL",
            "passed" => passed,
            "attempt_count" => 1,
            "failure_count" => passed ? 0 : 1,
            "live_leak_count" => residual.length,
            "orphan_count" => 0,
            "resource_reuse_count" => cycle_reuse_count,
            "resource_count" => active.length,
            "released_resource_count" => active.length - residual.length,
            "resource_kinds" => active.map { |entry| entry.fetch("kind") }.uniq.sort,
            "active_inventory" => active,
            "active_inventory_sha256" => M2Gate.canonical_document_digest(active),
            "active_inventory_count" => active.length,
            "active_inventory_kinds" => active.map { |entry| entry.fetch("kind") }.uniq.sort,
            "residual_inventory" => residual,
            "residual_inventory_sha256" => M2Gate.canonical_document_digest(residual),
            "residual_inventory_count" => residual.length,
            "residual_inventory_kinds" => residual.map { |entry| entry.fetch("kind") }.uniq.sort,
            "kernel_identity_sha256" => M2Gate.canonical_document_digest(active),
            "kernel_identity_source" => "production_native_l3_kernel_inventory",
            "measurement_source" => "production_native_l3_cycles",
            "elapsed_ms" => ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - started_at) * 1_000).round(3)
          }
        rescue NativeEffectFault => error
          raise "fault point escaped its armed cycle" unless fault_point == error.effect_point
          raise "fault token changed across the injection boundary" unless fault_capture&.fetch("token") == error.token

          operation = runtime.ledger.operation(sandbox_id)
          raise "fault rollback did not retain the durable operation" unless operation

          recovery = runtime.recover(observer: observer, cleaner: ->(resource) { observer.cleanup_resource(resource) })
          recovery_hash = recovery.respond_to?(:to_h) ? recovery.to_h : recovery
          residual = observer.list_resources.select do |resource|
            resource.dig("metadata", "observer_role") == fault_capture.fetch("role")
          end
          active = fault_capture.fetch("active_inventory")
          measured_active = active.select { |resource| RESOURCE_KINDS.include?(resource.fetch("kind")) }
          assert_unique_inventory_identities!(active, "Native L3 fault cycle #{cycle_number} active inventory")
          assert_unique_inventory_identities!(measured_active, "Native L3 fault cycle #{cycle_number} measured inventory")
          assert_unique_inventory_identities!(residual, "Native L3 fault cycle #{cycle_number} residual inventory")
          cycle_reuse_count = record_resource_reuse(measured_active, seen_identities)
          reuse_count += cycle_reuse_count
          wal_records = runtime.ledger.journal.records.select { |record| record["operation_id"] == sandbox_id }
          observed_error = {
            "class" => error.class.name,
            "message" => error.message,
            "message_sha256" => Digest::SHA256.hexdigest(error.message)
          }
          fault_record = fault_capture.merge(
            "injected" => true,
            "observed_error" => observed_error,
            "wal_path" => runtime.ledger.journal.path,
            "wal_records" => wal_records,
            "wal_records_sha256" => M2Gate.canonical_document_digest(wal_records),
            "rollback_state" => operation.state,
            "recovery" => recovery_hash,
            "recovery_sha256" => M2Gate.canonical_document_digest(recovery_hash),
            "residual_inventory" => residual,
            "residual_inventory_sha256" => M2Gate.canonical_document_digest(residual)
          )
          fault_record["evidence_sha256"] = M2Gate.canonical_document_digest(
            fault_record, excluded_keys: ["evidence_sha256"]
          )
          passed = operation.state == "Stopped" && residual.empty? &&
                   Array(recovery_hash["errors"]).empty? && measured_active.any? && cycle_reuse_count.zero?
          acquired_inventory.concat(measured_active)
          residual_inventory.concat(residual.select { |resource| RESOURCE_KINDS.include?(resource.fetch("kind")) })
          cycles << {
            "cycle" => cycle_number,
            "operations" => %w[create fault rollback recover],
            "status" => passed ? "PASS" : "FAIL",
            "passed" => passed,
            "attempt_count" => 1,
            "failure_count" => 1,
            "live_leak_count" => residual.length,
            "orphan_count" => Array(recovery_hash["orphans"]).length,
            "resource_reuse_count" => cycle_reuse_count,
            "resource_count" => measured_active.length,
            "released_resource_count" => measured_active.length - residual.length,
            "resource_kinds" => measured_active.map { |entry| entry.fetch("kind") }.uniq.sort,
            "active_inventory" => measured_active,
            "active_inventory_sha256" => M2Gate.canonical_document_digest(measured_active),
            "active_inventory_count" => measured_active.length,
            "active_inventory_kinds" => measured_active.map { |entry| entry.fetch("kind") }.uniq.sort,
            "residual_inventory" => residual,
            "residual_inventory_sha256" => M2Gate.canonical_document_digest(residual),
            "residual_inventory_count" => residual.length,
            "residual_inventory_kinds" => residual.map { |entry| entry.fetch("kind") }.uniq.sort,
            "kernel_identity_sha256" => M2Gate.canonical_document_digest(measured_active),
            "kernel_identity_source" => "production_native_l3_effect_fault_inventory",
            "measurement_source" => "production_native_l3_cycles",
            "fault_injection" => fault_record,
            "elapsed_ms" => ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - started_at) * 1_000).round(3)
          }
        ensure
          armed_fault = nil
          if sandbox && runtime.sandboxes.any? { |entry| entry.fetch("id") == sandbox_id }
            begin
              runtime.stop_sandbox(sandbox, timeout: 1)
              runtime.remove_sandbox(sandbox)
            rescue StandardError
              nil
            end
          end
        end
      end

      leak_scan = kernel_leak_scan(sandbox_root: sandbox_root, sandbox_prefixes: ["m2-native-cycle-"],
                                   pidfd_baseline: pidfd_baseline)
    end

    assert_unique_inventory_identities!(acquired_inventory, "Native L3 cycle aggregate active inventory")
    assert_unique_inventory_identities!(residual_inventory, "Native L3 cycle aggregate residual inventory")
    before = acquired_inventory
    after = residual_inventory
    before_keys = inventory_keys(before)
    after_keys = inventory_keys(after)
    diff = {
      "added" => (after_keys - before_keys).sort,
      "removed" => (before_keys - after_keys).sort,
      "retained" => (after_keys & before_keys).sort
    }
    kinds = before.filter_map { |entry| entry["kind"] }.uniq.sort
    measurement = {
      "source" => "real_adapter",
      "measurement_id" => "native-cycles-#{Process.pid}-#{Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)}",
      "before" => before,
      "after" => after,
      "diff" => diff,
      "inventory_diff_sha256" => M2Gate.canonical_document_digest({"before" => before, "after" => after, "diff" => diff}),
      "resource_kinds" => kinds,
      "required_resource_kinds" => RESOURCE_KINDS,
      "missing_resource_kinds" => (RESOURCE_KINDS - kinds).sort,
      "profile_status" => (RESOURCE_KINDS - kinds).empty? && after.empty? ? "PASS" : "INCOMPLETE",
      "live_leak_count" => after.length,
      "orphan_count" => 0,
      "live_wrong_deletion_count" => 0,
      "cycle_count" => cycles.length,
      "adapter_class" => "Rubernetes::Platform::Linux::NativeAdapters",
      "measurement_source" => "production_native_l3_cycles"
    }
    cycles.each do |cycle|
      cycle["cycle_id"] = format("m2-native-cycle-%04d", cycle.fetch("cycle"))
      cycle["measurement_id"] = cycle.fetch("cycle_id")
      cycle["inventory_measurement_id"] = measurement.fetch("measurement_id")
      cycle["active_inventory_measurement_id"] = measurement.fetch("measurement_id")
    end
    {"cycles" => cycles, "inventory_measurement" => measurement, "resource_reuse_count" => reuse_count,
     "kernel_leak_scan" => leak_scan, "limits_evidence" => limits_evidence, "image" => image.provenance}
  end

  # Every ledger cycle runs with real cgroup limits (§5.8.8); the expected
  # values come from the production v1.36.2 formulas and are recomputed by
  # the gate from the raw requests/limits.
  LEDGER_CONTAINER_RESOURCES = {
    "requests" => {"cpu" => "250m", "memory" => "64Mi"},
    "limits" => {"cpu" => "500m", "memory" => "128Mi"}
  }.freeze
  LEDGER_PIDS_LIMIT = 64
  LEDGER_POD_SPEC = {
    "containers" => [{"name" => "main", "resources" => LEDGER_CONTAINER_RESOURCES}]
  }.freeze

  def ledger_limits_evidence
    require "rubernetes/runtime/native"
    resources = Rubernetes::Runtime::Native::Resources
    qos = resources.qos_class({"spec" => LEDGER_POD_SPEC})
    container = {"resources" => LEDGER_CONTAINER_RESOURCES}
    {
      "requests" => LEDGER_CONTAINER_RESOURCES.fetch("requests"),
      "limits" => LEDGER_CONTAINER_RESOURCES.fetch("limits"),
      "pids_limit" => LEDGER_PIDS_LIMIT,
      "memory_qos" => true,
      "qos" => qos,
      "expected" => resources.container_cgroup_limits(container, qos: qos, memory_qos: true, pids_limit: LEDGER_PIDS_LIMIT),
      "expected_pod" => resources.pod_cgroup_limits({"spec" => LEDGER_POD_SPEC}, qos: qos, memory_qos: true),
      "formula_source" => "pkg/kubelet/cm/helpers_linux.go (MilliCPUToQuota, MilliCPUToShares), pkg/kubelet/cm/cgroup_manager_linux.go (getCPUWeight), pkg/kubelet/kuberuntime/kuberuntime_container_linux.go (memory.high)"
    }
  end

  def native_cycle_inventory(sandbox, container, expected_limits: nil, expected_pod_limits: nil)
    owner = sandbox.identity
    workspace = sandbox.workspace
    namespace = sandbox.namespace.adapter_handle
    process = container.process
    entries = []

    mount_line = File.readlines("/proc/#{namespace.pid}/mountinfo", chomp: true).find do |line|
      line.split.fetch(4, "") == workspace.root.gsub(" ", "\\040")
    end
    raise "OverlayFS mount was not observed in namespace #{namespace.pid}" unless mount_line&.include?(" - overlay ")

    mount_fields = mount_line.split
    entries << measured_resource("mount", "#{sandbox.id}:#{mount_fields.fetch(0)}",
                                 "mount:#{sandbox.id}:#{mount_fields.fetch(0)}:#{workspace.root}", owner,
                                 "mountpoint" => workspace.root, "mountinfo" => mount_line)

    namespace.namespaces.each do |name|
      proc_name = {mount: "mnt", network: "net"}.fetch(name, name.to_s)
      link = File.readlink("/proc/#{namespace.pid}/ns/#{proc_name}")
      entries << measured_resource("ns", "#{sandbox.id}:#{name}", "ns:#{sandbox.id}:#{name}:#{link}", owner,
                                   "namespace" => name.to_s, "kernel_link" => link, "holder_pid" => namespace.pid)
    end

    [sandbox.cgroup, container.cgroup].each do |handle|
      stat = File.stat(handle.path)
      metadata = {"path" => handle.path, "device" => stat.dev, "inode" => stat.ino,
                  "subtree_control" => File.read(File.join(File.dirname(handle.path), "cgroup.subtree_control")).split.sort}
      readback = Rubernetes::Platform::Linux::CgroupV2::READBACK_FILES.to_h do |name|
        file = File.join(handle.path, name)
        [name, File.exist?(file) ? File.read(file).strip : nil]
      end
      metadata["limits_readback"] = readback
      if handle.container_id == "sandbox" && expected_pod_limits
        pod_path = File.dirname(handle.path)
        metadata["pod_limits_readback"] = expected_pod_limits.keys.to_h { |name| [name, File.read(File.join(pod_path, name)).strip] }
        metadata["expected_pod_limits"] = expected_pod_limits
        mismatch = expected_pod_limits.reject { |name, value| metadata["pod_limits_readback"][name] == value }
        raise "pod cgroup readback mismatch: #{mismatch.inspect} vs #{metadata["pod_limits_readback"].inspect}" unless mismatch.empty?
      elsif handle.container_id != "sandbox" && expected_limits
        metadata["expected_limits"] = expected_limits
        mismatch = expected_limits.reject { |name, value| readback[name] == value }
        raise "container cgroup readback mismatch: #{mismatch.inspect} vs #{readback.inspect}" unless mismatch.empty?
      end
      entries << measured_resource("cgroup", "#{sandbox.id}:#{handle.container_id}",
                                   "cgroup:#{sandbox.id}:#{stat.dev}:#{stat.ino}", owner, metadata)
    end

    workload_pid = Integer(process.workload_pid)
    workload_start = process.workload_start_time.to_s
    raise "actual workload identity is not live" unless process_start_time(workload_pid) == workload_start

    membership = File.readlines("/proc/#{workload_pid}/cgroup", chomp: true)
    expected_cgroup = container.cgroup.path.delete_prefix("/sys/fs/cgroup")
    raise "actual workload is outside its container cgroup" unless membership.any? { |line| line.end_with?(expected_cgroup) }

    command = File.binread("/proc/#{workload_pid}/cmdline").split("\0").reject(&:empty?)
    # The workload's root is the pivoted OverlayFS; /proc/<pid>/exe resolves
    # inside it, so the digest is read through the magic link rather than a
    # host pathname that no longer exists in the container.
    executable = File.readlink("/proc/#{workload_pid}/exe")
    executable_digest = "sha256:#{Digest::SHA256.file("/proc/#{workload_pid}/exe").hexdigest}"
    raise "actual workload executable digest changed" unless executable_digest == process.workload_executable_digest

    workload_status = File.binread("/proc/#{workload_pid}/status")
    security_fields = proc_status_security_fields(workload_status)
    workload_mountinfo = File.binread("/proc/#{workload_pid}/mountinfo")
    root_line = workload_mountinfo.each_line.to_a.reverse.find { |line| line.split.fetch(4, nil) == "/" }
    raise "workload root is not the pivoted OverlayFS" unless root_line && root_line.include?(" - overlay ")

    entries << measured_resource(
      "process", process.id,
      "process:#{sandbox.id}:#{workload_pid}:#{workload_start}", owner,
      "pid" => workload_pid,
      "start_time" => workload_start,
      "command" => command,
      "executable" => executable,
      "executable_digest" => executable_digest,
      "cgroup_path" => container.cgroup.path,
      "cgroup_membership" => membership,
      "pid_namespace" => File.readlink("/proc/#{workload_pid}/ns/pid"),
      "mount_namespace" => File.readlink("/proc/#{workload_pid}/ns/mnt"),
      "user_namespace" => File.readlink("/proc/#{workload_pid}/ns/user"),
      "cgroup_namespace" => File.readlink("/proc/#{workload_pid}/ns/cgroup"),
      "creation_method" => process.workload_creation_method,
      "clone_flags" => process.workload_clone_flags,
      "security" => security_fields,
      "root_mount_id" => Integer(root_line.split.fetch(0)),
      "root_filesystem" => "overlay",
      "mount_count" => workload_mountinfo.lines.length,
      "mountinfo_sha256" => Digest::SHA256.hexdigest(workload_mountinfo),
      "readiness" => process.workload_security
    )
    {"namespace" => namespace.pidfd, "wrapper" => process.pidfd,
     "workload" => process.workload_pidfd}.each do |role, fd|
      raise "#{role} pidfd was not created" unless fd

      link = File.readlink("/proc/self/fd/#{fd}")
      raise "#{role} descriptor #{fd} is not a pidfd" unless link.include?("pidfd")

      fdinfo = File.binread("/proc/self/fdinfo/#{fd}")
      entries << measured_resource("pidfd", "#{sandbox.id}:#{role}", "pidfd:#{sandbox.id}:#{role}:#{fdinfo.lines.grep(/\APid:/).join.strip}", owner,
                                   "fd" => fd, "fd_link" => link, "fdinfo_sha256" => Digest::SHA256.hexdigest(fdinfo))
    end

    {"root" => workspace.root, "upper" => workspace.upper, "work" => workspace.work}.each do |role, path|
      stat = File.stat(path)
      entries << measured_resource("temp", "#{sandbox.id}:#{role}", "temp:#{sandbox.id}:#{stat.dev}:#{stat.ino}", owner,
                                   "role" => role, "path" => path, "device" => stat.dev, "inode" => stat.ino)
    end
    entries.freeze
  end

  def native_cycle_residual_inventory(sandbox, container)
    owner = sandbox.identity
    residual = []
    workspace = sandbox.workspace
    {"root" => workspace.root, "upper" => workspace.upper, "work" => workspace.work}.each do |role, path|
      next unless File.exist?(path)

      residual << measured_resource("temp", "#{sandbox.id}:#{role}:residual", "temp:residual:#{path}", owner, "path" => path)
    end
    [sandbox.cgroup, container.cgroup].each do |handle|
      next unless File.exist?(handle.path)

      residual << measured_resource("cgroup", "#{sandbox.id}:#{handle.container_id}:residual",
                                    "cgroup:residual:#{handle.path}", owner, "path" => handle.path)
    end
    namespace = sandbox.namespace.adapter_handle
    if File.exist?("/proc/#{namespace.pid}")
      residual << measured_resource("ns", "#{sandbox.id}:residual", "ns:residual:#{namespace.pid}", owner, "pid" => namespace.pid)
    end
    process = container.process
    if File.exist?("/proc/#{process.pid}")
      residual << measured_resource("process", "#{process.id}:wrapper:residual", "process:residual:#{process.pid}", owner,
                                    "pid" => process.pid)
    end
    if process.workload_pid && process_start_time(process.workload_pid) == process.workload_start_time.to_s
      residual << measured_resource("process", "#{process.id}:workload:residual",
                                    "process:residual:#{process.workload_pid}", owner,
                                    "pid" => process.workload_pid,
                                    "start_time" => process.workload_start_time)
    end
    {"namespace" => namespace.pidfd, "wrapper" => process.pidfd,
     "workload" => process.workload_pidfd}.each do |role, fd|
      next unless fd && File.exist?("/proc/self/fd/#{fd}")

      residual << measured_resource("pidfd", "#{sandbox.id}:#{role}:residual", "pidfd:residual:#{role}:#{fd}", owner, "fd" => fd)
    end
    residual.freeze
  end

  def measured_resource(kind, id, identity, owner, metadata = {})
    {"kind" => kind, "id" => String(id), "identity" => String(identity), "owner" => String(owner), "metadata" => metadata}
  end

  # In-process transport for the real API::Server store.  It preserves the
  # KubernetesClient streaming interface and records requests/events without
  # inserting objects into the watch queue itself.
  class NativeAPITransport
    class WatchBody
      include Enumerable

      def initialize(stream, observer:, on_close:)
        @stream = stream
        @observer = observer
        @on_close = on_close
        @mutex = Mutex.new
        @condition = ConditionVariable.new
        @closed = false
        @stream_closed = false
        @close_in_progress = false
        @close_succeeded = false
        @close_finished = false
        @close_error = nil
        @active_deliveries = 0
        @delivery_depth = Hash.new(0)
      end

      def each
        return enum_for(__method__) unless block_given?

        begin
          @stream.each_json_line(timeout: nil) do |line|
            break unless reserve_delivery

            begin
              event = JSON.parse(line)
              @observer.call(event)
            ensure
              release_delivery
            end

            # Closing suppresses consumer delivery. Reservation and the state
            # check happen under one mutex so no consumer callback can begin
            # after close has linearized.
            break unless reserve_delivery

            begin
              yield line
            ensure
              release_delivery
            end
          end
        ensure
          # EOF, parser/consumer errors, and a consumer break all pass through
          # this path.  Closing here also unregisters the body from the
          # transport so the ownership count cannot retain an exhausted watch.
          primary_error = $ERROR_INFO
          begin
            close
          rescue StandardError => cleanup_error
            raise unless primary_error

            Rubernetes::Cleanup.attach(primary_error, [cleanup_error])
          end
        end
        self
      end

      def closed?
        @mutex.synchronize { @closed }
      end

      def close
        owner = false
        @mutex.synchronize do
          return self if @close_succeeded

          if @close_in_progress
            @condition.wait(@mutex) while @close_in_progress
            return self if @close_succeeded
          end

          @closed = true
          @close_in_progress = true
          owner = true
        end
        return self unless owner

        errors = []
        unless @stream_closed
          begin
            @stream.close if @stream.respond_to?(:close)
            @stream_closed = true
          rescue StandardError => error
            errors << error
          end
        end
        if errors.empty?
          wait_for_deliveries
          begin
            @on_close.call(self)
          rescue StandardError => error
            errors << error
          end
        end

        cleanup_error = if errors.empty?
                          nil
                        elsif errors.length == 1
                          errors.first
                        else
                          Rubernetes::Cleanup.aggregate(errors, operation: "watch body close")
                        end
        @mutex.synchronize do
          @close_error = cleanup_error
          @close_succeeded = cleanup_error.nil?
          @close_in_progress = false
          @close_finished = @close_succeeded
          @condition.broadcast
        end
        raise cleanup_error if cleanup_error

        self
      end

      private

      def reserve_delivery
        @mutex.synchronize do
          next false if @closed

          thread = Thread.current
          @active_deliveries += 1
          @delivery_depth[thread] += 1
          true
        end
      end

      def release_delivery
        @mutex.synchronize do
          thread = Thread.current
          @active_deliveries -= 1
          @delivery_depth[thread] -= 1
          @delivery_depth.delete(thread) if @delivery_depth[thread].zero?
          @condition.broadcast if @active_deliveries.zero?
        end
      end

      # Close waits for deliveries already reserved by other threads. A close
      # invoked by a callback is allowed to return after that callback releases
      # its own reservation, avoiding self-deadlock while still preventing any
      # later callback from starting.
      def wait_for_deliveries
        @mutex.synchronize do
          own_deliveries = @delivery_depth.fetch(Thread.current, 0)
          @condition.wait(@mutex) while @active_deliveries > own_deliveries
        end
      end
    end

    def initialize(server)
      @server = server
      @request_events = []
      @watch_events = []
      @watch_bodies = []
      @mutex = Mutex.new
      @closed = false
    end

    def request(method, path, body: nil, headers: {}, query: nil)
      record_request(method, path, query)
      response = @server.call(
        method: method, path: path, body: normalize_body(body),
        headers: {"User-Agent" => "rubernetes-m2-agent"}.merge(headers || {}), query: query
      )
      body_value = if response.body.respond_to?(:each_json_line)
                     body = WatchBody.new(
                       response.body,
                       observer: ->(event) { record_watch_event(event) },
                       on_close: ->(watch_body) { unregister_watch_body(watch_body) }
                     )
                     close_immediately = @mutex.synchronize do
                       if @closed
                         true
                       else
                         @watch_bodies << body
                         false
                       end
                     end
                     body.close if close_immediately
                     body
                   else
                     response.body
                   end
      Rubernetes::API::Response.new(status: response.status, headers: response.headers, body: body_value)
    end

    def stream(method, path, body: nil, headers: {}, query: nil, &)
      response = request(method, path, body: body, headers: headers, query: query)
      return response unless block_given?

      response.body.each(&)
      response
    end

    def request_events
      @mutex.synchronize { JSON.parse(JSON.generate(@request_events)) }
    end

    def watch_events
      @mutex.synchronize { JSON.parse(JSON.generate(@watch_events)) }
    end

    def active_watch_count
      @mutex.synchronize { @watch_bodies.length }
    end

    # Close every response body opened by a production watch.  This is
    # separate from SyncLoop#stop because the transport owns the stream and
    # must be able to interrupt a blocked each_json_line call during shutdown.
    def close
      bodies = @mutex.synchronize do
        @closed = true
        @watch_bodies.dup
      end
      errors = []
      bodies.each do |body|
        body.close
      rescue StandardError => error
        # Close every registered watch even when one stream is already
        # broken; report cleanup failure after all ownership hooks ran.
        errors.concat(Array(error.respond_to?(:cleanup_errors) ? error.cleanup_errors : error))
      end
      aggregate = Rubernetes::Cleanup.aggregate(errors, operation: "NativeAPITransport close")
      raise aggregate if aggregate

      self
    end

    private

    def record_request(method, path, query)
      event = {
        "sequence" => nil, "method" => String(method).upcase, "path" => String(path),
        "query" => (query || {}).to_h.transform_keys(&:to_s)
      }
      @mutex.synchronize do
        event["sequence"] = @request_events.length + 1
        @request_events << event
      end
    end

    def record_watch_event(event)
      value = event.respond_to?(:to_h) ? event.to_h : event
      record = {
        "sequence" => nil,
        "type" => value["type"],
        "resource_version" => value.dig("object", "metadata", "resourceVersion"),
        "uid" => value.dig("object", "metadata", "uid"),
        "name" => value.dig("object", "metadata", "name")
      }
      @mutex.synchronize do
        record["sequence"] = @watch_events.length + 1
        @watch_events << record
      end
    end

    def unregister_watch_body(body)
      @mutex.synchronize { @watch_bodies.delete(body) }
    end

    def normalize_body(body)
      return body unless body.is_a?(String)

      JSON.parse(body)
    rescue JSON::ParserError
      body
    end
  end

  def subresource_e2e_measurement
    require_relative "m1_probe_support"
    require "rubernetes/api"
    require "rubernetes/bootstrap"
    require "rubernetes/client"
    require "rubernetes/node"
    require "rubernetes/runtime/native"
    require "rubernetes/transport"

    responses = {}
    flow = {}
    phase_events = []
    phase_mark = lambda do |phase, status = "started", details = {}|
      phase_events << {
        "phase" => String(phase),
        "status" => String(status),
        "at" => Time.now.utc.iso8601(6)
      }.merge(details.transform_keys(&:to_s))
      flow["phase_events"] = phase_events.map(&:dup)
    end
    phase_mark.call("bootstrap")
    raise "production Native L3 subresource probe requires root" unless Process.uid.zero?

    image = pinned_image
    image.image

    Dir.mktmpdir("rubernetes-m2-subresources-") do |directory|
      sandbox_root = File.join(directory, "sandboxes")
      adapters = Rubernetes::Platform::Linux::NativeAdapters.for_profile(
        profile: :l3, sandbox_root: sandbox_root, cgroup_root: "/sys/fs/cgroup",
        architecture: architecture_name
      )
      observer = NativeKernelObserver.new(directory: File.join(directory, "kernel-observer"))
      runtime = Rubernetes::Runtime::Native.new(
        profile: :l3, l3: true,
        adapters: adapters.merge(
          image: image_verifier,
          observer: observer,
          cleaner: ->(resource) { observer.cleanup_resource(resource) }
        ),
        sandbox_root: sandbox_root, cgroup_root: "/sys/fs/cgroup",
        log_root: File.join(directory, "logs"),
        journal_path: File.join(directory, "journal.jsonl"),
        security_context: {"allow_privilege_escalation" => false, "seccomp" => "RuntimeDefault"}
      )
      lifecycle = Rubernetes::Node::Lifecycle.new(
        runtime: runtime, image_resolver: image,
        state_store: File.join(directory, "node-lifecycle.json")
      )
      # Use the production resolver so AgentService#start owns endpoint
      # registration.  A plain Hash would let this probe bypass the startup
      # registration barrier and would not prove API-to-agent routing.
      node_resolver = Rubernetes::API::SubresourceBridge::NodeResolver.new
      allow = ->(**_context) { true }
      registered_core, = M1ProbeSupport.build_api_server
      api_core = Rubernetes::API::Server.new(
        namespace_lifecycle: true,
        registry: registered_core.registry, store: registered_core.store,
        openapi_root: File.join(ROOT, "generated/openapi"),
        node_resolver: node_resolver, authorizer: allow,
        identity_resolver: ->(request) { request.header("x-rubernetes-identity") }
      )
      api_transport = NativeAPITransport.new(api_core)
      kubernetes_client = Rubernetes::Client::KubernetesClient.new(rest_client: api_transport)
      source = Rubernetes::Node::APIClientAdapter.new(client: kubernetes_client, node_name: "m2-node")
      worker_errors = []
      workers = Rubernetes::Node::PodWorkerPool.new(
        reconcile: ->(pod, **options) { lifecycle.reconcile(pod, **options) },
        error_handler: ->(uid, error) { worker_errors << {"uid" => uid, "error" => error.message} }
      )
      sync_loop = Rubernetes::Node::SyncLoop.new(
        source: source,
        worker_pool: workers,
        node_name: "m2-node",
        resync_period: 60,
        watch_timeout: 5,
        error_handler: lambda { |error, event = nil|
          worker_errors << {"uid" => "sync-loop", "error" => error.message, "backtrace" => error.backtrace&.first(8), "event" => event}
        }
      )
      node_agent = Rubernetes::Node::Agent.new(
        node_name: "m2-node",
        api: source,
        runtime: runtime,
        lifecycle: lifecycle,
        sync_loop: sync_loop,
        # The production lease loop paces itself on an interruptible
        # condition wait; an injected sleeper would either spin (no-op,
        # starving the pod worker of every syscall) or block Agent#stop.
        clock: -> { Time.now.utc }
      )
      logger = Object.new
      %i[debug info warn error].each { |name| logger.define_singleton_method(name) { |_event, **_fields| true } }
      # The default streaming port is the well-known kubelet port, which is
      # taken on any host already running a cluster.  A probe binds a port of
      # its own so the trace measures the agent, not the host's occupancy.
      streaming_port = Socket.open(:INET, :STREAM) do |socket|
        socket.bind(Addrinfo.tcp("127.0.0.1", 0))
        socket.local_address.ip_port
      end
      agent = Rubernetes::Bootstrap::AgentService.new(
        config: {"node_name" => "m2-node",
                 "streaming" => {"host" => "127.0.0.1", "port" => streaming_port}}, logger: logger,
        runtime: runtime, node_agent: node_agent, authorizer: allow,
        node_resolver: node_resolver,
        runtime_observer: observer,
        runtime_cleaner: ->(resource) { observer.cleanup_resource(resource) }
      )
      server = Rubernetes::Transport::HTTPServer.new(api_core, port: 0, max_response_bytes: 2 * 1024 * 1024)
      server.start
      begin
        bootstrap_objects = [
          ["/api/v1/nodes", {"apiVersion" => "v1", "kind" => "Node",
                             "metadata" => {"name" => "m2-node"}}],
          ["/api/v1/namespaces", {"apiVersion" => "v1", "kind" => "Namespace",
                                  "metadata" => {"name" => "kube-node-lease"}}],
          ["/apis/coordination.k8s.io/v1/namespaces/kube-node-lease/leases",
           {"apiVersion" => "coordination.k8s.io/v1", "kind" => "Lease",
            "metadata" => {"name" => "m2-node", "namespace" => "kube-node-lease"},
            "spec" => {"holderIdentity" => "m2-node"}}]
        ]
        bootstrap_objects.each_with_index do |(path, object), index|
          response = probe_http_request(
            server, "POST", path, request_id: "m2-bootstrap-#{index}",
                                  body: JSON.generate(object), content_type: "application/json", identity: nil
          )
          # System namespaces exist from API server start; re-creating one is
          # the only expected conflict here.
          next if response.code == "409" && path == "/api/v1/namespaces"
          raise "Agent API bootstrap #{path} failed with HTTP #{response.code}: #{response.body}" unless response.code == "201"
        end
        phase_mark.call("bootstrap", "passed", "server_port" => server.port)
        phase_mark.call("agent_start")
        agent.start
        begin
          wait_for_probe_condition("AgentService registration", timeout: 10) do
            agent.ready? && node_agent.registered? && sync_loop.started? &&
              node_resolver.resolve(node_name: "m2-node").equal?(agent)
          end
        rescue RuntimeError => error
          raise "#{error.message}: agent_started=#{agent.started?} agent_ready=#{agent.ready?} " \
                "node_registered=#{node_agent.registered?} node_ready=#{node_agent.ready?} " \
                "sync_started=#{sync_loop.started?} sync_running=#{sync_loop.running?} " \
                "resolver=#{node_resolver.resolve(node_name: "m2-node").class} " \
                "startup_error=#{node_agent.startup_error&.message} sync_errors=#{sync_loop.errors.inspect}"
        end
        phase_mark.call("agent_start", "passed", "registered" => node_agent.registered?, "sync_running" => sync_loop.running?)
        manifest = {
          "apiVersion" => "v1", "kind" => "Pod",
          "metadata" => {"name" => "m2-subresource-probe"},
          "spec" => {
            "nodeName" => "m2-node",
            "terminationGracePeriodSeconds" => 2,
            "containers" => [{
              "name" => "app", "image" => image.reference,
              "command" => [
                "/bin/busybox", "sh", "-c",
                "echo logs-ok; " \
                "(while :; do echo port-ok | /bin/busybox nc -l -p 18080; done) & " \
                "while :; do echo attach-ok; /bin/busybox sleep 1; done"
              ]
            }]
          }
        }
        phase_mark.call("apply")
        applied = probe_http_request(
          server, "PATCH", "/api/v1/namespaces/default/pods/m2-subresource-probe?fieldManager=m2-probe",
          request_id: "m2-apply", body: JSON.generate(manifest),
          content_type: "application/apply-patch+yaml", identity: nil
        )
        raise "Pod apply failed with HTTP #{applied.code}" unless applied.code == "201"

        applied_pod = JSON.parse(applied.body)
        phase_mark.call("apply", "passed", "http_status" => Integer(applied.code))
        flow["apply_http_status"] = Integer(applied.code)
        flow["apply_observed_at"] = Time.now.utc.iso8601(6)
        watched_pod = applied_pod
        phase_mark.call("apply_watch_reconciliation")
        begin
          # Native L3 startup crosses several real kernel barriers (workspace,
          # namespace, mount readback, cgroup, and pidfd gate). The timeout is
          # bounded per phase rather than inherited from the old 90-second
          # process-wide probe; this leaves enough room for a loaded host while
          # still failing deterministically when the lifecycle makes no progress.
          wait_for_probe_condition(
            "Apply watch reconciliation",
            timeout: 45,
            stall_timeout: 15,
            progress: lambda {
              record = lifecycle.record(watched_pod)
              sandbox_state = begin
                sandbox_id = record && record[:sandbox_id]
                sandbox_id ? runtime.sandbox(sandbox_id).state.to_s : nil
              rescue StandardError
                nil
              end
              [
                record&.slice(:state, :phase, :sandbox_id, :error),
                runtime.events.length,
                sandbox_state
              ]
            }
          ) do
            record = lifecycle.record(watched_pod)
            record && record.fetch(:phase) == "Running"
          end
        rescue RuntimeError => error
          lifecycle_record = lifecycle.record(watched_pod)
          phase_mark.call(
            "apply_watch_reconciliation", "failed",
            "error" => error.message,
            "lifecycle_state" => lifecycle_record&.slice(:state, :phase, :error, :sandbox_id)
          )
          raise "#{error.message}; worker_errors=#{worker_errors.inspect}; " \
                "sync_errors=#{sync_loop.errors.inspect}; requests=#{api_transport.request_events.inspect}; " \
                "watch_events=#{api_transport.watch_events.inspect}; " \
                "lifecycle_state=#{lifecycle_record&.slice(:state, :phase, :error, :sandbox_id).inspect}; " \
                "lifecycle_records=#{lifecycle.records.transform_values do |record|
                  record.slice(:state, :phase, :error, :sandbox_id)
                end.inspect}; " \
                "watched_uid=#{watched_pod.dig("metadata", "uid").inspect}; " \
                "phase_events=#{phase_events.inspect}"
        end
        phase_mark.call("apply_watch_reconciliation", "passed", "lifecycle_phase" => lifecycle.record(watched_pod)&.fetch(:phase))
        raise "Node worker failed the apply watch event: #{worker_errors.inspect}" unless worker_errors.empty?

        started = lifecycle.record(watched_pod)
        raise "Node Lifecycle did not retain the applied Pod" unless started
        raise "Node Lifecycle did not start the applied Pod: #{started[:error]}" unless started.fetch(:phase) == "Running"

        record = lifecycle.record(watched_pod)
        container = Array(record&.fetch(:containers)).find { |entry| entry.fetch(:name) == "app" }
        raise "Node Lifecycle did not publish the app container" unless container

        runtime_container = runtime.container_status(container.fetch(:id))
        runtime_sandbox = runtime.sandbox(record.fetch(:sandbox_id))
        runtime_container_object = runtime_sandbox.container(container.fetch(:id))
        observer.capture(
          runtime: runtime, sandbox: runtime_sandbox, container: runtime_container_object,
          role: "subresource", agent_pid: Process.pid
        )
        kernel_process = observer.list_resources.find do |resource|
          resource["kind"] == "process" && resource.dig("metadata", "observer_role") == "subresource"
        end
        raise "subresource workload kernel process was not observed" unless kernel_process

        flow.merge!(
          "lifecycle_started_at" => Time.now.utc.iso8601(6),
          "apply_preceded_lifecycle" => true,
          "node_lifecycle_class" => lifecycle.class.name,
          "node_agent_class" => node_agent.class.name,
          "agent_service_class" => agent.class.name,
          "agent_start_path" => "Rubernetes::Bootstrap::AgentService#start",
          "agent_service_started" => agent.started?,
          "agent_service_ready" => agent.ready?,
          "node_endpoint_registered" => node_resolver.resolve(node_name: "m2-node").equal?(agent),
          "node_resolver_class" => node_resolver.class.name,
          "api_server_class" => api_core.class.name,
          "http_server_class" => server.class.name,
          "sync_loop_class" => sync_loop.class.name,
          "watch_source_class" => source.class.name,
          "watch_event_count" => api_transport.watch_events.length,
          "watch_resource_version" => sync_loop.resource_version,
          "agent_registered" => node_agent.registered?,
          "lifecycle_started_from_watch" => true,
          "runtime_class" => runtime.class.name,
          "runtime_profile" => runtime.profile.to_s,
          "container_id" => container.fetch(:id),
          "container_state" => runtime_container.fetch("state"),
          "resolved_rootfs" => runtime_container.dig("spec", "rootfs_path"),
          "manifest_sha256" => M2Gate.canonical_document_digest(applied_pod),
          "kernel_process" => kernel_process,
          "kernel_process_sha256" => M2Gate.canonical_document_digest(kernel_process)
        )

        # The process gate reports successful exec, not completion of the
        # workload's first write. Give the log producer a bounded scheduling
        # window before taking the non-follow snapshot.
        sleep 0.1

        paths = {
          "logs" => "/api/v1/namespaces/default/pods/m2-subresource-probe/log",
          "attach" => "/api/v1/namespaces/default/pods/m2-subresource-probe/attach",
          "exec" => "/api/v1/namespaces/default/pods/m2-subresource-probe/exec?#{URI.encode_www_form([
                                                                                                       ["command",
                                                                                                        "/bin/busybox"], ["command", "echo"], ["command", "exec-ok"]
                                                                                                     ])}",
          "port_forward" => "/api/v1/namespaces/default/pods/m2-subresource-probe/portforward?ports=18080&timeout=5"
        }
        expected = {
          "logs" => "logs-ok\n", "attach" => "attach-ok\n",
          "exec" => "exec-ok\n", "port_forward" => "port-ok\n"
        }
        %w[logs attach exec port_forward].each do |name|
          request_id = "m2-api-#{name}"
          phase_mark.call(name)
          begin
            if %w[attach exec port_forward].include?(name)
              status, body = probe_http_stream_until(
                server, paths.fetch(name), request_id: request_id, marker: expected.fetch(name)
              )
            else
              response = probe_http_request(server, "GET", paths.fetch(name), request_id: request_id)
              status = response.code
              body = response.body.to_s.b
            end
          rescue StandardError => error
            phase_mark.call(name, "failed", "error" => error.message)
            raise
          end
          expected_body = expected.fetch(name).b
          passed = status == "200" && body.include?(expected_body)
          phase_mark.call(
            name,
            passed ? "passed" : "failed",
            "http_status" => Integer(status),
            "response_bytes" => body.bytesize,
            "response_preview" => body.byteslice(0, 512).inspect
          )
          responses[name] = {
            "requested" => true,
            "observed" => status == "200",
            "passed" => passed,
            "request_id" => request_id,
            "route" => paths.fetch(name),
            "server_class" => server.class.name,
            "api_server_class" => api_core.class.name,
            "agent_service_class" => agent.class.name,
            "node_resolver_class" => node_resolver.class.name,
            "node_endpoint_registered" => node_resolver.resolve(node_name: "m2-node").equal?(agent),
            "service_class" => agent.subresource(name).class.name,
            "response_sha256" => Digest::SHA256.hexdigest(body),
            "http_status" => Integer(status),
            "response_bytes" => body.bytesize,
            "response_preview" => body.byteslice(0, 512).inspect
          }
        end
        failed_subresources = responses.reject { |_name, result| result.fetch("passed") }
        unless failed_subresources.empty?
          container_stderr = begin
            runtime.logs(container.fetch(:id), stream: :stderr).to_s.b.byteslice(0, 4096).inspect
          rescue StandardError => error
            "unavailable: #{error.class}: #{error.message}"
          end
          container_status = begin
            runtime.container_status(container.fetch(:id)).slice("state", "process")
          rescue StandardError => error
            {"unavailable" => "#{error.class}: #{error.message}"}
          end
          raise "Pod subresource responses failed: #{failed_subresources.transform_values do |result|
            result.slice("http_status", "response_preview")
          end.inspect}; " \
                "container_stderr=#{container_stderr}; container_status=#{container_status.inspect}"
        end
        phase_mark.call("delete")
        deleted = probe_http_request(
          server, "DELETE", "/api/v1/namespaces/default/pods/m2-subresource-probe",
          request_id: "m2-delete"
        )
        raise "Pod delete failed with HTTP #{deleted.code}" unless deleted.code == "200"

        phase_mark.call("delete", "passed", "http_status" => Integer(deleted.code))
        flow["delete_http_status"] = Integer(deleted.code)
        phase_mark.call("delete_watch_reconciliation")
        wait_for_probe_condition(
          "Delete watch reconciliation",
          timeout: 45,
          stall_timeout: 20,
          progress: lambda {
            current = lifecycle.record(watched_pod)
            threads = Thread.list.filter_map do |thread|
              next if thread == Thread.current

              [thread.name, thread.status, Array(thread.backtrace).first(4)]
            end
            [current&.slice(:state, :phase, :cleanup_errors, :error), runtime.events.length,
             runtime.events.last(12), worker_errors.last(3), threads]
          }
        ) do
          lifecycle.record(watched_pod)&.fetch(:state) == "Removed"
        end
        phase_mark.call("delete_watch_reconciliation", "passed", "finish_state" => lifecycle.record(watched_pod)&.fetch(:state))
        raise "Node worker failed the delete watch event: #{worker_errors.inspect}" unless worker_errors.empty?

        flow["watch_event_count"] = api_transport.watch_events.length
        flow["watch_resource_version"] = sync_loop.resource_version
        flow["finish_state"] = lifecycle.record(watched_pod).fetch(:state)
        flow["api_request_events"] = api_transport.request_events
        flow["watch_events"] = api_transport.watch_events
        flow["apply_watch_binding"] = flow.fetch("watch_events").any? do |event|
          event["type"] == "ADDED" && event["name"] == "m2-subresource-probe" && event["uid"] == applied_pod.dig("metadata", "uid")
        end
        flow["delete_watch_binding"] = flow.fetch("watch_events").any? do |event|
          event["type"] == "DELETED" && event["name"] == "m2-subresource-probe" && event["uid"] == applied_pod.dig("metadata", "uid")
        end
        flow["subresource_routes"] = paths
        flow["subresource_service_classes"] = %w[logs attach exec port_forward].to_h do |name|
          [name, agent.subresource(name).class.name]
        end
        flow["api_request_events_sha256"] = M2Gate.canonical_document_digest(flow.fetch("api_request_events"))
        flow["watch_events_sha256"] = M2Gate.canonical_document_digest(flow.fetch("watch_events"))
      rescue StandardError => error
        raise "#{error.message}; phase_events=#{phase_events.inspect}"
      ensure
        phase_mark.call("stop")
        cleanup_errors = []
        [
          ["NativeAPITransport#close", -> { api_transport&.close }],
          ["AgentService#stop", -> { agent&.stop(reason: "m2 subresource probe") if agent&.started? }],
          ["HTTPServer#stop", -> { server&.stop }],
          ["Node::Lifecycle#terminate", lambda {
            lifecycle&.terminate(watched_pod || applied_pod || manifest, request_id: "m2-node-cleanup")
          }]
        ].each do |label, operation|
          Timeout.timeout(3) { operation.call }
        rescue StandardError => error
          cleanup_errors << "#{label}: #{error.message}"
        end
        remaining_watch_bodies = api_transport&.active_watch_count.to_i
        remaining_stream_monitors = server&.active_stream_monitors.to_i
        remaining_http_clients = server&.active_connections.to_i
        remaining_sync_thread = sync_loop.respond_to?(:thread_alive?) && sync_loop.thread_alive?
        remaining_agent = agent&.started? || node_agent&.running?
        cleanup_errors << "NativeAPITransport watch bodies remain: #{remaining_watch_bodies}" if remaining_watch_bodies.positive?
        cleanup_errors << "HTTPServer stream monitors remain: #{remaining_stream_monitors}" if remaining_stream_monitors.positive?
        cleanup_errors << "HTTPServer clients remain: #{remaining_http_clients}" if remaining_http_clients.positive?
        cleanup_errors << "SyncLoop watcher thread remains alive" if remaining_sync_thread
        cleanup_errors << "AgentService or Node Agent remains running" if remaining_agent
        lifecycle_after_cleanup = lifecycle&.record(watched_pod || applied_pod || manifest)
        if lifecycle_after_cleanup && lifecycle_after_cleanup[:state] != "Removed"
          cleanup_errors << "Node Lifecycle remains in #{lifecycle_after_cleanup[:state]}"
        end
        phase_mark.call("stop", cleanup_errors.empty? ? "passed" : "failed", "errors" => cleanup_errors)
        raise "subresource probe cleanup failed: #{cleanup_errors.join("; ")}" if cleanup_errors.any? && $ERROR_INFO.nil?
      end
    end
    e2e = M2Gate::REQUIRED_SUBRESOURCES.to_h { |name| [name, responses.fetch(name)] }
    [e2e, M2Gate.canonical_document_digest(e2e), flow]
  end

  def wait_for_probe_condition(label, timeout:, stall_timeout: nil, progress: nil)
    now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    deadline = now + Float(timeout)
    stall_limit = Float(stall_timeout || timeout)
    raise ArgumentError, "stall_timeout must be positive" unless stall_limit.positive?

    last_progress = progress&.call
    stall_deadline = now + stall_limit
    loop do
      return true if yield

      now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      if progress
        current_progress = progress.call
        if current_progress != last_progress
          last_progress = current_progress
          stall_deadline = now + stall_limit
        end
      end
      effective_deadline = progress ? [deadline, stall_deadline].min : deadline
      raise "#{label} timed out; progress=#{last_progress.inspect}" if now >= effective_deadline

      sleep 0.01
    end
  end

  # Execute a workload through the production Native L3 adapters.  The image
  # root is an OverlayFS lowerdir containing only a static BusyBox, making a
  # successful /bin/busybox exec direct evidence of the chroot transition.
  def with_native_l3_runtime(command:, prefix: "l3")
    require "rubernetes/runtime/native"

    raise "production Native L3 probe requires root" unless Process.uid.zero?

    image = pinned_image
    image.image

    result = nil
    Dir.mktmpdir("rubernetes-m2-#{prefix}-") do |directory|
      sandbox_root = File.join(directory, "sandboxes")
      sandbox_id = "m2-#{prefix}-#{Process.pid}-#{Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)}"
      adapters = Rubernetes::Platform::Linux::NativeAdapters.for_profile(
        profile: :l3, sandbox_root: sandbox_root, cgroup_root: "/sys/fs/cgroup",
        architecture: architecture_name
      )
      runtime = Rubernetes::Runtime::Native.new(
        profile: :l3, l3: true, adapters: adapters.merge(image: image_verifier),
        sandbox_root: sandbox_root, cgroup_root: "/sys/fs/cgroup",
        log_root: File.join(directory, "logs"),
        journal_path: File.join(directory, "journal.jsonl"),
        security_context: {"allow_privilege_escalation" => false, "seccomp" => "RuntimeDefault"}
      )
      sandbox = runtime.run_sandbox(image.runtime_input(id: sandbox_id), request_id: sandbox_id)
      container = runtime.create_container(sandbox, image.container_spec(id: "main", command: Array(command)))
      runtime.start_container(container)
      result = yield(runtime, sandbox, container)
    ensure
      active_error = $ERROR_INFO
      if runtime && sandbox && runtime.sandboxes.any?
        begin
          runtime.stop_sandbox(sandbox, timeout: 2)
          runtime.remove_sandbox(sandbox)
        rescue StandardError => cleanup_error
          raise cleanup_error unless active_error
        end
      end
      if sandbox_id
        leftover = Dir.glob(File.join("/sys/fs/cgroup/rubernetes", "*", sandbox_id))
        raise "Native L3 cleanup left cgroup #{leftover.join(", ")}" if leftover.any? && !active_error
      end
    end
    result
  end

  def native_l3_smoke_measurement(architecture: architecture_name)
    raise "architecture #{architecture} is not the current execution architecture" unless architecture == architecture_name

    measurement = {}
    # Rootfs isolation witness: the workload hashes its own /etc/passwd.  The
    # digest must be the pinned image's file (the container sees the image
    # rootfs) and must differ from the host's file (it does not see the
    # host).  An image without /etc/passwd must not see the host's either.
    image_passwd = File.join(pinned_image.rootfs.to_s, "etc", "passwd")
    image_digest = File.file?(image_passwd) ? Digest::SHA256.file(image_passwd).hexdigest : nil
    host_digest = File.file?("/etc/passwd") ? Digest::SHA256.file("/etc/passwd").hexdigest : nil
    with_native_l3_runtime(
      command: ["/bin/busybox", "sh", "-c",
                "if [ -e /etc/passwd ]; then sha256sum /etc/passwd | cut -d' ' -f1; else echo missing; fi; echo l3-ok"],
      prefix: "runtime"
    ) do |runtime, _sandbox, container|
      waited = runtime.wait_container(container, timeout: 5)
      output = runtime.logs(container)
      lines = output.lines.map(&:strip)
      observed_digest = lines[0]
      rootfs_isolated = lines[1] == "l3-ok" &&
                        (observed_digest == (image_digest || "missing")) &&
                        (host_digest.nil? || observed_digest != host_digest)
      inventory = runtime.resource_inventory.reject { |resource| resource.fetch("owner", "").empty? }
      measurement = {
        "exit_code" => waited.fetch("exitCode"),
        "stdout_sha256" => Digest::SHA256.hexdigest(output),
        "rootfs_witness" => {"observed_passwd_sha256" => observed_digest, "image_passwd_sha256" => image_digest,
                             "host_passwd_sha256" => host_digest},
        "rootfs_isolated" => rootfs_isolated,
        "inventory" => inventory,
        "inventory_sha256" => M2Gate.canonical_document_digest(inventory),
        "measurement_source" => "production_native_l3",
        "runtime_class" => "Rubernetes::Runtime::Native",
        "adapter_class" => "Rubernetes::Platform::Linux::NativeAdapters"
      }
    end
    measurement.merge("passed" => measurement["exit_code"] == 0 && measurement["rootfs_isolated"] == true)
  end

  # Capture a real before/active/after kernel inventory around one Native L3
  # workload and inspect the final workload (not the Ruby wrapper) through
  # /proc.  Landlock is verified behaviorally: a rootfs file outside the
  # allowed /bin subtree must be unreadable before the workload announces
  # readiness.
  def native_kernel_inventory_measurement(architecture: architecture_name)
    require "rubernetes/runtime/native"

    raise "architecture #{architecture} is not the current execution architecture" unless architecture == architecture_name
    raise "production Native L3 kernel inventory requires root" unless Process.uid.zero?

    image = pinned_image
    image.image

    result = nil
    Dir.mktmpdir("rubernetes-m2-kernel-") do |directory|
      # An extra (topmost) layer carries the Landlock denial witness; the
      # image layers stay byte-identical to the pulled, digest-verified rootfs.
      lower = File.join(directory, "witness-lower")
      FileUtils.mkdir_p(lower, mode: 0o755)
      File.binwrite(File.join(lower, "blocked"), "landlock-must-deny\n")
      sandbox_root = File.join(directory, "sandboxes")
      sandbox_id = "m2-kernel-#{Process.pid}-#{Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)}"
      baseline = managed_kernel_snapshot(sandbox_id: sandbox_id, sandbox_root: sandbox_root)
      adapters = Rubernetes::Platform::Linux::NativeAdapters.for_profile(
        profile: :l3, sandbox_root: sandbox_root, cgroup_root: "/sys/fs/cgroup",
        architecture: architecture, landlock_roots: PROBE_LANDLOCK_ROOTS
      )
      runtime = Rubernetes::Runtime::Native.new(
        profile: :l3, l3: true, adapters: adapters.merge(image: image_verifier),
        sandbox_root: sandbox_root, cgroup_root: "/sys/fs/cgroup",
        log_root: File.join(directory, "logs"),
        journal_path: File.join(directory, "journal.jsonl"),
        security_context: {
          "allow_privilege_escalation" => false,
          "seccomp" => "RuntimeDefault",
          "landlock" => {"readOnlyPaths" => PROBE_LANDLOCK_ROOTS}
        }
      )
      sandbox = nil
      container = nil
      begin
        sandbox_key = runtime.run_sandbox(image.runtime_input(id: sandbox_id, lowerdirs: [lower]), request_id: sandbox_id)
        sandbox = runtime.sandbox(sandbox_key)
        container = runtime.create_container(sandbox, image.container_spec(
          id: "main",
          command: [
            "/bin/busybox", "sh", "-c",
            "if /bin/busybox cat /blocked >/dev/null 2>&1; then exit 41; fi; " \
            "echo security-ready; exec /bin/busybox sleep 3600"
          ]
        ))
        container = runtime.start_container(container)
        output = "".b
        Timeout.timeout(5) do
          loop do
            output = runtime.logs(container)
            break if output.include?("security-ready\n")
            raise "Landlock denial workload exited before readiness" unless runtime.wait_container(container,
                                                                                                   timeout: 0).fetch("state") == "running"

            sleep 0.01
          end
        end

        active = native_cycle_inventory(sandbox, container)
        cgroup_pids = File.readlines(File.join(container.cgroup.path, "cgroup.procs"), chomp: true).map { |pid| Integer(pid) }
        child_pid = Integer(container.process.workload_pid)
        raise "actual clone3 workload PID was not observed in its cgroup" unless cgroup_pids.include?(child_pid)

        child_status = File.binread("/proc/#{child_pid}/status")
        # Captured while the workload is alive; the sandbox is stopped before
        # the result document is assembled.
        child_uid_map = File.read("/proc/#{child_pid}/uid_map").strip
        child_fields = proc_status_security_fields(child_status)
        unless child_fields["NoNewPrivs"] == "1" && child_fields["Seccomp"] == "2"
          raise "actual clone3 workload did not retain the required security state: #{child_fields.inspect}"
        end

        child_identity = kernel_identity_for(runtime, container.id, name: "main")
        parent_namespaces = %w[mnt pid net uts ipc cgroup user].to_h { |ns| [ns, File.readlink("/proc/self/ns/#{ns}")] }
        active_snapshot = RESOURCE_KINDS.to_h do |kind|
          [kind, active.select { |entry| entry.fetch("kind") == kind }]
        end
        runtime.stop_sandbox(sandbox, timeout: 2)
        runtime.remove_sandbox(sandbox)
        final = managed_kernel_snapshot(
          sandbox_id: sandbox_id, sandbox_root: sandbox_root,
          pids: [sandbox.namespace.adapter_handle.pid, container.process.pid,
                 container.process.workload_pid, child_pid],
          pidfds: [sandbox.namespace.adapter_handle.pidfd, container.process.pidfd,
                   container.process.workload_pidfd]
        )
        residual = native_cycle_residual_inventory(sandbox, container)
        difference_keys = RESOURCE_KINDS.reject { |kind| baseline.fetch(kind) == final.fetch(kind) }
        parent_security = proc_status_security_fields(File.binread("/proc/self/status"))
        result = {
          "baseline" => baseline,
          "active" => active_snapshot,
          "final" => final,
          "difference_keys" => difference_keys,
          "difference_count" => difference_keys.length,
          "live_leak_count" => residual.length,
          "child_security" => child_fields.merge(
            "pid" => child_pid,
            "start_time" => container.process.workload_start_time,
            "executable_digest" => container.process.workload_executable_digest,
            "creation_method" => container.process.workload_creation_method,
            "clone_flags" => container.process.workload_clone_flags,
            "cgroup_path" => container.cgroup.path,
            "cgroup_inode" => child_identity.fetch("cgroup_inode"),
            "cgroup_membership" => child_identity.fetch("cgroup_membership"),
            "blocked_read_denied" => output == "security-ready\n",
            "landlock_policy" => {"allowed_roots" => PROBE_LANDLOCK_ROOTS, "blocked_path" => "/blocked"},
            "status_sha256" => Digest::SHA256.hexdigest(child_status),
            "namespaces" => child_identity.fetch("namespaces"),
            "parent_namespaces" => parent_namespaces,
            "root_mount_id" => child_identity.fetch("root_mount_id"),
            "root_filesystem" => child_identity.fetch("root_filesystem"),
            "mount_count" => child_identity.fetch("mount_count"),
            "mountinfo_sha256" => child_identity.fetch("mountinfo_sha256"),
            "old_root_unreachable" => child_identity.dig("readiness", "rootfs", "old_root_unreachable") == true,
            "old_root_mount_ids" => child_identity.dig("readiness", "rootfs", "old_root_mount_ids"),
            "uid_map" => child_uid_map,
            "image" => image.provenance
          ),
          "parent_security" => parent_security,
          "active_inventory_sha256" => M2Gate.canonical_document_digest(active),
          "baseline_sha256" => M2Gate.canonical_document_digest(baseline),
          "final_sha256" => M2Gate.canonical_document_digest(final)
        }
      ensure
        if runtime && sandbox && runtime.sandboxes.any? { |entry| entry.fetch("id") == sandbox.id }
          begin
            runtime.stop_sandbox(sandbox, timeout: 1)
            runtime.remove_sandbox(sandbox)
          rescue StandardError
            nil
          end
        end
      end
    end
    child = result.fetch("child_security")
    result.merge(
      "passed" => result.fetch("difference_count").zero? && result.fetch("live_leak_count").zero? &&
                  child.fetch("NoNewPrivs") == "1" && child.fetch("Seccomp") == "2" &&
                  child.fetch("blocked_read_denied") == true
    )
  end

  def managed_kernel_snapshot(sandbox_id:, sandbox_root:, pids: [], pidfds: [])
    cgroups = Dir.glob(File.join("/sys/fs/cgroup/rubernetes", "**", sandbox_id, "**", "*"))
      .select { |path| File.directory?(path) }.sort
    processes = Array(pids).compact.select { |pid| File.exist?("/proc/#{pid}") }.map do |pid|
      {"pid" => pid, "start_time" => process_start_time(pid)}
    end
    descriptors = Array(pidfds).compact.filter_map do |fd|
      next unless File.exist?("/proc/self/fd/#{fd}")

      {"fd" => fd, "link" => File.readlink("/proc/self/fd/#{fd}"),
       "fdinfo_sha256" => Digest::SHA256.hexdigest(File.binread("/proc/self/fdinfo/#{fd}"))}
    end
    {
      "mount" => File.readlines("/proc/self/mountinfo", chomp: true).grep(/#{Regexp.escape(sandbox_id)}/).sort,
      "ns" => processes.filter_map do |entry|
        pid = entry.fetch("pid")
        links = %w[mnt pid net uts ipc cgroup].to_h { |name| [name, File.readlink("/proc/#{pid}/ns/#{name}")] }
        {"pid" => pid, "links" => links}
      rescue Errno::ENOENT
        nil
      end,
      "cgroup" => cgroups,
      "process" => processes,
      "pidfd" => descriptors,
      "temp" => Dir.glob(File.join(sandbox_root, "#{sandbox_id}*"), File::FNM_DOTMATCH).sort
    }
  end

  def proc_status_security_fields(status)
    keys = %w[NoNewPrivs Seccomp Seccomp_filters CapEff CapBnd]
    status.each_line.with_object({}) do |line, fields|
      key, value = line.split(":", 2)
      fields[key] = value.to_s.strip if keys.include?(key)
    end
  end

  def probe_http_request(server, method, path, request_id:, body: nil, content_type: nil, identity: "m2-probe-user")
    uri = URI("http://127.0.0.1:#{server.port}#{path}")
    http = Net::HTTP.new(uri.host, uri.port)
    http.open_timeout = 2
    http.read_timeout = 5
    request = Net::HTTP.const_get(String(method).capitalize).new(uri.request_uri)
    request["X-Request-ID"] = request_id
    request["X-Rubernetes-Identity"] = identity if identity
    request["Content-Type"] = content_type if content_type
    request.body = body if body
    http.start { |connection| connection.request(request) }
  end

  def probe_http_stream_until(server, path, request_id:, marker:, timeout: 30)
    socket = TCPSocket.new("127.0.0.1", server.port)
    request = [
      "GET #{path} HTTP/1.1", "Host: 127.0.0.1", "Connection: close",
      "X-Request-ID: #{request_id}", "X-Rubernetes-Identity: m2-probe-user", "", ""
    ].join("\r\n")
    socket.write(request)
    bytes = +"".b
    marker_bytes = String(marker).b
    begin
      Timeout.timeout(Float(timeout)) do
        loop do
          header_end = bytes.index("\r\n\r\n".b)
          if header_end
            status = bytes[%r{\AHTTP/1\.1\s+(\d{3})}, 1]
            payload = bytes.byteslice(header_end + 4, bytes.bytesize) || "".b
            header_lines = bytes.byteslice(0, header_end).to_s.split("\r\n").drop(1)
            headers = header_lines.each_with_object({}) do |line, result|
              name, value = line.split(":", 2)
              result[name.to_s.downcase] = value.to_s.strip.downcase if name
            end
            chunked = headers["transfer-encoding"].to_s.split(",").map(&:strip).include?("chunked")
            if status == "200" && chunked
              decoded, complete = decode_chunked_payload(payload)
              # Stop on the first complete response even when the requested
              # marker is absent. The terminating chunk is framing, never
              # application output, and must not be reported as evidence.
              return [status, decoded] if decoded.include?(marker_bytes) || complete
            elsif status == "200" && payload.include?(marker_bytes)
              return [status, payload]
            end
          end
          bytes << socket.readpartial(16 * 1024)
        end
      end
    rescue EOFError
      # The peer may close a non-streaming error response immediately after
      # its JSON body. Parse it below and let the caller record the real HTTP
      # status/body rather than turning a useful 503 into an opaque EOF.
    end
    status = bytes[%r{\AHTTP/1\.1\s+(\d{3})}, 1]
    raise "stream response did not contain an HTTP status" unless status

    header_end = bytes.index("\r\n\r\n".b)
    raw_body = header_end ? (bytes.byteslice(header_end + 4, bytes.bytesize) || "".b) : "".b
    header_lines = header_end ? bytes.byteslice(0, header_end).to_s.split("\r\n").drop(1) : []
    chunked = header_lines.any? do |line|
      name, value = line.split(":", 2)
      name.to_s.downcase == "transfer-encoding" && value.to_s.split(",").map { |item| item.strip.downcase }.include?("chunked")
    end
    body = if chunked
             decoded, = decode_chunked_payload(raw_body)
             decoded
           else
             raw_body
           end
    [status, body]
  rescue Timeout::Error
    raise "stream response timed out after #{bytes&.bytesize || 0} bytes: #{bytes.to_s.byteslice(0, 512).inspect}"
  ensure
    socket&.close
  end

  def decode_chunked_payload(payload)
    value = String(payload).b
    decoded = "".b
    offset = 0
    complete = false
    loop do
      line_end = value.index("\r\n".b, offset)
      break unless line_end

      size_text = value.byteslice(offset, line_end - offset).to_s.split(";", 2).first
      size = Integer(size_text, 16)
      offset = line_end + 2
      break if value.bytesize < offset + size + 2

      decoded << value.byteslice(offset, size).to_s.b
      offset += size
      raise "invalid chunk terminator" unless value.byteslice(offset, 2) == "\r\n".b

      offset += 2
      if size.zero?
        complete = true
        break
      end
    end
    [decoded, complete]
  rescue ArgumentError => error
    raise "invalid chunk size: #{error.message}"
  end

  def managed_dead_resource?(resource)
    metadata = resource["metadata"] || resource[:metadata] || {}
    metadata["managed_by"].to_s == "rubernetes" && metadata["live"] == false
  end

  def process_start_time(pid)
    stat = File.read("/proc/#{Integer(pid)}/stat")
    stat[(stat.rindex(")") + 1)..].split.fetch(19)
  rescue StandardError
    ""
  end

  def wait_for_file(path, pid, timeout: 10.0, error_path: nil)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
    until File.file?(path)
      if error_path && File.file?(error_path)
        failure = parse_json_file(error_path)
        raise "SIGKILL worker failed before barrier: #{failure["class"]}: #{failure["message"]}"
      end
      begin
        waited = Process.waitpid(pid, Process::WNOHANG)
        raise "SIGKILL worker #{pid} exited before measurement barrier #{File.basename(path)}" if waited
      rescue Errno::ECHILD
        raise "SIGKILL worker #{pid} disappeared before measurement barrier #{File.basename(path)}"
      end
      raise "SIGKILL worker #{pid} did not reach measurement barrier #{File.basename(path)}" if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline

      sleep 0.01
    end
    true
  end

  def terminate_child(pid)
    return unless pid

    begin
      Process.kill("KILL", pid)
    rescue Errno::ESRCH, Errno::ECHILD
      return
    end
    Process.wait(pid)
  rescue Errno::ESRCH, Errno::ECHILD
    nil
  end

  def parse_json_file(path)
    JSON.parse(File.binread(path))
  end

  def write_json_fsync(path, value)
    temporary = "#{path}.tmp-#{Process.pid}"
    File.open(temporary, File::WRONLY | File::CREAT | File::TRUNC, 0o600) do |file|
      file.write(JSON.generate(value) << "\n")
      file.flush
      file.fsync
    end
    File.rename(temporary, path)
    directory = File.open(File.dirname(path), File::RDONLY)
    directory.fsync
    true
  ensure
    directory&.close
    File.delete(temporary) if temporary && File.exist?(temporary)
  end

  def file_digest(path)
    File.file?(path) ? Digest::SHA256.file(path).hexdigest : Digest::SHA256.hexdigest("")
  end

  def digest_json(value)
    M2Gate.canonical_document_digest(value)
  end

  def inventory_keys(entries)
    Array(entries).filter_map do |entry|
      next unless entry.is_a?(Hash)

      "#{entry["kind"]}:#{entry["id"]}"
    end
  end

  # Inventory multiplicity is part of the observation. Reject a duplicate
  # identity before any aggregation can erase it and make a forged count look
  # like a clean lifecycle.
  def assert_unique_inventory_identities!(entries, label = "inventory")
    seen = {}
    duplicates = []
    Array(entries).each do |entry|
      identity = entry.is_a?(Hash) ? entry["identity"] : nil
      next unless identity.is_a?(String) && !identity.empty?

      duplicates << identity if seen.key?(identity)
      seen[identity] = true
    end
    return true if duplicates.empty?

    raise "#{label} contains duplicate raw inventory identities: #{duplicates.uniq.sort.join(", ")}"
  end

  def dead_residuals(entries)
    Array(entries).count { |entry| managed_dead_resource?(entry) }
  end

  def start_native_agent(directory:, observer:, effect_hook: nil)
    require File.join(ROOT, "lib/rubernetes/node")
    require File.join(ROOT, "lib/rubernetes/runtime/native")

    sandbox_root = File.join(directory, "native-agent-sandboxes")
    adapters = Rubernetes::Platform::Linux::NativeAdapters.for_profile(
      profile: :l3,
      sandbox_root: sandbox_root,
      cgroup_root: "/sys/fs/cgroup",
      architecture: architecture_name
    ).merge(
      image: image_verifier,
      observer: observer,
      cleaner: ->(resource) { observer.cleanup_resource(resource) }
    )
    adapters[:effect_hook] = effect_hook if effect_hook
    runtime = Rubernetes::Runtime::Native.new(
      profile: :l3,
      l3: true,
      adapters: adapters,
      sandbox_root: sandbox_root,
      cgroup_root: "/sys/fs/cgroup",
      journal_path: File.join(directory, "native-agent.wal"),
      security_context: {"allow_privilege_escalation" => false, "seccomp" => "RuntimeDefault"}
    )
    lifecycle = Rubernetes::Node::Lifecycle.new(
      runtime: runtime,
      state_store: File.join(directory, "native-agent-state.json")
    )
    api = NativeAgentAPI.new
    agent = Rubernetes::Node::Agent.new(
      node_name: "m2-native-agent",
      api: api,
      runtime: runtime,
      lifecycle: lifecycle,
      clock: -> { Time.now.utc }
    )
    # Drive the actual Agent startup barrier and its production SyncLoop once
    # without starting a background watcher in the crash child.
    agent.run_once(events: [], resync: false)
    NativeAgentSession.new(agent: agent, runtime: runtime, lifecycle: lifecycle)
  end

  # Independent crash observer.  Capture persists immutable identities while
  # the Agent is alive; every subsequent list re-reads the kernel.  It never
  # accepts a caller-supplied liveness value and cannot manufacture a guard.
  class NativeKernelObserver
    MANIFEST_GLOB = "*-kernel-manifest.json"

    def initialize(directory:)
      @directory = File.expand_path(directory)
      FileUtils.mkdir_p(@directory)
    end

    def external_observer?
      true
    end

    def capture(runtime:, sandbox:, container:, role:, agent_pid:)
      process = container.process
      namespace = sandbox.namespace.adapter_handle
      owner = sandbox.identity
      resources = runtime.ledger.resources(owner: owner, include_released: false).map do |resource|
        enrich_ledger_resource(resource, sandbox: sandbox, container: container,
                                         process: process, namespace: namespace, role: role,
                                         agent_pid: agent_pid)
      end
      resources.concat(derived_kernel_resources(sandbox, container, role: role, agent_pid: agent_pid))
      manifest = {
        "schema" => "rubernetes.m2.native-kernel-observer.v1",
        "role" => String(role),
        "agent_pid" => Integer(agent_pid),
        "agent_start_time" => M2ProbeSupport.process_start_time(agent_pid),
        "sandbox_id" => sandbox.id,
        "owner" => owner,
        "workload_pid" => process.workload_pid,
        "workload_start_time" => process.workload_start_time,
        "liveness_pid" => process.workload_pid,
        "liveness_start_time" => process.workload_start_time,
        "workload_executable_digest" => process.workload_executable_digest,
        "entries" => resources.sort_by { |entry| [entry.fetch("kind"), entry.fetch("id")] }
      }
      M2ProbeSupport.write_json_fsync(manifest_path(role), manifest)
      manifest
    end

    # Persist the exact kernel identities present immediately after a Native
    # sandbox effect transition.  Early effect points intentionally have no
    # workload process: their liveness is tied to the Agent before namespace
    # creation and to the namespace holder afterwards.
    def capture_effect(runtime:, sandbox:, role:, agent_pid:, effect_point:)
      namespace = sandbox.namespace&.adapter_handle
      liveness_pid = namespace&.pid || agent_pid
      liveness_start_time = namespace&.start_time || M2ProbeSupport.process_start_time(agent_pid)
      owner = sandbox.identity
      resources = runtime.ledger.resources(owner: owner, include_released: false).map do |resource|
        enrich_effect_resource(resource, sandbox: sandbox, namespace: namespace, role: role)
      end
      resources.concat(derived_effect_resources(sandbox, namespace, role: role, agent_pid: agent_pid))
      manifest = {
        "schema" => "rubernetes.m2.native-kernel-observer.v1",
        "role" => String(role),
        "effect_point" => String(effect_point),
        "agent_pid" => Integer(agent_pid),
        "agent_start_time" => M2ProbeSupport.process_start_time(agent_pid),
        "sandbox_id" => sandbox.id,
        "owner" => owner,
        "workload_pid" => nil,
        "workload_start_time" => nil,
        "liveness_pid" => liveness_pid,
        "liveness_start_time" => liveness_start_time,
        "entries" => resources.sort_by { |entry| [entry.fetch("kind"), entry.fetch("id")] }
      }
      M2ProbeSupport.write_json_fsync(manifest_path(role), manifest)
      manifest
    end

    def list_resources
      entries = manifests.flat_map do |manifest|
        Array(manifest.fetch("entries")).filter_map { |entry| observe_entry(entry, manifest) }
      end.sort_by { |entry| [entry.fetch("kind"), entry.fetch("id"), entry.fetch("identity")] }
      M2ProbeSupport.assert_unique_inventory_identities!(entries, "Native kernel observer inventory")
      entries
    end

    alias resources list_resources

    def cleanup_resource(resource)
      value = stringify(resource)
      manifest, expected = find_expected(value.fetch("kind"), value.fetch("id"))
      raise "unowned kernel resource #{value.fetch("kind")}:#{value.fetch("id")}" unless expected
      unless expected.fetch("identity") == value.fetch("identity") && expected.fetch("owner") == value.fetch("owner")
        raise "kernel resource identity changed before cleanup"
      end

      observed = observe_entry(expected, manifest)
      return true if observed.nil? && exact_resource_absent?(expected)
      raise "kernel resource identity changed or became unverifiable before cleanup" unless observed
      raise "refusing to cleanup a live kernel resource" unless observed.dig("metadata", "live") == false

      case value.fetch("kind")
      when "process", "namespace"
        raise "refusing to signal a stable live process" if stable_process?(expected.dig("metadata", "pid"),
                                                                            expected.dig("metadata", "start_time"))
      when "cgroup"
        cleanup_cgroup(expected)
      when "workspace"
        cleanup_workspace(expected)
      else
        raise "observer cleanup does not own #{value.fetch("kind")} resources"
      end
      true
    end

    def live_guard_present?
      manifests.select { |manifest| manifest["role"] == "guard" }.any? do |manifest|
        stable_process?(manifest["workload_pid"], manifest["workload_start_time"])
      end
    end

    def dead_residual_count
      manifests.select { |manifest| manifest["role"] == "victim" }.sum do |manifest|
        Array(manifest["entries"]).count { |entry| !observe_entry(entry, manifest).nil? }
      end
    end

    private

    def exact_resource_absent?(entry)
      metadata = stringify(entry.fetch("metadata"))
      case entry.fetch("kind")
      when "process", "namespace"
        !stable_process?(metadata["pid"], metadata["start_time"])
      when "cgroup"
        !File.exist?(metadata.fetch("path"))
      when "workspace"
        metadata.fetch("workspace_stats").keys.none? { |path| File.exist?(path) }
      else
        false
      end
    end

    def manifest_path(role)
      File.join(@directory, "#{role}-kernel-manifest.json")
    end

    def manifests
      Dir.glob(File.join(@directory, MANIFEST_GLOB)).map do |path|
        JSON.parse(File.binread(path))
      end
    end

    def find_expected(kind, id)
      manifests.each do |manifest|
        entry = Array(manifest["entries"]).find { |item| item["kind"] == kind && item["id"] == id }
        return [manifest, entry] if entry
      end
      [nil, nil]
    end

    def enrich_ledger_resource(resource, sandbox:, container:, process:, namespace:, role:, agent_pid:)
      value = stringify(resource)
      durable_metadata = stringify(value.fetch("metadata", {}))
      metadata = common_metadata(role)
      case value.fetch("kind")
      when "workspace"
        workspace = sandbox.workspace
        metadata.merge!(
          "root" => workspace.root, "upper" => workspace.upper, "work" => workspace.work,
          "workspace_stats" => path_stats([workspace.root, workspace.upper, workspace.work]),
          "probe_type" => "workspace"
        )
      when "namespace"
        metadata.merge!(
          namespace.to_h,
          "pid" => namespace.pid, "start_time" => namespace.start_time,
          "namespace_links" => namespace.namespace_links,
          "creation_method" => namespace.creation_method,
          "clone_flags" => namespace.clone_flags,
          "probe_type" => "process"
        )
      when "cgroup"
        path = durable_metadata.fetch("path")
        stat = File.stat(path)
        metadata.merge!("path" => path, "device" => stat.dev, "inode" => stat.ino,
                        "members" => cgroup_members(path), "probe_type" => "cgroup")
      when "process"
        pid = process.workload_pid
        metadata.merge!(
          "pid" => pid, "start_time" => process.workload_start_time,
          "command" => process.command,
          "executable_digest" => process.workload_executable_digest,
          "cgroup_path" => container.cgroup.path,
          "cgroup_membership" => proc_cgroup(pid),
          "pid_namespace" => namespace_link(pid, "pid"),
          "mount_namespace" => namespace_link(pid, "mnt"),
          "workload_pidfd" => process.workload_pidfd,
          "workload_pidfd_link" => fd_link(agent_pid, process.workload_pidfd),
          "workload_pidfd_info_sha256" => fdinfo_digest(agent_pid, process.workload_pidfd),
          "creation_method" => process.workload_creation_method,
          "clone_flags" => process.workload_clone_flags,
          "probe_type" => "process"
        )
      end
      value.merge("metadata" => metadata)
    end

    def enrich_effect_resource(resource, sandbox:, namespace:, role:)
      value = stringify(resource)
      durable_metadata = stringify(value.fetch("metadata", {}))
      metadata = common_metadata(role)
      case value.fetch("kind")
      when "workspace"
        workspace = sandbox.workspace
        metadata.merge!(
          "root" => workspace.root, "upper" => workspace.upper, "work" => workspace.work,
          "workspace_stats" => path_stats([workspace.root, workspace.upper, workspace.work]),
          "probe_type" => "workspace"
        )
      when "namespace"
        raise "namespace ledger claim exists without a holder" unless namespace

        metadata.merge!(
          namespace.to_h,
          "pid" => namespace.pid, "start_time" => namespace.start_time,
          "namespace_links" => namespace.namespace_links,
          "creation_method" => namespace.creation_method,
          "clone_flags" => namespace.clone_flags,
          "probe_type" => "process"
        )
      when "cgroup"
        path = durable_metadata.fetch("path")
        stat = File.stat(path)
        metadata.merge!("path" => path, "device" => stat.dev, "inode" => stat.ino,
                        "members" => cgroup_members(path), "probe_type" => "cgroup")
      else
        raise "unsupported effect-point ledger resource #{value.fetch("kind").inspect}"
      end
      value.merge("metadata" => metadata)
    end

    def derived_effect_resources(sandbox, namespace, role:, agent_pid:)
      owner = sandbox.identity
      workspace = sandbox.workspace
      entries = []
      if namespace
        mount_line = mountinfo_line(namespace.pid, workspace.root)
        raise "OverlayFS readback is missing for #{workspace.root}" unless mount_line&.include?(" - overlay ")

        mount_fields = mount_line.split
        entries << measured(
          "mount", "#{sandbox.id}:#{mount_fields.fetch(0)}",
          "mount:#{sandbox.id}:#{mount_fields.fetch(0)}:#{workspace.root}", owner,
          observer_metadata(role).merge(
            "probe_type" => "mount", "holder_pid" => namespace.pid,
            "holder_start_time" => namespace.start_time, "mount_id" => mount_fields.fetch(0),
            "major_minor" => mount_fields.fetch(2), "root" => mount_fields.fetch(3),
            "mountpoint" => workspace.root, "filesystem" => "overlay",
            "mountinfo" => mount_line, "mountinfo_sha256" => Digest::SHA256.hexdigest(mount_line)
          )
        )
        namespace.namespace_links.each do |name, link|
          entries << measured(
            "ns", "#{sandbox.id}:#{name}", "ns:#{sandbox.id}:#{name}:#{link}", owner,
            observer_metadata(role).merge(
              "probe_type" => "namespace_link", "pid" => namespace.pid,
              "start_time" => namespace.start_time, "namespace" => name, "kernel_link" => link
            )
          )
        end
        fd = namespace.pidfd
        raise "namespace pidfd is missing" unless fd

        entries << measured(
          "pidfd", "#{sandbox.id}:namespace", "pidfd:#{sandbox.id}:namespace:#{fdinfo_digest(agent_pid, fd)}", owner,
          observer_metadata(role).merge(
            "probe_type" => "pidfd", "source_pid" => agent_pid, "fd" => fd,
            "fd_link" => fd_link(agent_pid, fd), "fdinfo_sha256" => fdinfo_digest(agent_pid, fd)
          )
        )
      end
      {"root" => workspace.root, "upper" => workspace.upper, "work" => workspace.work}.each do |name, path|
        stat = File.stat(path)
        entries << measured(
          "temp", "#{sandbox.id}:#{name}", "temp:#{sandbox.id}:#{stat.dev}:#{stat.ino}", owner,
          observer_metadata(role).merge(
            "probe_type" => "path", "path" => path, "device" => stat.dev, "inode" => stat.ino
          )
        )
      end
      entries
    end

    def derived_kernel_resources(sandbox, container, role:, agent_pid:)
      owner = sandbox.identity
      namespace = sandbox.namespace.adapter_handle
      process = container.process
      workspace = sandbox.workspace
      mount_line = mountinfo_line(namespace.pid, workspace.root)
      raise "OverlayFS readback is missing for #{workspace.root}" unless mount_line&.include?(" - overlay ")

      mount_fields = mount_line.split
      entries = [measured(
        "mount", "#{sandbox.id}:#{mount_fields.fetch(0)}",
        "mount:#{sandbox.id}:#{mount_fields.fetch(0)}:#{workspace.root}", owner,
        observer_metadata(role).merge(
          "probe_type" => "mount", "holder_pid" => namespace.pid,
          "holder_start_time" => namespace.start_time, "mount_id" => mount_fields.fetch(0),
          "major_minor" => mount_fields.fetch(2), "root" => mount_fields.fetch(3),
          "mountpoint" => workspace.root, "filesystem" => "overlay",
          "mountinfo" => mount_line, "mountinfo_sha256" => Digest::SHA256.hexdigest(mount_line)
        )
      )]
      namespace.namespace_links.each do |name, link|
        entries << measured(
          "ns", "#{sandbox.id}:#{name}", "ns:#{sandbox.id}:#{name}:#{link}", owner,
          observer_metadata(role).merge(
            "probe_type" => "namespace_link", "pid" => namespace.pid,
            "start_time" => namespace.start_time, "namespace" => name, "kernel_link" => link
          )
        )
      end
      {"namespace" => namespace.pidfd, "workload" => process.workload_pidfd}.each do |name, fd|
        raise "#{name} pidfd is missing" unless fd

        entries << measured(
          "pidfd", "#{sandbox.id}:#{name}", "pidfd:#{sandbox.id}:#{name}:#{fdinfo_digest(agent_pid, fd)}", owner,
          observer_metadata(role).merge(
            "probe_type" => "pidfd", "source_pid" => agent_pid, "fd" => fd,
            "fd_link" => fd_link(agent_pid, fd), "fdinfo_sha256" => fdinfo_digest(agent_pid, fd)
          )
        )
      end
      {"root" => workspace.root, "upper" => workspace.upper, "work" => workspace.work}.each do |name, path|
        stat = File.stat(path)
        entries << measured(
          "temp", "#{sandbox.id}:#{name}", "temp:#{sandbox.id}:#{stat.dev}:#{stat.ino}", owner,
          observer_metadata(role).merge(
            "probe_type" => "path", "path" => path, "device" => stat.dev, "inode" => stat.ino
          )
        )
      end
      entries
    end

    def common_metadata(role)
      {"managed_by" => "rubernetes-native", "ownership_verified" => true,
       "observer_role" => String(role), "live" => true}
    end

    def observer_metadata(role)
      common_metadata(role).merge("managed_by" => "rubernetes-native-observer")
    end

    def measured(kind, id, identity, owner, metadata)
      {"kind" => kind, "id" => String(id), "identity" => String(identity),
       "owner" => String(owner), "metadata" => metadata}
    end

    def observe_entry(entry, manifest)
      value = stringify(entry)
      metadata = stringify(value.fetch("metadata"))
      present = case metadata.fetch("probe_type")
                when "process"
                  stable_process?(metadata["pid"], metadata["start_time"])
                when "namespace_link"
                  stable_process?(metadata["pid"], metadata["start_time"]) &&
                  namespace_link(metadata["pid"], metadata["namespace"]) == metadata["kernel_link"]
                when "pidfd"
                  fd_link(metadata["source_pid"], metadata["fd"]) == metadata["fd_link"] &&
                  fdinfo_digest(metadata["source_pid"], metadata["fd"]) == metadata["fdinfo_sha256"]
                when "mount"
                  current = mountinfo_line(metadata["holder_pid"], metadata["mountpoint"])
                  stable_process?(metadata["holder_pid"], metadata["holder_start_time"]) &&
                  current == metadata["mountinfo"] && current.include?(" - overlay ")
                when "cgroup"
                  stable_path?(metadata["path"], metadata["device"], metadata["inode"])
                when "workspace"
                  metadata.fetch("workspace_stats").all? do |path, stat|
                    stable_path?(path, stat.fetch("device"), stat.fetch("inode"))
                  end
                when "path"
                  stable_path?(metadata["path"], metadata["device"], metadata["inode"])
                else
                  false
                end
      return nil unless present

      owner_live = stable_process?(
        manifest["liveness_pid"] || manifest["workload_pid"],
        manifest["liveness_start_time"] || manifest["workload_start_time"]
      )
      observed = metadata.merge("live" => owner_live)
      if value["kind"] == "cgroup"
        observed["members"] = cgroup_members(metadata["path"])
      elsif value["kind"] == "process"
        observed["cgroup_membership"] = proc_cgroup(metadata["pid"])
        observed["pid_namespace"] = namespace_link(metadata["pid"], "pid")
        observed["mount_namespace"] = namespace_link(metadata["pid"], "mnt")
      end
      value.merge("metadata" => observed)
    end

    def stable_process?(pid, start_time)
      return false if pid.nil? || start_time.nil?

      M2ProbeSupport.process_start_time(pid).to_s == start_time.to_s
    end

    def stable_path?(path, device, inode)
      stat = File.stat(path)
      stat.dev == Integer(device) && stat.ino == Integer(inode)
    rescue SystemCallError, ArgumentError, TypeError
      false
    end

    def path_stats(paths)
      paths.to_h do |path|
        stat = File.stat(path)
        [path, {"device" => stat.dev, "inode" => stat.ino}]
      end
    end

    def mountinfo_line(pid, target)
      File.readlines("/proc/#{Integer(pid)}/mountinfo", chomp: true).find do |line|
        line.split.fetch(4, "") == String(target).gsub(" ", "\\040")
      end
    rescue SystemCallError, ArgumentError
      nil
    end

    def namespace_link(pid, name)
      File.readlink("/proc/#{Integer(pid)}/ns/#{name}")
    rescue SystemCallError, ArgumentError
      nil
    end

    def fd_link(pid, fd)
      File.readlink("/proc/#{Integer(pid)}/fd/#{Integer(fd)}")
    rescue SystemCallError, ArgumentError, TypeError
      nil
    end

    def fdinfo_digest(pid, fd)
      Digest::SHA256.hexdigest(File.binread("/proc/#{Integer(pid)}/fdinfo/#{Integer(fd)}"))
    rescue SystemCallError, ArgumentError, TypeError
      nil
    end

    def cgroup_members(path)
      File.readlines(File.join(path, "cgroup.procs"), chomp: true).map { |pid| Integer(pid) }.sort
    rescue SystemCallError, ArgumentError
      []
    end

    def proc_cgroup(pid)
      File.readlines("/proc/#{Integer(pid)}/cgroup", chomp: true)
    rescue SystemCallError, ArgumentError
      []
    end

    def cleanup_cgroup(entry)
      metadata = entry.fetch("metadata")
      path = File.expand_path(metadata.fetch("path"))
      raise "cgroup cleanup escaped Rubernetes hierarchy" unless path.start_with?("/sys/fs/cgroup/rubernetes/")
      raise "cgroup identity changed" unless stable_path?(path, metadata.fetch("device"), metadata.fetch("inode"))
      raise "cgroup is still populated" unless cgroup_members(path).empty?

      Dir.rmdir(path)
      parent = File.dirname(path)
      Dir.rmdir(parent) if parent.start_with?("/sys/fs/cgroup/rubernetes/") && File.directory?(parent) && Dir.empty?(parent)
    rescue Errno::ENOENT
      true
    end

    def cleanup_workspace(entry)
      metadata = entry.fetch("metadata")
      stats = metadata.fetch("workspace_stats")
      raise "workspace identity changed" unless stats.all? { |path, stat| stable_path?(path, stat.fetch("device"), stat.fetch("inode")) }

      base = File.dirname(metadata.fetch("root"))
      raise "workspace cleanup escaped probe directory" unless base.start_with?("#{@directory}/")

      FileUtils.remove_entry_secure(base)
    end

    def stringify(value)
      value.respond_to?(:to_h) ? value.to_h.transform_keys(&:to_s) : value
    end
  end
end
