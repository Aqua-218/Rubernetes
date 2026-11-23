# frozen_string_literal: true

require_relative "../test_helper"
require "open3"
require "rubernetes/bootstrap/assembler"
require "timeout"

class EmptyDirProjectQuotaTest < Minitest::Test
  Mount = Rubernetes::Platform::Linux::Mount
  OPENAT2 = Rubernetes::Platform::Linux::Openat2
  ProjectQuota = Rubernetes::Volume::ProjectQuota
  StatsProvider = Rubernetes::Node::StatsProvider
  PAYLOAD_BYTES = 256 * 1024
  WRITER = <<~'RUBY'
    path, length = ARGV
    puts File.readlink("/proc/self/ns/user")
    STDOUT.flush
    exit unless STDIN.gets
    File.open(path) do |directory|
      attributes = "\0".b * 28
      directory.ioctl(0x801c581f, attributes)
      attributes[12, 4] = [0].pack("L")
      begin
        directory.ioctl(0x401c5820, attributes)
        abort "user namespace cleared the volume project ID"
      rescue Errno::EPERM, Errno::EINVAL
      end
    end
    File.open(File.join(path, "unlinked"), "w") do |file|
      file.write("a" * Integer(length))
      file.fsync
      File.unlink(file.path)
      puts "ready"
      STDOUT.flush
      STDIN.gets
    end
  RUBY

  def teardown
    @prepared&.reverse_each { |volumes, pod, result| volumes.release(pod, result) }
  ensure
    @managers&.each(&:close)
    if @mounted
      mount = Mount.new
      @pod_roots.reverse_each { |root| mount.unmount(target: root, flags: Mount::MNT_DETACH) }
      mount.unmount(target: @volume_root)
    end
    FileUtils.remove_entry(@root) if @root
  end

  def test_an_unmounted_directory_is_left_to_the_directory_scanner
    Dir.mktmpdir("rbn-quota-unsupported-") do |root|
      adapter = ProjectQuota.new(root: root)
      source = File.join(root, "new-emptydir")

      refute_predicate adapter, :supported?
      assert_nil adapter.provision(source)
      refute_path_exists source
    end
  end

  def test_ext4_counts_unlinked_open_files_through_the_pod_summary
    mount_quota_filesystem("ext4")
    verify_project_quota
  end

  def test_xfs_counts_unlinked_open_files_through_the_pod_summary
    mount_quota_filesystem("xfs")
    verify_project_quota
  end

  def test_ext4_summary_uses_periodic_project_quota_counters
    mount_quota_filesystem("ext4")
    verify_periodic_quota_summary
  end

  def test_xfs_summary_uses_periodic_project_quota_counters
    mount_quota_filesystem("xfs")
    verify_periodic_quota_summary
  end

  def test_gate_and_user_namespace_eligibility_on_a_quota_enabled_filesystem
    mount_quota_filesystem("ext4")
    default_manager = manager
    default = prepare_volumes(default_manager, pod("default", host_users: false))

    assert_no_project(default_manager, default, "scratch")

    enabled_manager = manager(gates: {ProjectQuota::FEATURE_GATE => true})
    host = prepare_volumes(enabled_manager, pod("host", host_users: true))
    omitted = prepare_volumes(enabled_manager, pod("omitted"))
    isolated = prepare_volumes(enabled_manager, pod("isolated", host_users: false, medium: "Memory"))

    assert_no_project(enabled_manager, host, "scratch")
    assert_no_project(enabled_manager, omitted, "scratch")
    assert_no_project(enabled_manager, isolated, "scratch")

    # A pre-existing directory must never be assigned a project at recovery.
    source = File.join(@volume_root, "already-present")
    Dir.mkdir(source)
    File.write(File.join(source, "existing"), "preserved")

    refute_predicate ProjectQuota.new(root: source), :supported?
    assert_nil ProjectQuota.new(root: @volume_root).provision(source)
    assert_equal "preserved", File.read(File.join(source, "existing"))
    File.open(source) do |directory|
      attributes = "\0".b * 28
      directory.ioctl(ProjectQuota::GET_FSXATTR, attributes)

      assert_equal 0, attributes.unpack1("@12L")
    end
    assert_whole_filesystem_bind_is_ineligible
  end

  private

  def mount_quota_filesystem(filesystem)
    skip "requires root in a private mount namespace" unless Process.euid.zero? && !Mount.new.initial_mount_namespace?
    skip "requires mkfs.#{filesystem} and loop devices" unless executable?("mkfs.#{filesystem}") && File.exist?("/dev/loop-control")

    @root = Dir.mktmpdir("rbn-emptydir-quota-")
    @volume_root = File.join(@root, "volumes")
    @pod_roots = []
    @prepared = []
    @managers = []
    Dir.mkdir(@volume_root)
    image = File.join(@root, "filesystem.img")
    File.open(image, "w") { |file| file.truncate((filesystem == "xfs" ? 320 : 32) * 1024 * 1024) }
    options = filesystem == "ext4" ? %w[-O project,quota -E quotatype=prjquota] : []
    run_command("mkfs.#{filesystem}", "-q", *options, image)
    run_command("mount", "-o", "loop,prjquota", image, @volume_root)
    @mounted = true
  end

  def executable?(command)
    ENV.fetch("PATH").split(File::PATH_SEPARATOR).any? { |path| File.executable?(File.join(path, command)) }
  end

  def run_command(*command)
    output, status = Open3.capture2e(*command)

    assert_predicate status, :success?, "#{command.first} failed (#{status.exitstatus}): #{output}"
  end

  def manager(gates: {})
    process = {"runtime_profile" => "kernel_isolation", "feature_gates" => gates,
               "volume" => {"data_dir" => File.join(@root, "state"), "root" => @volume_root}}
    resolver = Rubernetes::Platform::Linux::Openat2.new(root: @root, strict: true)
    security = Rubernetes::Volume::PathSecurity.new(root: @root, adapter: resolver, require_openat2: true)
    Rubernetes::Bootstrap::Assembler.allocate.send(:build_volume, process, adapters: {volume_path_security: security}).tap do |volume|
      @managers << volume
    end
  end

  def pod(uid, host_users: nil, medium: "")
    {"metadata" => {"namespace" => "default", "name" => uid, "uid" => uid},
     "spec" => {"hostUsers" => host_users, "volumes" => [{"name" => "scratch", "emptyDir" => {"medium" => medium, "sizeLimit" => "128Ki"}}],
                "containers" => [{"name" => "app", "volumeMounts" => [{"name" => "scratch", "mountPath" => "/scratch"}]}]}.compact}
  end

  def prepare_volumes(manager, pod)
    pod_root = File.join(@root, "pods-#{pod.dig("metadata", "uid")}")
    volumes = Rubernetes::Node::PodVolumes.new(volume: manager, root: pod_root, node_name: "worker")
    @pod_roots << pod_root
    volumes.prepare(pod).tap { |result| @prepared << [volumes, pod, result] }
  end

  def assert_no_project(manager, prepared, volume)
    mount = prepared.dig("mounts", volume)

    assert_nil manager.volume(mount.fetch("id")).spec.dig("backendResult", "projectQuotaId")
    assert_nil manager.project_quota_usage(mount.fetch("id"), mount.fetch("path"))
  end

  def assert_whole_filesystem_bind_is_ineligible
    target = File.join(@root, "whole-filesystem-alias")
    Dir.mkdir(target)
    mount = Mount.new
    mount.mount(source: @volume_root, target: target, filesystem: nil, flags: Mount::MS_BIND)
    bound = true

    refute_predicate ProjectQuota.new(root: target), :supported?
    refute_predicate ProjectQuota.new(root: @volume_root), :supported?
  ensure
    mount.unmount(target: target) if bound
  end

  def verify_project_quota
    gates = {ProjectQuota::FEATURE_GATE => true}
    workload = pod("workload", host_users: false)
    active_manager = manager(gates: gates)
    prepared = prepare_volumes(active_manager, workload)
    mount = prepared.dig("mounts", "scratch")
    id = mount.fetch("id")
    path = mount.fetch("path")
    baseline = active_manager.project_quota_usage(id, path)

    assert_equal 1, baseline&.last
    assert_nil active_manager.project_quota_usage(id, @volume_root)

    recovered_manager = manager(gates: gates)

    assert_equal baseline, recovered_manager.project_quota_usage(id, path)
    with_unlinked_file(path) do
      assert_empty Dir.children(path)
      stats = summary(recovered_manager, workload, prepared)

      assert_equal [baseline.first + PAYLOAD_BYTES, 2], stats.dig("volume", 0).values_at("usedBytes", "inodesUsed")
      assert_equal baseline.first + PAYLOAD_BYTES, stats.dig("ephemeral-storage", "usedBytes")
      fallback = summary(manager, workload, prepared)

      assert_equal Rubernetes::Node::DirectoryUsage.measure(path), fallback.dig("volume", 0).values_at("usedBytes", "inodesUsed")
    end
    run_command("sync", "-f", @volume_root)

    assert_equal baseline, recovered_manager.project_quota_usage(id, path)
  end

  def with_unlinked_file(path)
    target = File.join(@root, "idmapped")
    Dir.mkdir(target)
    mount = Mount.new
    attached = false
    Open3.popen3("unshare", "--user", "--map-root-user", RbConfig.ruby, "-e", WRITER, target, PAYLOAD_BYTES.to_s) do |input, output, error, process|
      namespace = Timeout.timeout(5) { output.gets&.strip }
      assert namespace, error.read unless namespace

      refute_equal File.readlink("/proc/self/ns/user"), namespace
      attached = bind_idmapped_path(mount, path, target, process.pid)
      input.puts "start"

      assert_equal "ready\n", Timeout.timeout(5) { output.gets }
      yield
      input.close

      assert_predicate process.value, :success?, error.read
    end
  ensure
    mount.unmount(target: target) if attached
  end

  def bind_idmapped_path(mount, source, target, pid)
    File.open("/proc/#{pid}/ns/user") do |userns|
      File.open(source, OPENAT2::O_PATH) do |from|
        File.open(target, OPENAT2::O_PATH) do |to|
          mount.bind_tree(source_fd: from.fileno, target_fd: to.fileno, recursive: true, userns_fd: userns.fileno)
        end
      end
    end
  end

  def summary(manager, workload, prepared)
    provider = stats_provider(manager, workload, prepared)
    provider.sample_volume_stats
    provider.summary.fetch("pods").first
  end

  def stats_provider(manager, workload, prepared, **)
    record = {state: "Running", sandbox_id: "sandbox", uid: workload.dig("metadata", "uid"), pod: workload, volume: prepared}
    lifecycle = Struct.new(:records).new({record.fetch(:uid) => record})
    StatsProvider.new(node_name: "worker", lifecycle: lifecycle, runtime: Object.new, pod_root: @root,
                      project_quota_usage: manager.method(:project_quota_usage), **)
  end

  def verify_periodic_quota_summary
    workload = pod("periodic", host_users: false)
    active_manager = manager(gates: {ProjectQuota::FEATURE_GATE => true})
    prepared = prepare_volumes(active_manager, workload)
    id, path = prepared.fetch("mounts").fetch("scratch").values_at("id", "path")
    baseline = active_manager.project_quota_usage(id, path)
    elapsed = 0
    start = Time.utc(2026, 1, 1)
    provider = stats_provider(active_manager, workload, prepared,
                              volume_stats_agg_period: 3, monotonic: -> { elapsed }, clock: -> { start + elapsed })

    assert_nil provider.summary.dig("pods", 0, "volume")

    payload = File.join(path, "ordinary-write")
    sample = File.open(payload, "wb") do |file|
      file.write("a" * PAYLOAD_BYTES)
      file.fsync
      File.unlink(payload)
      fallback = summary(manager, workload, prepared)

      assert_equal Rubernetes::Node::DirectoryUsage.measure(path), fallback.dig("volume", 0).values_at("usedBytes", "inodesUsed")

      provider.sample_volume_stats
      provider.summary.fetch("pods").first
    end

    assert_equal [baseline.first + PAYLOAD_BYTES, baseline.last + 1], sample.dig("volume", 0).values_at("usedBytes", "inodesUsed")
    assert_equal baseline.first + PAYLOAD_BYTES, sample.dig("ephemeral-storage", "usedBytes")

    run_command("sync", "-f", @volume_root)
    elapsed += 3

    assert_equal sample.fetch("volume"), provider.summary.dig("pods", 0, "volume")

    provider.sample_volume_stats
    refreshed = provider.summary.fetch("pods").first

    assert_equal [*baseline, (start + elapsed).iso8601], refreshed.dig("volume", 0).values_at("usedBytes", "inodesUsed", "time")
    assert_equal baseline.first, refreshed.dig("ephemeral-storage", "usedBytes")
  end
end
