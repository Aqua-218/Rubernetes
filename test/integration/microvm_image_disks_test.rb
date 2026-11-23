# frozen_string_literal: true

require "io/wait"
require "tmpdir"
require_relative "../test_helper"
require "rubernetes/runtime/microvm"

class MicroVMImageDisksTest < Minitest::Test
  Disks = Rubernetes::Runtime::MicroVM::ImageDisks
  DiskError = Rubernetes::Runtime::MicroVM::Error
  DIGEST = "sha256:#{"ab" * 32}".freeze

  class ObservedDisks < Disks
    attr_accessor :fail_copy, :staging_signal

    private

    def run!(*arguments)
      if arguments.first == "mkfs.ext4"
        label = arguments.fetch(arguments.index("-L") + 1)
        File.open(File.join(root, "formats.log"), "a") { |file| file.puts(label) }
        sleep 0.05
      elsif arguments.first == "cp" && fail_copy
        self.fail_copy = false
        File.binwrite(arguments.last, "partial workspace")
        raise DiskError, "injected copy failure"
      elsif arguments.first == "cp" && staging_signal
        File.binwrite(arguments.last, "partial workspace")
        staging_signal.puts(arguments.last)
        staging_signal.close
        sleep 30
      end
      super
    end
  end

  def setup
    _, status = Open3.capture2e("mkfs.ext4", "-V")
    skip "mkfs.ext4 is unavailable" unless status.success?

    @base = Dir.mktmpdir("rubernetes-microvm-disks")
    @rootfs = File.join(@base, "rootfs")
    FileUtils.mkdir_p(@rootfs)
    File.write(File.join(@rootfs, "payload"), "verified image\n")
    @disks = ObservedDisks.new(root: File.join(@base, "disks"), workspace_mib: 128)
  rescue Errno::ENOENT
    skip "mkfs.ext4 is unavailable"
  end

  def teardown
    FileUtils.remove_entry_secure(@base) if @base
  end

  def test_processes_build_each_shared_disk_once_and_get_complete_artifacts
    reader, writer = IO.pipe
    pids = Array.new(3) do |index|
      fork do
        writer.close
        reader.read(1)
        disks = ObservedDisks.new(root: @disks.root, workspace_mib: 128)
        paths = [disks.image_disk(DIGEST, @rootfs), disks.workspace_template(128), disks.placeholder(0)]
        paths.each { |path| raise "unformatted #{path}" unless File.binread(path, 2, 1080) == "\x53\xEF".b }
        checksum = File.read("#{paths.first}.sha256").strip
        raise "inconsistent image checksum" unless checksum == Digest::SHA256.file(paths.first).hexdigest

        File.write(File.join(@base, "result-#{index}"), paths.join("\n"))
        exit! 0
      end
    end
    reader.close
    writer.write("x" * pids.length)
    writer.close
    statuses = pids.map { |pid| Process.wait2(pid).last }

    assert statuses.all?(&:success?)
    assert_equal 1, Dir[File.join(@base, "result-*")].map { |path| File.read(path) }.uniq.length
    assert_equal %w[image placeholder workspace], File.readlines(File.join(@disks.root, "formats.log"), chomp: true).sort
    assert_empty Dir[File.join(@disks.root, "**/*.ext4.staging")]
  end

  def test_one_thread_publishes_a_sparse_workspace_and_teardown_leaves_no_sidecar
    go = Queue.new
    threads = Array.new(4) do
      Thread.new do
        go.pop
        @disks.image_disk(DIGEST, @rootfs)
        @disks.workspace_disk("shared")
      rescue DiskError => error
        error.message
      end
    end
    threads.length.times { go << true }
    outcomes = threads.map(&:value)
    path = File.join(@disks.root, "workspaces/shared.ext4")

    assert_equal 1, outcomes.count(path)
    assert_equal 3, outcomes.count("workspace shared already exists")
    assert_equal %w[image workspace], File.readlines(File.join(@disks.root, "formats.log"), chomp: true).sort
    assert_equal 128 * 1024 * 1024, File.size(path)
    assert_operator File.stat(path).blocks * 512, :<, File.size(path) / 16
    assert_equal "\x53\xEF".b, File.binread(path, 2, 1080)
    assert @disks.remove_workspace("shared")
    refute @disks.remove_workspace("shared")
    assert_empty Dir.children(File.dirname(path))
    assert_operator Dir.children(File.join(@disks.root, ".locks")).length, :<=, Disks::LOCK_STRIPES
  end

  def test_retry_removes_interrupted_staging_files_and_repairs_corrupt_cache_pairs
    @disks.fail_copy = true

    assert_raises(DiskError) { @disks.workspace_disk("retry") }
    assert_empty Dir.children(File.join(@disks.root, "workspaces"))
    assert_equal "\x53\xEF".b, File.binread(@disks.workspace_disk("retry"), 2, 1080)

    image = @disks.image_disk(DIGEST, @rootfs)
    File.write("#{image}.sha256", "#{"0" * 64}\n")
    abandoned = "#{image}.staging/build-abandoned"
    FileUtils.mkdir_p(abandoned)
    File.write(File.join(abandoned, "disk.ext4"), "previous partial build")
    File.write(File.join(abandoned, "disk.ext4.sha256"), "previous partial checksum")

    assert_equal image, @disks.image_disk(DIGEST, @rootfs)
    assert_equal Digest::SHA256.file(image).hexdigest, File.read("#{image}.sha256").strip
    assert_empty Dir[File.join(@disks.root, "**/*.ext4.staging")]
  end

  def test_retry_cannot_reuse_the_temporary_path_of_a_killed_writer
    reader, writer = IO.pipe
    child = fork do
      reader.close
      @disks.staging_signal = writer
      @disks.workspace_disk("interrupted")
      exit! 0
    end
    writer.close

    assert reader.wait_readable(5), "workspace writer did not stage its disk"

    temporary = reader.gets&.chomp

    assert_path_exists temporary
    assert_empty @disks.workspaces

    Process.kill("KILL", child)
    Process.wait(child)
    child = nil
    workspace = @disks.workspace_disk("interrupted")

    assert_equal "\x53\xEF".b, File.binread(workspace, 2, 1080)
    refute_path_exists File.dirname(temporary)
    assert_empty Dir[File.join(@disks.root, "**/*.ext4.staging")]
  ensure
    reader&.close
    writer&.close unless writer&.closed?
    if child
      Process.kill("KILL", child)
      Process.wait(child)
    end
  end

  def test_repairs_an_old_placeholder_left_unformatted_at_the_final_path
    path = File.join(@disks.root, "placeholders/slot0.ext4")
    File.open(path, "w") { |file| file.truncate(Disks::PLACEHOLDER_MIB * 1024 * 1024) }

    assert_equal path, @disks.placeholder(0)
    assert_equal "\x53\xEF".b, File.binread(path, 2, 1080)
  end

  def test_checksum_publication_failure_does_not_leave_an_image_or_temporary_files
    image = File.join(@disks.root, "images", "#{DIGEST.delete_prefix("sha256:")}.ext4")
    checksum = "#{image}.sha256"
    Dir.mkdir(checksum)

    assert_raises(Errno::EISDIR) { @disks.image_disk(DIGEST, @rootfs) }
    refute_path_exists image
    assert_empty Dir[File.join(@disks.root, "**/*.ext4.staging")]
    assert_path_exists checksum

    Dir.rmdir(checksum)

    assert_equal image, @disks.image_disk(DIGEST, @rootfs)
    assert_equal Digest::SHA256.file(image).hexdigest, File.read(checksum).strip
  end
end
