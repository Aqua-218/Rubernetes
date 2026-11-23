# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/volume"
require "tmpdir"

class ProjectionGenerationRecoveryTest < Minitest::Test
  Writer = Rubernetes::Volume::AtomicWriter

  def test_restart_reclaims_a_generation_interrupted_before_publication
    Dir.mktmpdir do |root|
      writer = Writer.new(root, fsync: false)
      writer.write({"value" => "first"})
      pid = fork do
        interrupted = Writer.new(root, fsync: false)
        interrupted.define_singleton_method(:swap_data_link) { |_name| exit! 24 }
        interrupted.write({"value" => "unfinished"})
      end
      _, status = Process.wait2(pid)

      assert_equal 24, status.exitstatus
      assert_equal "first", writer.read("value")
      assert_equal 2, writer.generations.size
      writer.write({"value" => "replacement"})

      assert_equal "replacement", writer.read("value")
      assert_equal [writer.current_generation], writer.generations
    end
  end

  def test_custom_generation_names_retire_without_accumulating_directories
    Dir.mktmpdir do |root|
      writer = Writer.new(root, fsync: false)
      writer.write({"nested/value" => "first"}, generation: "..initial")
      writer.write({"nested/value" => "second"}, generation: "..next")

      assert_equal %w[..data ..next nested], Dir.children(root).sort
      assert_equal "second", writer.read("nested/value")
    end
  end

  def test_restrictive_agent_umask_keeps_projection_directories_traversable
    Dir.mktmpdir do |root|
      dest = File.join(root, "volume")
      pid = fork do
        File.umask(0o077)
        Writer.new(dest, mountpoints: ["mounts/child"]).write({"config/nested/value" => "visible"}, mode: 0o444)
      end
      _, status = Process.wait2(pid)

      assert_predicate status, :success?
      ["", "..data", "config/nested", "mounts", "mounts/child"].each do |name|
        assert_equal 0o755, File.stat(File.join(dest, name)).mode & 0o777, name
      end
      assert_equal 0o444, File.stat(File.join(dest, "config/nested/value")).mode & 0o777
      assert_equal "visible", File.read(File.join(dest, "config/nested/value"))
    end
  end

  def test_nested_directory_sync_failure_keeps_the_previous_generation_visible
    Dir.mktmpdir do |root|
      writer = Writer.new(root)
      writer.write({"nested/dir/config" => "before"})
      previous = writer.current_generation
      writer.define_singleton_method(:fsync_directory) do |path|
        raise Errno::ENOSPC if path.end_with?("/nested/dir")

        super(path)
      end

      assert_raises(Errno::ENOSPC) { writer.write({"nested/dir/config" => "after"}) }
      assert_equal [previous], writer.generations
      assert_equal previous, writer.current_generation
      assert_equal "before", writer.read("nested/dir/config")
    end
  end
end
