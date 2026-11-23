# frozen_string_literal: true

require "fileutils"
require "tmpdir"
require_relative "../test_helper"
require_relative "../../tools/milestones/m0_source_inventory"

class MilestoneSourceInventoryTest < Minitest::Test
  def test_pruning_preserves_the_legacy_file_and_symlink_inventories
    Dir.mktmpdir do |directory|
      root = File.join(directory, "source")
      write_paths(root, %w[
                    lib/.input.rb lib/a11-generated.ABC123/source.rb lib/pattern[1]/source.rb
                    a11-generated.short/source.rb a11-generated.abcDEF a11-generated.ABC123/temporary.rb
                    apps/dashboard/app/assets/app.js apps/dashboard/config/credentials/production.yml.enc
                    apps/dashboard/data_dictionary.rb apps/dashboard/config/master.key apps/dashboard/db/test.sqlite3-shm
                    apps/dashboard/data-live/wal/head.wal apps/dashboard/public/assets/app.js
                    apps/other/log apps/other/tmp/runtime.log .git/objects/index build/cache/source.rb
                  ])
      File.symlink(File.join(root, "lib/.input.rb"), File.join(root, "link-to-file"))
      File.symlink(File.join(root, "lib/.input.rb"), File.join(root, "a11-generated.linked"))
      File.symlink(File.join(root, "lib/.input.rb"), File.join(root, "apps/dashboard/data-linked"))
      File.symlink(File.join(root, "lib"), File.join(root, "link-to-directory"))
      File.symlink("missing", File.join(root, "dangling-link"))
      File.symlink(root, File.join(directory, "source-link"))

      [root, File.join(directory, "source-link")].each do |tree|
        follow_links = M0SourceInventory.source_files(tree)
        check_regular_file = ->(path) { File.lstat(path).file? }
        strict = M0SourceInventory.source_files(tree, &check_regular_file)

        legacy = legacy_files(tree) { |path| File.file?(path) }

        assert_equal legacy, follow_links
        assert_equal legacy_files(tree, &check_regular_file), strict
        assert_includes follow_links, File.join(tree, "link-to-file")
        refute_includes strict, File.join(tree, "link-to-file")
      end
    end
  end

  def test_unreadable_directories_are_skipped_and_caller_errors_are_preserved
    Dir.mktmpdir do |root|
      write_paths(root, %w[visible.rb unreadable/member.rb])
      children = Dir.method(:children)
      unreadable = File.join(root, "unreadable")
      list = lambda do |directory|
        raise Errno::EACCES, directory if directory == unreadable

        children.call(directory)
      end
      result = Dir.stub(:children, list) { M0SourceInventory.source_files(root) }

      assert_equal [File.join(root, "visible.rb")], result
      assert_raises(Errno::EIO) { M0SourceInventory.source_files(root) { |path| raise Errno::EIO, path } }
    end
  end

  def test_excluded_directories_are_not_opened
    Dir.mktmpdir do |root|
      excluded = %w[build artifacts a11-generated.ABC123 apps/dashboard/data-local apps/dashboard/public/assets apps/example/log]
      write_paths(root, excluded.map { |relative| "#{relative}/child/readme" } + ["lib/real.rb"])
      children = Dir.method(:children)
      opened = []
      observed_children = lambda do |directory|
        opened << directory
        children.call(directory)
      end
      files = Dir.stub(:children, observed_children) { M0SourceInventory.source_files(root) }

      assert_equal [File.join(root, "lib/real.rb")], files
      assert_includes opened, File.join(root, "lib")
      excluded.each do |relative|
        subtree = File.join(root, relative)

        refute(opened.any? { |path| path == subtree || path.start_with?("#{subtree}/") }, relative)
      end
    end
  end

  private

  def write_paths(root, paths)
    paths.each do |relative|
      path = File.join(root, relative)
      FileUtils.mkdir_p(File.dirname(path))
      File.write(path, "test source")
    end
  end

  def legacy_files(root)
    Dir.glob(File.join(root, "**/*"), File::FNM_DOTMATCH).select do |path|
      !M0SourceInventory.excluded?(path.delete_prefix("#{root}/")) && yield(path)
    end.sort
  end
end
