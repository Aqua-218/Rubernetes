# frozen_string_literal: true

require "tmpdir"
require_relative "../test_helper"
require_relative "../../tools/conformance/run"

class ConformanceRunnerSourceIdentityTest < Minitest::Test
  Runner = Conformance::Runner
  Lanes = Conformance::Lanes

  def test_git_head_is_used_only_for_an_actual_clean_checkout
    Dir.mktmpdir do |root|
      git(root, "init", "--quiet")
      source = write_input(root, "lib/rubernetes.rb", "original")
      git(root, "add", ".")
      git(root, "commit", "--quiet", "-m", "pinned source")
      revision = git(root, "rev-parse", "HEAD")

      assert_equal revision, Runner.rubernetes_commit(root: root)

      File.write(source, "dirty source")
      first = Runner.rubernetes_commit(root: root)
      File.write(source, "different dirty source")
      second = Runner.rubernetes_commit(root: root)

      assert_match(/\Asha256:[0-9a-f]{64}\z/, first)
      assert_match(/\Asha256:[0-9a-f]{64}\z/, second)
      refute_equal first, second

      File.write(source, "original")
      write_input(root, "config/untracked.yml", "configuration")

      assert_match(/\Asha256:[0-9a-f]{64}\z/, Runner.rubernetes_commit(root: root))
    end
  end

  def test_export_in_an_ancestor_checkout_does_not_inherit_its_head
    Dir.mktmpdir do |parent|
      git(parent, "init", "--quiet")
      write_input(parent, ".gitignore", "export/\n")
      git(parent, "add", ".")
      git(parent, "commit", "--quiet", "-m", "parent repository")
      root = File.join(parent, "export")
      write_input(root, "lib/rubernetes.rb", "exported")

      assert_empty git(parent, "status", "--porcelain")
      assert_equal "sha256:#{Lanes.source_tree_digest(root: root)}", Runner.rubernetes_commit(root: root)
    end
  end

  def test_source_digest_covers_packaged_inputs_and_skips_runtime_and_caches
    Dir.mktmpdir do |root|
      files = %w[Gemfile.lock config/cluster.yml generated/schema/api.json ext/rubernetes_linux/native.c
                 third_party/locks/artifacts.json sig/rubernetes.rbs apps/dashboard/config/database.yml
                 apps/dashboard/db/schema.rb apps/dashboard/config/credentials/production.yml.enc apps/dashboard/data_dictionary.rb]
      initial = Lanes.source_tree_digest(root: root)
      files.each do |name|
        write_input(root, name, "distributed")
        changed = Lanes.source_tree_digest(root: root)

        refute_equal initial, changed, name
        initial = changed
      end
      %w[.git/index build/images/disk artifacts/run/manifest.json third_party/cache/download
         apps/dashboard/tmp/cache/key apps/dashboard/config/dashboard.local.env apps/dashboard/config/master.key
         apps/dashboard/config/credentials/production.key apps/dashboard/public/assets/application.js
         apps/dashboard/db/test.sqlite3-shm apps/dashboard/data/index.sqlite apps/dashboard/data-test/wal/head.wal
         verification/tla/states/log ext/rubernetes_linux/native.so].each do |name|
        write_input(root, name, "scratch")
      end

      assert_equal initial, Lanes.source_tree_digest(root: root)
    end
  end

  def test_runner_records_start_and_finish_and_fails_if_source_changes
    Dir.mktmpdir do |directory|
      root = File.join(directory, "export")
      file = write_input(root, "config/apiserver.yml", "original")
      identity = Runner.method(:rubernetes_commit)
      initial = identity.call(root: root)
      output = File.join(directory, "out")
      result = [{"lane" => "K1", "status" => "COMPLETE", "passed" => true}]
      execute = lambda do |*_, **|
        File.write(file, "different")
        result
      end
      status = nil
      capture_io do
        Runner.stub(:rubernetes_commit, -> { identity.call(root: root) }) do
          Runner.stub(:execute_lanes, execute) { status = Runner.run(["--lanes", "K1", "--output-root", output]) }
        end
      end
      manifest = JSON.parse(File.read(Dir.glob(File.join(output, "*", "manifest.json")).fetch(0)))

      assert_equal 1, status
      assert_equal initial, manifest.fetch("rubernetesCommit")
      assert_equal identity.call(root: root), manifest.fetch("rubernetesCommitAfter")
      refute manifest.fetch("rubernetesSourceStable")
      refute manifest.fetch("summary").fetch("passed")
      assert_equal result, manifest.fetch("lanes")
    end
  end

  private

  def write_input(root, relative, content)
    path = File.join(root, relative)
    FileUtils.mkdir_p(File.dirname(path))
    File.write(path, content)
    path
  end

  def git(root, *)
    config = ["-c", "user.email=test@example.test", "-c", "user.name=Test", "-c", "commit.gpgSign=false"]
    out, error, status = Open3.capture3("git", "-C", root, *config, *)
    raise error unless status.success?

    out.strip
  end
end
