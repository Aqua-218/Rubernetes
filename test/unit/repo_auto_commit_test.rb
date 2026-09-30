# frozen_string_literal: true

require "fileutils"
require "json"
require "open3"
require "stringio"
require "tmpdir"
require_relative "../test_helper"
require_relative "../../tools/repo/auto_commit"

# The recorder turns whatever changed in the work tree into commits without
# anyone writing a message: one commit per contiguous edit, named after the
# declaration it lands in; sources before tests before generated records; a
# single fast-import stream published with a compare-and-swap on HEAD; the
# real index brought in line afterwards.  It adds no trailer of its own
# besides Cycle/Cycle-Result -- in particular no co-author.
class RepoAutoCommitTest < Minitest::Test
  AutoCommit = Rubernetes::Repo::AutoCommit

  def setup
    @dir = Dir.mktmpdir("auto-commit-test")
    git("init", "-q", "-b", "main")
    git("config", "user.name", "Recorder Test")
    git("config", "user.email", "recorder@example.test")
    git("config", "commit.gpgsign", "false")
  end

  def teardown
    FileUtils.rm_rf(@dir)
  end

  def git(*args, input: nil)
    out, err, status = Open3.capture3("git", *args, chdir: @dir, stdin_data: input)
    raise "git #{args.join(" ")} failed: #{err}" unless status.success?

    out
  end

  def write(path, content)
    full = File.join(@dir, path)
    FileUtils.mkdir_p(File.dirname(full))
    File.write(full, content)
  end

  def run_recorder(*argv)
    out = StringIO.new
    err = StringIO.new
    status = AutoCommit.main(argv, io: out, err: err, root: @dir)
    [status, out.string, err.string]
  end

  def subjects
    git("log", "--reverse", "--format=%s").lines(chomp: true)
  end

  def commit_message(ref)
    git("log", "-1", "--format=%B", ref)
  end

  def test_first_run_on_an_unborn_branch_records_files_in_category_order
    write("lib/rubernetes/api/thing.rb", "module Thing\n  def self.run\n    1\n  end\nend\n")
    write("test/unit/thing_test.rb", "class ThingTest\n  def test_run\n  end\nend\n")
    write("README.md", "# Title\n\nText.\n")
    write("generated/report.json", JSON.pretty_generate("status" => "ok", "count" => 3))
    status, out, err = run_recorder("--quiet")

    assert_equal 0, status, err

    assert_equal ["feat(api): add thing", "test(unit): add thing test", "docs: add readme", "chore(generated): add report"],
                 subjects
    body = commit_message("HEAD~3")

    assert_includes body, "Declares:"
    assert_includes body, "  Thing"
    refute_match(/Co-Authored-By/i, git("log", "--format=%B"))
    assert_equal "", git("status", "--porcelain"), "the index was brought in line: nothing left staged"
    assert_equal "", out
  end

  def test_each_edit_becomes_its_own_commit_named_after_the_enclosing_declaration
    write("lib/rubernetes/node/agent.rb", <<~RUBY)
      module Agent
        def self.start
          boot
        end

        def self.stop
          halt
        end

        def self.status
          :ok
        end
      end
    RUBY
    run_recorder("--quiet")
    write("lib/rubernetes/node/agent.rb", <<~RUBY)
      module Agent
        def self.start
          prepare
          boot
        end

        def self.stop
          halt
        end

        def self.status
          :ok
          # extra
        end
      end
    RUBY
    status, = run_recorder("--quiet", "--cycle", "edit-cycle", "--status", "0")

    assert_equal 0, status
    assert_equal ["feat(node): extend start", "feat(node): extend status"], subjects.last(2)
    body = commit_message("HEAD")

    assert_includes body, "One edit in `status` (lib/rubernetes/node/agent.rb, line"
    assert_includes body, "Cycle: edit-cycle"
    assert_includes body, "Cycle-Result: pass"
    assert_equal File.read(File.join(@dir, "lib/rubernetes/node/agent.rb")), git("show", "HEAD:lib/rubernetes/node/agent.rb")
    assert_equal "", git("status", "--porcelain")
  end

  def test_file_granularity_records_one_commit_per_path_with_declarations_touched
    write("lib/rubernetes/volume/manager.rb", "class Manager\n  def mount\n    1\n  end\n\n  def unmount\n    2\n  end\nend\n")
    run_recorder("--quiet")
    write("lib/rubernetes/volume/manager.rb", "class Manager\n  def mount\n    1 + 1\n  end\n\n  def unmount\n    2 + 2\n  end\nend\n")
    write("lib/rubernetes/volume/other.rb", "class Other; end\n")
    status, = run_recorder("--quiet", "--granularity", "file")

    assert_equal 0, status
    assert_equal ["chore(volume): update mount and unmount", "feat(volume): add other"], subjects.last(2)
    assert_includes commit_message("HEAD~1"), "Declarations touched:"
  end

  def test_cycle_granularity_records_everything_as_one_commit_with_a_file_map
    write("lib/rubernetes/api/a.rb", "A = 1\n")
    write("test/unit/a_test.rb", "AT = 1\n")
    run_recorder("--quiet")
    write("lib/rubernetes/api/a.rb", "A = 2\n")
    write("test/unit/a_test.rb", "AT = 2\n")
    write("lib/rubernetes/api/b.rb", "B = 1\n")
    status, = run_recorder("--quiet", "--granularity", "cycle", "--cycle", "rake-test", "--status", "1")

    assert_equal 0, status
    assert_equal 1, subjects.length - 2
    assert_match(/\Afeat\(api\): update /, subjects.last)
    body = commit_message("HEAD")

    assert_includes body, "Recorded after `rake-test` exited 1 (fail-closed)."
    assert_includes body, "Source:"
    assert_includes body, "  M lib/rubernetes/api/a.rb (+1 -1)"
    assert_includes body, "Tests:"
    assert_includes body, "3 files changed, 3 insertions(+), 2 deletions(-)."
    assert_includes body, "Cycle-Result: fail (1)"
  end

  def test_already_staged_changes_are_recorded_first_and_separately
    write("lib/rubernetes/api/a.rb", "A = 1\n")
    run_recorder("--quiet")
    write("lib/rubernetes/api/a.rb", "A = 2\n")
    git("add", "lib/rubernetes/api/a.rb")
    write("lib/rubernetes/api/c.rb", "C = 1\n")
    run_recorder("--quiet")
    last_two = subjects.last(2)

    assert_match(/update a\z/, last_two[0])
    assert_includes commit_message("HEAD~1"), "Changes that were already staged when the recorder ran."
    assert_equal "feat(api): add c", last_two[1]
  end

  def test_renames_deletions_binaries_and_json_records_are_described
    write("lib/rubernetes/api/old_name.rb", "module OldName\n  X = 1\nend\n")
    write("lib/rubernetes/api/gone.rb", "GONE = 1\n")
    write("generated/status.json", JSON.pretty_generate("status" => "pending", "items" => [1, 2], "generated_at" => "t1"))
    File.binwrite(File.join(@dir, "artifact.bin"), [0, 1, 2, 255, 0, 7].pack("C*") * 100)
    run_recorder("--quiet")
    FileUtils.mv(File.join(@dir, "lib/rubernetes/api/old_name.rb"), File.join(@dir, "lib/rubernetes/api/new_name.rb"))
    File.delete(File.join(@dir, "lib/rubernetes/api/gone.rb"))
    write("generated/status.json", JSON.pretty_generate("status" => "ok", "items" => [1, 2, 3], "generated_at" => "t2"))
    File.binwrite(File.join(@dir, "artifact.bin"), [9, 8, 7, 255, 0].pack("C*") * 200)
    status, = run_recorder("--quiet")

    assert_equal 0, status
    recent = subjects.last(4)

    assert_includes recent, "feat(api): rename old name to new name"
    assert_includes recent, "feat(api): remove gone"
    # Every changed top-level key of a record is a "declaration touched".
    assert(recent.any? { |subject| subject.start_with?("chore(generated): refresh status") }, recent.inspect)
    record_body = commit_message(git("log", "-1", "--format=%H", "--grep=refresh status").strip)

    assert_includes record_body, "[pending -> ok]"
    assert_includes record_body, "items: 2 items -> 3 items"
    # Noise fields (timestamps, digests) never appear as headline changes.
    refute_includes record_body.split("Declarations touched").first, "generated_at"
    binary = recent.find { |subject| subject.include?("artifact") }

    refute_nil binary
    assert_includes commit_message(git("log", "-1", "--format=%H", "--grep=artifact").strip), "Git treats this file as binary"
    assert_equal "", git("status", "--porcelain")
  end

  def test_dry_run_changes_nothing_and_reports_the_plan
    write("lib/rubernetes/api/a.rb", "A = 1\n")
    run_recorder("--quiet")
    write("lib/rubernetes/api/a.rb", "A = 2\n")
    head = git("rev-parse", "HEAD").strip
    status, out, = run_recorder("--dry-run")

    assert_equal 0, status
    assert_includes out, "[dry-run] chore(api): update a"
    assert_includes out, "would record 1 commit across 1 file"
    assert_equal head, git("rev-parse", "HEAD").strip
    assert_equal " M lib/rubernetes/api/a.rb\n", git("status", "--porcelain")
  end

  def test_nothing_to_record_leaves_the_repository_alone_and_a_report_is_written
    write("lib/rubernetes/api/a.rb", "A = 1\n")
    run_recorder("--quiet")
    head = git("rev-parse", "HEAD").strip
    report = File.join(@dir, "report.json")
    status, out, = run_recorder("--report", report, "--cycle", "noop")

    assert_equal 0, status
    assert_includes out, "nothing to record"
    assert_equal head, git("rev-parse", "HEAD").strip
    data = JSON.parse(File.read(report))

    assert_equal [], data["commits"]
    assert_equal "noop", data["cycle"]
  end

  def test_head_moving_underneath_makes_the_recorder_retake_the_snapshot
    write("lib/rubernetes/api/a.rb", "A = 1\n")
    run_recorder("--quiet")
    write("lib/rubernetes/api/a.rb", "A = 2\n")
    git_obj = AutoCommit::Git.new(@dir)
    moved = false
    dir = @dir
    original = AutoCommit.method(:write_commits)
    AutoCommit.define_singleton_method(:write_commits) do |git_arg, units, base|
      unless moved
        moved = true
        # Someone else commits between the snapshot and the publish.
        File.write(File.join(dir, "elsewhere.txt"), "x\n")
        Open3.capture3("git", "add", "elsewhere.txt", chdir: dir)
        Open3.capture3("git", "-c", "user.name=Other", "-c", "user.email=o@example.test", "commit", "-q", "-m", "other: commit", chdir: dir)
      end
      original.call(git_arg, units, base)
    end
    begin
      status, _out, err = run_recorder

      assert_equal 0, status
      assert_includes err, "HEAD moved while recording; retaking the snapshot"
    ensure
      AutoCommit.define_singleton_method(:write_commits, original)
    end

    assert_equal ["other: commit", "chore(api): update a"], subjects.last(2)
    assert_equal "", git("status", "--porcelain")
    assert git_obj.head
  end

  def test_the_recorder_never_adds_a_co_author
    write("lib/rubernetes/api/a.rb", "A = 1\n")
    write("docs/guide.md", "# Guide\n")
    run_recorder("--quiet", "--cycle", "check", "--status", "0")
    log = git("log", "--format=%B%n---%an <%ae>")

    refute_match(/co-authored-by|signed-off-by|generated with/i, log)
    assert_includes log, "Recorder Test <recorder@example.test>"
  end

  def test_classification_of_this_repository_layout
    assert_equal %w[api source], AutoCommit.classify("lib/rubernetes/api/server.rb")
    assert_equal %w[raft source], AutoCommit.classify("lib/rubernetes/consensus/wal.rb")
    assert_equal %w[unit tests], AutoCommit.classify("test/unit/foo_test.rb")
    assert_equal %w[repo tools], AutoCommit.classify("tools/repo/auto_commit.rb")
    assert_equal %w[spec docs], AutoCommit.classify("spec/node/runtime.md")
    assert_equal %w[verification verification], AutoCommit.classify("verification/tla/Raft.tla")
    assert_equal %w[generated evidence], AutoCommit.classify("generated/openapi/v3.json")
    assert_equal %w[vendor provenance], AutoCommit.classify("third_party/locks/ruby-3.4.11.json")
    assert_equal %w[deps build], AutoCommit.classify("Gemfile.lock")
    assert_equal %w[docs docs], AutoCommit.classify("README.md")
    assert_equal "tla", AutoCommit.language_of("verification/tla/Raft.tla")
    assert_equal "ruby", AutoCommit.language_of("Rakefile")
  end
end
