# frozen_string_literal: true

require "securerandom"
require "tmpdir"
require_relative "../test_helper"
require_relative "../../tools/conformance/cluster"
require_relative "../../tools/conformance/retirable_image_cache"

class ConformanceImageCacheRetirementTest < Minitest::Test
  Retirable = Conformance::RetirableImageCache
  PROFILE = "linux-amd64-ipv4-native"

  def setup
    @base = Dir.mktmpdir("rubernetes-cache-retirement")
    @root = File.join(@base, PROFILE)
    @cache = File.join(@root, "runtime/worker-0/ledger.jsonl.images")
    @cgroup = File.join(Retirable::CGROUP_ROOT, "rubernetes-retirement-#{Process.pid}-#{SecureRandom.hex(4)}")
    Dir.mkdir(@cgroup)
    FileUtils.mkdir_p(@cache)
    File.binwrite(File.join(@cache, "layer"), "image data" * 65_536)
    @kubeconfig = File.join(@root, "kubeconfig")
    File.write(@kubeconfig, "fixture kubeconfig")
    @descriptor = {"root" => @root, "kind" => "conformance_cluster", "profile" => {"name" => PROFILE},
                   "ready_at" => "2026-11-19T00:00:00Z", "cgroup_root" => @cgroup,
                   "kubeconfig" => @kubeconfig, "isolated_worker_networks" => true,
                   "processes" => [{"name" => "agent-worker-0", "pid" => Process.pid, "config" => File.join(@root, "agent.yml")}]}
    File.write(File.join(@root, "cluster.json"), JSON.generate(@descriptor))
    Retirable.new(@root, @descriptor).register!
  rescue Errno::EACCES, Errno::EPERM, Errno::EROFS
    skip "requires an isolated writable cgroup v2 root"
  end

  def teardown
    Dir.rmdir(@cgroup) if @cgroup && File.directory?(@cgroup)
    FileUtils.remove_entry_secure(@base) if @base && File.directory?(@base)
  end

  def test_down_retires_only_the_recorded_cache_after_a_successful_full_result
    File.write(File.join(@root, "runtime/worker-0/ledger.jsonl"), "retain runtime ledger")
    receipt = write_receipt
    out, status = run_down(receipt)
    result = JSON.parse(out)

    assert_equal 0, status.exitstatus, out
    assert_equal [@cache], result.dig("retired_image_cache", "directories")
    assert_operator result.dig("retired_image_cache", "allocated_bytes"), :>=, 655_360
    refute_path_exists @cache
    assert_path_exists File.join(@root, "runtime/worker-0/ledger.jsonl")
    assert_path_exists receipt
    assert_path_exists File.join(File.dirname(receipt), "k1/hydrophone/junit_01.xml")
  end

  def test_rejects_failed_results_and_a_replaced_cache_directory
    error = run_down(write_receipt(success: false))

    assert_equal 1, error.last.exitstatus
    assert_path_exists File.join(@cache, "layer")

    moved = "#{@cache}-outside"
    File.rename(@cache, moved)
    File.symlink(moved, @cache)
    out, status = run_down(write_receipt)

    assert_equal 1, status.exitstatus
    assert_match(/unowned or noncanonical fixture directory/, JSON.parse(out).fetch("detail"))
    assert_path_exists File.join(moved, "layer")
  end

  def test_requires_an_opt_in_from_the_fresh_fixture
    File.unlink(File.join(@root, Retirable::MARKER))
    out, status = run_down(write_receipt)

    assert_equal 1, status.exitstatus
    assert_match(/fixture did not opt in/, JSON.parse(out).fetch("detail"))
    assert_path_exists File.join(@cache, "layer")
  end

  def test_refuses_to_retire_with_remaining_workloads
    process = fork { sleep 30 }
    File.write(File.join(@cgroup, "cgroup.procs"), process.to_s)
    out, status = run_down(write_receipt)

    assert_equal 1, status.exitstatus
    assert_match(/fixture cgroup still contains live workloads/, JSON.parse(out).fetch("detail"))
    assert_path_exists File.join(@cache, "layer")
  ensure
    if process
      Process.kill("TERM", process)
      Process.wait(process)
    end
  end

  def test_refuses_to_delete_a_bind_mount_inside_the_recorded_cache
    external = File.join(@base, "outside-cache")
    target = File.join(@cache, "mounted")
    FileUtils.mkdir_p([external, target])
    sentinel = File.join(external, "sentinel")
    File.write(sentinel, "keep")
    shell = 'mount --bind "$1" "$2"; shift 2; exec "$@"'
    bind = ["unshare", "-m", "--propagation", "private", "--", "sh", "-ecu", shell, "_", external, target]
    out, error, status = Open3.capture3(*bind, *down_command(write_receipt))
    skip error.strip if error.match?(/\Aunshare: .*Operation not permitted/)

    assert_empty error
    assert_equal 1, status.exitstatus
    assert_match(/a mount still references the fixture image cache/, JSON.parse(out).fetch("detail"))
    assert_path_exists sentinel
    assert_path_exists File.join(@cache, "layer")
  end

  private

  def run_down(receipt)
    out, error, status = Open3.capture3(*down_command(receipt))

    assert_empty error
    [out, status]
  end

  def down_command(receipt)
    [RbConfig.ruby, File.join(Conformance::Lock::ROOT, "tools/conformance/cluster.rb"),
     "down", "--root", @base, "--retire-images-after", receipt]
  end

  def write_receipt(success: true)
    output = File.join(@base, "evidence")
    command = File.join(output, "k1/hydrophone-command.json")
    junit = File.join(output, "k1/hydrophone/junit_01.xml")
    FileUtils.mkdir_p(File.dirname(junit))
    File.write(command, JSON.generate({"command" => ["hydrophone", "--conformance", "--kubeconfig", @kubeconfig],
                                       "exit_status" => 0, "timed_out" => false}))
    File.write(junit, "<testsuite/>")
    count = Conformance::Lock.conformance_definition.fetch("test_count")
    lane = {"lane" => "K1", "status" => success ? "COMPLETE" : "FAILED", "passed" => success,
            "summary" => {"selected" => count, "passed" => count, "failed" => 0, "skipped" => 0, "flaked" => 0,
                          "suite_passed" => true, "execution_properties_match" => true, "unexpected_executions" => []},
            "codenames" => {"unexpected_codenames" => [], "unmatched_codenames" => [], "duplicate_codenames" => []}}
    manifest = File.join(output, "manifest.json")
    artifacts = [command, junit].map { |path| {"path" => path, "sha256" => Digest::SHA256.file(path).hexdigest} }
    File.write(manifest, JSON.generate({"profile" => PROFILE, "sourceCommit" => Conformance::Lock.source_commit,
                                        "startedAt" => "2026-11-19T00:00:01Z", "summary" => {"passed" => success},
                                        "lanes" => [lane], "artifacts" => artifacts}))
    manifest
  end
end
