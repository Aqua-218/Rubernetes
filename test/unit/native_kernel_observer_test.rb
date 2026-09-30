# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/runtime/native"

# The observer exists so recovery can tell "gone" from "reused" from "still
# here".  Getting that wrong in either direction is a correctness failure:
# calling a reused pid dead invites deleting a live workload's resources, and
# calling a dead resource live wedges recovery forever.
class NativeKernelObserverTest < Minitest::Test
  Observer = Rubernetes::Runtime::Native::KernelObserver

  class FakeLedger
    def initialize(resources) = @resources = resources
    def resources(include_released: false) = @resources
  end

  def setup
    @pid = Process.pid
    @start_time = real_start_time(@pid)
  end

  def test_reports_a_live_process_with_the_claimed_identity
    entries = observe([process_claim(pid: @pid, start_time: @start_time)])

    assert_equal(1, entries.length)
    assert_equal("process:sb:c:#{@pid}:#{@start_time}:none", entries.first.fetch("identity"))
    assert_equal(true, entries.first.dig("metadata", "live"))
  end

  def test_omits_a_process_that_no_longer_exists
    dead = spawn_and_reap

    assert_empty(observe([process_claim(pid: dead, start_time: "1")]))
  end

  def test_reports_a_reused_pid_with_a_different_identity
    claimed = process_claim(pid: @pid, start_time: (@start_time.to_i + 12_345).to_s)
    entry = observe([claimed]).fetch(0)

    refute_equal(claimed.fetch("identity"), entry.fetch("identity"),
                 "a reused pid must not be reported under the claimed identity")
    assert_equal(true, entry.dig("metadata", "identity_mismatch"))
    assert_equal(true, entry.dig("metadata", "live"),
                 "a reused pid is live: recovery must refuse to clean it, not treat it as dead")
  end

  def test_reports_a_present_directory_and_omits_a_removed_one
    Dir.mktmpdir("kernel-observer-") do |directory|
      stat = File.stat(directory)
      present = observe([path_claim(directory, device: stat.dev, inode: stat.ino)])

      assert_equal(1, present.length)
      assert_equal(true, present.first.dig("metadata", "live"))

      missing = observe([path_claim(File.join(directory, "gone"), device: stat.dev, inode: stat.ino)])

      assert_empty(missing)
    end
  end

  def test_reports_a_recreated_directory_as_an_identity_mismatch
    Dir.mktmpdir("kernel-observer-") do |directory|
      claim = path_claim(directory, device: File.stat(directory).dev, inode: File.stat(directory).ino + 1)
      entry = observe([claim]).fetch(0)

      refute_equal(claim.fetch("identity"), entry.fetch("identity"))
      assert_equal(true, entry.dig("metadata", "identity_mismatch"))
    end
  end

  def test_a_claim_without_kernel_evidence_is_neither_adopted_nor_released
    entry = observe([{"kind" => "workspace", "id" => "w1", "identity" => "workspace:w1",
                      "owner" => "op", "state" => "Running", "metadata" => {}}]).fetch(0)

    assert_equal(false, entry.dig("metadata", "live"), "no evidence must not read as live")
    assert_equal(true, entry.dig("metadata", "unverifiable"))
    assert_equal("workspace:w1", entry.fetch("identity"),
                 "absent evidence is not reuse evidence: the identity must be unchanged")
  end

  def test_declares_itself_external
    assert_predicate(Observer.new(ledger: FakeLedger.new([])), :external_observer?)
  end

  private

  def observe(claims) = Observer.new(ledger: FakeLedger.new(claims)).list_resources

  def process_claim(pid:, start_time:)
    {"kind" => "process", "id" => "sb:c", "identity" => "process:sb:c:#{pid}:#{start_time}:none",
     "owner" => "op-1", "state" => "Running",
     "metadata" => {"workload_pid" => pid, "workload_start_time" => start_time}}
  end

  def path_claim(path, device:, inode:)
    {"kind" => "workspace", "id" => path, "identity" => "workspace:#{path}:#{inode}",
     "owner" => "op-1", "state" => "Running",
     "metadata" => {"path" => path, "device" => device, "inode" => inode}}
  end

  def real_start_time(pid)
    stat = File.read("/proc/#{pid}/stat")
    stat[(stat.rindex(")") + 1)..].split[19]
  end

  def spawn_and_reap
    pid = Process.spawn("/bin/true", out: File::NULL, err: File::NULL)
    Process.waitpid(pid)
    pid
  end
end
