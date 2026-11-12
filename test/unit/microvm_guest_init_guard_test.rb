# frozen_string_literal: true

require "test_helper"
require "open3"
require "rbconfig"

# The guest init remounts /proc, /run and /tmp.  Loaded or run anywhere but
# as a VM's PID 1 it must not get that far.
class MicrovmGuestInitGuardTest < Minitest::Test
  INIT = File.expand_path("../../lib/rubernetes/runtime/microvm/guest/init.rb", __dir__)

  def mounts = File.readlines("/proc/self/mountinfo").length

  def test_requiring_it_outside_a_guest_does_nothing
    before = mounts
    output, status = Open3.capture2e(RbConfig.ruby, "-e", "require #{INIT.inspect}; puts :returned")

    assert_predicate status, :success?, output
    assert_equal "returned", output.strip
    assert_equal before, mounts
  end

  def test_running_it_outside_a_guest_is_refused
    before = mounts
    output, status = Open3.capture2e(RbConfig.ruby, INIT)

    refute_predicate status, :success?
    assert_match(/only runs as PID 1/, output)
    assert_equal before, mounts
  end

  def test_the_guard_comes_before_any_other_code
    code = File.readlines(INIT).reject { |line| line.start_with?("#") || line.strip.empty? }

    assert_equal "unless Process.pid == 1\n", code.first
  end
end
