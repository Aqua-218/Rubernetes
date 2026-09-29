# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/platform/linux/process_supervisor"

# A short workload can exit between the gate's pid/start-time record and the
# supervisor's pidfd_open.  The kernel reports that race as ESRCH or, while
# another reference still pins the struct pid, as EINVAL.  Both must be
# accepted only when the recorded identity is confirmed gone.
class ProcessSupervisorPidfdRaceTest < Minitest::Test
  class RaisingPidfdAdapter
    def initialize(errno)
      @errno = errno
    end

    def open(pid:, resource_id: "pid:#{pid}")
      raise Rubernetes::Platform::Linux::Error.new(errno: @errno, operation: "pidfd_open", resource_id: resource_id)
    end
  end

  def supervisor(errno)
    Rubernetes::Platform::Linux::ProcessSupervisor.new(pidfd_adapter: RaisingPidfdAdapter.new(errno))
  end

  def exited_pid
    pid = Process.fork { exit!(0) }
    Process.waitpid(pid)
    pid
  end

  def test_einval_after_the_workload_exited_is_a_completed_short_process
    pid = exited_pid
    result = supervisor(Errno::EINVAL::Errno).send(:open_live_workload_pidfd, pid, 123_456, "process:test:workload")
    assert_nil result
  end

  def test_esrch_after_the_workload_exited_is_a_completed_short_process
    pid = exited_pid
    result = supervisor(Errno::ESRCH::Errno).send(:open_live_workload_pidfd, pid, 123_456, "process:test:workload")
    assert_nil result
  end

  def test_einval_for_a_live_matching_workload_is_still_fatal
    live = supervisor(Errno::EINVAL::Errno)
    start_time = live.send(:process_start_time, Process.pid)
    error = assert_raises(Rubernetes::Platform::Linux::Error) do
      live.send(:open_live_workload_pidfd, Process.pid, start_time, "process:test:workload")
    end
    assert_equal Errno::EINVAL::Errno, error.errno
  end

  def test_a_changed_start_time_never_attaches_to_a_reused_pid
    live = supervisor(Errno::EINVAL::Errno)
    start_time = live.send(:process_start_time, Process.pid)
    assert_nil live.send(:open_live_workload_pidfd, Process.pid, start_time + 1, "process:test:workload")
  end
end
