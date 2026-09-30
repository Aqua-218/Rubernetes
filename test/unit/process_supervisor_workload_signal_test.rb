# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/platform/linux/process_supervisor"

# Stopping a container signals its workload, not the wrapper that forked it:
# the wrapper still carries the agent's Ruby signal handlers and swallowed
# SIGTERM, so every Pod delete sat out its whole grace period.
class ProcessSupervisorWorkloadSignalTest < Minitest::Test
  Supervisor = Rubernetes::Platform::Linux::ProcessSupervisor
  TERM = Signal.list.fetch("TERM")
  KILL = Signal.list.fetch("KILL")

  class RecordingPidfdAdapter
    attr_reader :signals

    def initialize(gone: [])
      @signals = []
      @gone = gone
    end

    def send_signal(pidfd:, signal:, resource_id:)
      if @gone.include?(pidfd)
        raise Rubernetes::Platform::Linux::Error.new(errno: Errno::ESRCH::Errno, operation: "pidfd_send_signal", resource_id: resource_id)
      end

      @signals << [pidfd, signal]
      true
    end
  end

  WRAPPER_FD = 11
  WORKLOAD_FD = 12

  def handle(workload_pidfd: WORKLOAD_FD)
    fields = Supervisor::Handle.members.to_h { |name| [name, nil] }
    Supervisor::Handle.new(**fields, id: "c1", pid: 100, pidfd: WRAPPER_FD, workload_pid: 101, workload_pidfd: workload_pidfd,
                                     state: :running)
  end

  def signal(adapter, value, target = handle)
    Supervisor.new(pidfd_adapter: adapter).send(:send_signal, target, value, "process:c1")
  end

  def test_term_reaches_the_workload_and_not_the_wrapper
    adapter = RecordingPidfdAdapter.new
    signal(adapter, TERM)

    assert_equal [[WORKLOAD_FD, TERM]], adapter.signals
  end

  def test_kill_reaches_workload_and_wrapper
    adapter = RecordingPidfdAdapter.new
    signal(adapter, KILL)

    assert_equal [[WORKLOAD_FD, KILL], [WRAPPER_FD, KILL]], adapter.signals
  end

  def test_workload_already_gone_falls_back_to_the_wrapper
    adapter = RecordingPidfdAdapter.new(gone: [WORKLOAD_FD])
    signal(adapter, TERM)

    assert_equal [[WRAPPER_FD, TERM]], adapter.signals
  end

  def test_process_without_a_separate_workload_signals_its_own_pidfd
    adapter = RecordingPidfdAdapter.new
    signal(adapter, TERM, handle(workload_pidfd: nil))

    assert_equal [[WRAPPER_FD, TERM]], adapter.signals
  end
end
