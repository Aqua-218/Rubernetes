# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/platform/linux/process_supervisor"
require "timeout"

# CRI semantics: a container gets /dev/null as stdin unless it asked for one
# (v1.Container stdin: true).  An open pipe nobody writes to kept busybox's
# default `sh` blocked in read(2) for ever, so the init container of
# "[sig-node] Pods Extended pod generation should start at 1" never finished
# and the Pod never left Pending.
class ProcessStdinDefaultTest < Minitest::Test
  Adapter = Rubernetes::Platform::Linux::ProcessSupervisor::ForkAdapter

  def wait_for_exit(pid, seconds)
    Timeout.timeout(seconds) { Process.wait2(pid) }
  rescue Timeout::Error
    nil
  end

  def test_a_process_without_stdin_reads_eof_and_exits
    process = Adapter.new.spawn(command: ["sh"], gate: false)

    assert_nil process[:stdin], "no stdin handle when the container did not ask for one"
    _pid, status = wait_for_exit(process[:pid], 5) || flunk("sh must exit at EOF on stdin")

    assert_equal 0, status.exitstatus
  ensure
    [process[:stdout], process[:stderr], process[:gate]].compact.each { |io| io.close unless io.closed? }
  end

  def test_a_process_with_stdin_keeps_it_open_until_the_writer_closes
    process = Adapter.new.spawn(command: ["sh"], gate: false, stdin: true)

    refute_nil process[:stdin]
    assert_nil wait_for_exit(process[:pid], 0.5), "sh must wait for input while stdin is open"
    process[:stdin].write("exit 3\n")
    process[:stdin].close
    _pid, status = wait_for_exit(process[:pid], 5) || flunk("sh must exit once stdin closes")

    assert_equal 3, status.exitstatus
  ensure
    [process[:stdout], process[:stderr], process[:gate]].compact.each { |io| io.close unless io.closed? }
  end
end
