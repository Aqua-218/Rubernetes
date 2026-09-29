# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/platform/linux/namespace_process"

# The child's failure pipe was wrapped in an AUTOCLOSING IO that was never
# closed (IO.for_fd(fd).read), while the ensure closed the same descriptor
# through a second IO.  When the GC later finalised the first wrapper it closed
# that descriptor NUMBER again -- by then owned by something else.  On
# 2026-09-14 that closed the node agent's streaming listener at 15:07 and
# glibc's netlink socket at 15:18; glibc answers EBADF on its netlink
# descriptor with __libc_fatal ("Unexpected error 9 on netlink descriptor
# 164.") and aborts, killing the node agent in the middle of a conformance run.
class NamespaceProcessDescriptorOwnershipTest < Minitest::Test
  Subject = Rubernetes::Platform::Linux::NamespaceProcess

  class FakePidfd
    def wait(pidfd:, timeout:, resource_id:) = {"exited" => true}
    def send_signal(**) = true
  end

  def setup
    @reader, @writer = IO.pipe
    @spawn = Subject::Spawn.new(pid: 4242, pidfd: 7, error_fd: @reader.fileno)
  end

  def teardown
    # wait() takes ownership of the read end, so the fixture's own wrapper may
    # already be pointing at a closed descriptor.
    begin
      @reader.close unless @reader.closed?
    rescue Errno::EBADF, IOError
      nil
    end
    begin
      @writer.close unless @writer.closed?
    rescue Errno::EBADF, IOError
      nil
    end
  end

  def run_wait
    Rubernetes::Platform::Linux::Pidfd.stub(:new, FakePidfd.new) do
      Subject.new.wait(spawn: @spawn, timeout: 1.0, resource_id: "test")
    end
  end

  def test_the_failure_pipe_is_closed_exactly_once
    @writer.close
    fd = @reader.fileno

    run_wait

    refute File.exist?("/proc/self/fd/#{fd}"), "the failure pipe must be closed when wait returns"
    # And no surviving wrapper may close that number again later.
    5.times { GC.start }
    refute File.exist?("/proc/self/fd/#{fd}"), "the descriptor must not be reopened or double-closed"
  end

  def test_a_second_descriptor_is_not_stolen_by_a_finalised_wrapper
    @writer.close
    run_wait

    # Take the descriptor number back for something else, then force GC: a
    # leaked autoclosing wrapper would close this victim.
    victim_read, victim_write = IO.pipe
    5.times { GC.start }

    assert_equal "alive", begin
      victim_write.write("alive")
      victim_write.flush
      victim_read.read(5)
    end
    victim_read.close
    victim_write.close
  end

  def test_child_failure_is_still_reported
    @writer.write([2, Errno::EPERM::Errno].pack("l2"))
    @writer.close

    error = assert_raises(Rubernetes::Platform::Linux::Error) { run_wait }

    assert_equal Errno::EPERM::Errno, error.errno
  end

  def test_a_missing_error_descriptor_is_not_fatal
    spawn = Subject::Spawn.new(pid: 1, pidfd: 7, error_fd: nil)
    result = Rubernetes::Platform::Linux::Pidfd.stub(:new, FakePidfd.new) do
      Subject.new.wait(spawn: spawn, timeout: 1.0, resource_id: "test")
    end

    assert_equal 1, result.pid
  end
end
