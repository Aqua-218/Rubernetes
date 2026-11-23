# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/platform/linux/native_adapters"
require "timeout"

class NamespaceHelperReplyTest < Minitest::Test
  class ForkedAdapter < Rubernetes::Platform::Linux::NativeAdapters::NamespaceAdapter
    def initialize(release)
      @release = release
    end

    private

    def lookup(value) = value

    def open_namespace_descriptors(_value, only:) = {}

    def supervise_namespace_helper(value, descriptors, writer, _timeout, &)
      # An unrelated sandbox process inherits this response pipe. Leave it
      # open until after the caller has received the helper's reply.
      Process.fork do
        @release.getbyte
        exit!(0)
      end
      run_in_namespaces(value, descriptors, writer, &)
    end
  end

  class HeldRetirementAdapter < ForkedAdapter
    def initialize(release, started)
      super(release)
      @started = started
    end

    private

    def supervise_namespace_helper(_value, _descriptors, writer, _timeout)
      writer.puts(JSON.generate("ok" => true, "value" => "success"))
      writer.close
      @started.puts(Process.pid)
      @started.close
      @release.getbyte
      exit!(0)
    end
  end

  def test_a_complete_reply_does_not_wait_for_other_forked_writers_to_close
    release, signal = IO.pipe
    adapter = ForkedAdapter.new(release)
    message = "first line\nsecond line"

    assert_equal(message, Timeout.timeout(5) { adapter.within_namespaces("fixture") { message } })
  ensure
    signal&.write("1")
    signal&.close
    release&.close
  end

  def test_cancelled_retirement_reaps_the_helper_after_it_exits
    release, signal = IO.pipe
    noticed, started = IO.pipe
    adapter = HeldRetirementAdapter.new(release, started)

    assert_raises(Timeout::Error) do
      Timeout.timeout(0.5, Timeout::Error) { adapter.within_namespaces("fixture") { "success" } }
    end

    noticed.timeout = 1
    pid = Integer(noticed.gets)
    signal.write("1")
    assert_raises(Errno::ESRCH) do
      Timeout.timeout(2) do
        loop do
          Process.kill(0, pid)
          sleep 0.01
        end
      end
    end
  ensure
    [signal, release, noticed, started].each { |io| io&.close }
    Process.detach(pid) if pid
  end
end
