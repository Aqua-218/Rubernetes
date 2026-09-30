# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/platform/linux/process_supervisor"
require "tmpdir"

# A followed container log must end when its reader goes away.  `stop` only
# reports the WRITER (the container) gone, so before this an idle log followed
# by a disconnected client polled at 10Hz forever: 379 of the node agent's 603
# threads in the 2026-09-14 K1 run were parked in this loop.
#
# Specification: spec/node/logs.md (log streaming lifecycle).
class ProcessSupervisorLogFollowTest < Minitest::Test
  Rotator = Rubernetes::Platform::Linux::ProcessSupervisor::LogRotator

  def test_a_followed_log_ends_when_the_reader_closes_it
    Dir.mktmpdir("log-follow") do |dir|
      path = File.join(dir, "stdout.log")
      File.binwrite(path, "first\n")
      rotator = Rotator.new(path: path, max_bytes: 1 << 20, max_files: 2)
      # The container keeps running: `stop` never reports it finished, which
      # is exactly the case that used to leak.
      stream = rotator.read(follow: true, stop: -> { false })
      chunks = Queue.new
      reader = Thread.new { stream.each { |chunk| chunks << chunk } }

      assert_equal "first\n", chunks.pop
      # Append, the way a container writes: rewriting the file whole would
      # look like a rotation to the follower.
      File.open(path, "ab") { |file| file.write("second\n") }

      assert_equal "second\n", chunks.pop

      stream.close

      assert reader.join(5), "closing a followed log must end its reader"
      assert_predicate stream, :closed?
    end
  end

  # sinceTime/sinceSeconds name a moment, not a byte offset: a timestamp used
  # to raise from Integer() and sinceSeconds=3600 silently skipped 3600 bytes
  # ("[sig-node] Kubelet ... should print the output to logs").
  def test_since_selects_the_log_written_from_a_moment
    Dir.mktmpdir("log-since") do |dir|
      rotator = Rotator.new(path: File.join(dir, "container.log"), max_bytes: 16, max_files: 3)
      now = Time.utc(2026, 9, 16, 12, 0, 0)
      rotator.clock = -> { now }
      rotator.append("old line\n")
      now += 10
      rotator.append("Hello World\n")
      now += 10
      rotator.append("later\n")

      assert_equal "old line\nHello World\nlater\n", rotator.read(since: Time.utc(2026, 9, 16, 11))
      assert_equal "Hello World\nlater\n", rotator.read(since: "2026-09-16T12:00:05Z")
      assert_equal "later\n", rotator.read(since: "2026-09-16T12:00:20.000000000Z")
      assert_equal "", rotator.read(since: "2026-09-16T13:00:00Z")
      assert_equal "World\nlater\n", rotator.read(since: 15)
    end
  end

  def test_timestamps_prefix_each_line_with_its_write_time
    Dir.mktmpdir("log-timestamps") do |dir|
      rotator = Rotator.new(path: File.join(dir, "container.log"), max_bytes: 1 << 20, max_files: 2)
      now = Time.utc(2026, 9, 16, 12, 0, 0)
      rotator.clock = -> { now }
      rotator.append("one\ntwo\n")
      now += 1.5
      rotator.append("three\n")

      assert_equal "2026-09-16T12:00:00.000000000Z one\n2026-09-16T12:00:00.000000000Z two\n" \
                   "2026-09-16T12:00:01.500000000Z three\n", rotator.read(timestamps: true)
      assert_equal "2026-09-16T12:00:01.500000000Z three\n", rotator.read(timestamps: true, tail: 1)
    end
  end

  def test_a_followed_log_still_ends_when_the_container_exits
    Dir.mktmpdir("log-follow") do |dir|
      path = File.join(dir, "stdout.log")
      File.binwrite(path, "done\n")
      rotator = Rotator.new(path: path, max_bytes: 1 << 20, max_files: 2)
      stream = rotator.read(follow: true, stop: -> { true })

      assert_equal ["done\n"], stream.to_a
    end
  end

  def test_the_stream_answers_the_close_contract_the_transport_uses
    Dir.mktmpdir("log-follow") do |dir|
      path = File.join(dir, "stdout.log")
      File.binwrite(path, "x\n")
      stream = Rotator.new(path: path, max_bytes: 1 << 20, max_files: 2).read(follow: true, stop: -> { false })

      assert_respond_to stream, :close
      assert_respond_to stream, :closed?
      assert_respond_to stream, :to_enum
      stream.close
    end
  end
end
