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

  class MemoryLogAdapter
    def initialize = @files = {}
    def exists?(path) = @files.key?(path)
    def read(path) = @files.fetch(path)
    def append(path, bytes) = (@files[path] ||= "".b) << bytes

    def rotate(path:, max_files:)
      (max_files - 1).downto(1) do |index|
        source = index == 1 ? path : "#{path}.#{index - 1}"
        target = "#{path}.#{index}"
        @files.delete(target)
        @files[target] = @files.delete(source) if exists?(source)
      end
      @files[path] = "".b
    end
  end

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

  def test_an_oversized_append_fills_existing_files_and_preserves_only_the_retained_suffix
    Dir.mktmpdir("log-rotate") do |dir|
      path = File.join(dir, "container.log")
      File.binwrite(path, "abc")
      File.binwrite("#{path}.1", "old\n")
      rotator = Rotator.new(path: path, max_bytes: 4, max_files: 3)

      assert_equal 6, rotator.append("defghi")
      assert_equal(%w[abcd efgh i], ["#{path}.2", "#{path}.1", path].map { |entry| File.binread(entry) })
      assert_equal "abcdefghi", rotator.read

      assert_equal 16, rotator.append("123456789abcdefg")
      assert_equal(%w[89ab cdef g], ["#{path}.2", "#{path}.1", path].map { |entry| File.binread(entry) })
      assert_equal "89abcdefg", rotator.read
    end
  end

  def test_an_independent_native_writer_replacing_the_log_with_the_same_bytes_is_followed
    [1, 2].each do |max_files|
      Dir.mktmpdir("log-follow-rotation") do |dir|
        path = File.join(dir, "container.log")
        writer = Rotator.new(path: path, max_bytes: 5, max_files: max_files)
        reader = Rotator.new(path: path, max_bytes: 5, max_files: max_files)
        writer.append("same\n")
        stream = reader.read(follow: true, tick: -> { writer.append("same\n") }, stop: -> { true })

        assert_equal "same\nsame\n", stream.to_a.join
      end
    end
  end

  def test_follow_retries_when_an_independent_writer_moves_files_during_a_poll
    Dir.mktmpdir("log-follow-rotation") do |dir|
      path = File.join(dir, "container.log")
      writer = Rotator.new(path: path, max_bytes: 4, max_files: 3)
      reader = Rotator.new(path: path, max_bytes: 4, max_files: 3)
      writer.append("aaaa")
      polls = 0
      move_file = false
      reader.define_singleton_method(:read_segment) do |index, cursor = nil|
        if move_file && index == 1
          move_file = false
          writer.append("cccc")
        end
        super(index, cursor)
      end
      tick = lambda do
        polls += 1
        if polls == 1
          writer.append("bbbb")
          move_file = true
        end
      end
      stream = reader.read(follow: true, tick: tick, stop: -> { polls == 2 })

      assert_equal "aaaabbbbcccc", stream.to_a.join
      assert_equal(%w[aaaa bbbb cccc], ["#{path}.2", "#{path}.1", path].map { |file| File.binread(file) })
    end
  end

  def test_follow_drains_unread_archived_bytes_and_keeps_line_timestamps_across_boundaries
    Dir.mktmpdir("log-follow-rotation") do |dir|
      rotator = Rotator.new(path: File.join(dir, "container.log"), max_bytes: 4, max_files: 4)
      now = Time.utc(2026, 9, 16, 12, 0, 0)
      rotator.clock = -> { now }
      rotator.append("ab")
      tick = lambda do
        now += 1
        rotator.append("cd\nefgh\nij\n")
      end
      stream = rotator.read(follow: true, tick: tick, stop: -> { true }, timestamps: true)

      assert_equal ["2026-09-16T12:00:00.000000000Z ab",
                    "cd\n2026-09-16T12:00:01.000000000Z efgh\n2026-09-16T12:00:01.000000000Z ij\n"], stream.to_a
      assert_equal "cd\nefgh\nij\n", rotator.read(since: Time.utc(2026, 9, 16, 12, 0, 1))
      assert_equal "abcd\nefgh\nij\n", rotator.read
    end
  end

  def test_follow_and_cap_work_with_an_adapter_without_a_size_method
    adapter = MemoryLogAdapter.new
    rotator = Rotator.new(path: "/example/container.log", max_bytes: 4, max_files: 2, adapter: adapter)
    rotator.append("ab")
    stream = rotator.read(follow: true, tick: -> { rotator.append("cdefgh") }, stop: -> { true })

    assert_equal %w[ab cdefgh], stream.to_a
    assert_equal "abcd", adapter.read("#{rotator.path}.1")
    assert_equal "efgh", adapter.read(rotator.path)
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
