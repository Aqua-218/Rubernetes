# frozen_string_literal: true

require "tmpdir"
require_relative "../test_helper"
require "rubernetes/runtime/cri/logs"

# CRI container log files (kubelet kuberuntime/logs): records joined across
# partials, stream selection, since, tail, timestamps and follow.
class CRILogsTest < Minitest::Test
  Logs = Rubernetes::Runtime::CRI::Logs

  LOG = <<~LOG
    2026-09-24T00:00:01.000000001Z stdout F hello
    2026-09-24T00:00:02.000000002Z stderr F warning
    2026-09-24T00:00:03.000000003Z stdout P par
    2026-09-24T00:00:03.500000000Z stderr F interleaved
    2026-09-24T00:00:04.000000004Z stdout F tial
    not a record
    2026-09-24T00:00:05.000000005Z stdout F last
  LOG

  def with_log(content = LOG)
    Dir.mktmpdir("cri-logs") do |dir|
      path = File.join(dir, "0.log")
      File.write(path, content)
      yield path
    end
  end

  def test_both_streams_with_partials_joined
    with_log do |path|
      assert_equal "hello\nwarning\ninterleaved\npartial\nlast\n", Logs.read(path)
    end
  end

  def test_stream_since_tail_and_timestamps
    with_log do |path|
      assert_equal "hello\npartial\nlast\n", Logs.read(path, stream: :stdout)
      assert_equal "warning\ninterleaved\n", Logs.read(path, stream: "stderr")
      assert_equal "interleaved\npartial\nlast\n", Logs.read(path, since: "2026-09-24T00:00:03Z")
      assert_equal "partial\nlast\n", Logs.read(path, tail: 2)
      assert_equal "2026-09-24T00:00:05.000000005Z last\n", Logs.read(path, tail: 1, timestamps: true)
      assert_equal "", Logs.read(File.join(File.dirname(path), "missing.log"))
    end
  end

  def test_follow_yields_what_is_appended_until_the_container_stops
    with_log("2026-09-24T00:00:01Z stdout F one\n") do |path|
      running = true
      stream = Logs.read(path, follow: true, running: -> { running })
      chunks = Queue.new
      reader = Thread.new { stream.each { |chunk| chunks << chunk } }

      assert_equal "one\n", chunks.pop
      File.write(path, "2026-09-24T00:00:02Z stdout F two\n", mode: "a")

      assert_equal "two\n", chunks.pop
      running = false
      reader.join(5)

      refute_predicate reader, :alive?
    end
  end
end
