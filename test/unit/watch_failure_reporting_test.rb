# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/watch/informer"
require "rubernetes/watch/reflector"

# client-go's reflector logs every failed watch.  Ours only stored the last
# error behind #last_error, which nothing reads, and the Informer never handed
# its error handler down to the Reflector -- so a watch that kept failing was
# completely silent.  A conformance round showed the control plane going deaf
# for 120 s, 180 s and 630 s at a stretch (reconciled 600 -> 24 per interval,
# queue wait 0, workers idle, leader still true) with not one line in the
# controller-manager log: new namespaces never got their default
# ServiceAccount and ten specs died in [BeforeEach].
class WatchFailureReportingTest < Minitest::Test
  Watch = Rubernetes::Watch

  class FailingStream
    def initialize(error) = @error = error
    def each = raise @error
    def close = nil
  end

  class FailingClient
    attr_reader :watch_calls

    def initialize(error)
      @error = error
      @watch_calls = 0
    end

    def list(**_options)
      {"items" => [], "metadata" => {"resourceVersion" => "1"}}
    end

    def watch(**_options)
      @watch_calls += 1
      FailingStream.new(@error)
    end
  end

  def reflector(error, handler)
    Watch::Reflector.new(client: FailingClient.new(error), fifo: Watch::DeltaFIFO.new,
                         resource: "pods", sleeper: ->(_seconds) {}, error_handler: handler)
  end

  def test_a_failing_watch_reaches_the_error_handler
    seen = []
    subject = reflector(IOError.new("connection reset"), ->(error) { seen << error })

    subject.list!
    refute subject.watch_once

    assert_equal 1, seen.length, "the watch failure must be reported, not only remembered"
    assert_kind_of IOError, seen.first
    assert_equal "connection reset", seen.first.message
  end

  def test_every_repeated_failure_is_reported
    seen = []
    subject = reflector(IOError.new("reset"), ->(error) { seen << error })

    subject.list!
    3.times { subject.watch_once }

    assert_equal 3, seen.length, "a watch that keeps failing must keep saying so"
  end

  # Reporting must never be able to end the watch.
  def test_a_handler_that_raises_does_not_break_the_reflector
    subject = reflector(IOError.new("reset"), ->(_error) { raise "handler exploded" })

    subject.list!

    refute subject.watch_once
    assert_kind_of IOError, subject.last_error
  end

  def test_the_informer_hands_its_error_handler_to_the_reflector
    seen = []
    informer = Watch::Informer.new(client: FailingClient.new(IOError.new("reset")),
                                   resource: "pods", sleeper: ->(_seconds) {},
                                   error_handler: ->(error) { seen << error })

    informer.reflector.list!
    informer.reflector.watch_once

    assert_equal 1, seen.length, "an informer's watch failures must reach its own handler"
  end
end
