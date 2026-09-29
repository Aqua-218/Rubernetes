# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/bootstrap"

# Every control-plane loop retries a transient fault with a bounded backoff
# and ends the process on anything else.  The helper lived on one service
# only, so the scheduler's rescue path called a method it did not have: the
# first retryable API error killed the scheduler with NoMethodError and the
# cluster stopped scheduling Pods until someone noticed.
class ControlPlaneLoopErrorsTest < Minitest::Test
  SERVICES = [Rubernetes::Bootstrap::SchedulerService,
              Rubernetes::Bootstrap::ControllerManagerService].freeze

  def test_every_loop_service_can_classify_its_own_errors
    SERVICES.each do |service|
      assert(service.method_defined?(:transient_loop_error?) ||
             service.private_method_defined?(:transient_loop_error?),
             "#{service} must be able to classify a transient loop error")
      assert(service.method_defined?(:loop_backoff) || service.private_method_defined?(:loop_backoff),
             "#{service} must be able to compute its retry backoff")
    end
  end

  def test_transient_classification_matches_the_retryable_conditions
    helper = Object.new.extend(Rubernetes::Bootstrap::TransientLoopErrors)

    assert helper.transient_loop_error?(IOError.new("connection reset"))
    assert helper.transient_loop_error?(Errno::ECONNREFUSED.new)
    assert helper.transient_loop_error?(RuntimeError.new("Kubernetes API request failed with HTTP 503"))
    assert helper.transient_loop_error?(RuntimeError.new("request timed out"))
    refute helper.transient_loop_error?(ArgumentError.new("bad field"))
    refute helper.transient_loop_error?(RuntimeError.new("HTTP 404 not found"))
  end

  def test_backoff_is_bounded_and_monotonic
    helper = Object.new.extend(Rubernetes::Bootstrap::TransientLoopErrors)
    delays = (1..8).map { |failures| helper.loop_backoff(failures) }

    assert_equal delays.sort, delays
    assert_equal delays.last, helper.loop_backoff(100)
    assert_operator delays.last, :<=, 5.0
  end
end
