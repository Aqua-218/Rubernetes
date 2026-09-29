# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/controller"

# A controller's requeue timer (upstream queue.AddAfter on that controller's
# own queue) must come back to that controller only.  The key used to return
# unrouted, and an unrouted key is offered to every controller that can find
# an object under its name: the endpointslice controller's 15 s resync of
# each Service also ran the endpoints and mirroring controllers on it, and the
# 200 Services of "[sig-network] Service endpoints latency should not be very
# high" turned that into thousands of no-op reconciles ahead of real work.
class ControllerTimerRouteTest < Minitest::Test
  Manager = Rubernetes::Controller::Manager

  def manager
    subject = Manager.allocate
    subject.instance_variable_set(:@queue_routes, {})
    subject.instance_variable_set(:@route_mutex, Mutex.new)
    subject
  end

  def test_a_fired_timer_is_routed_to_the_controllers_that_set_it
    subject = manager
    subject.send(:remember_timer_routes, "ns/svc", ["endpointslice-controller"])

    subject.send(:promote_timer_routes, "ns/svc")

    assert_equal ["endpointslice-controller"], subject.instance_variable_get(:@queue_routes)["ns/svc"]
  end

  def test_timer_routes_join_the_routes_of_events_that_arrived_meanwhile
    subject = manager
    subject.instance_variable_get(:@queue_routes)["ns/svc"] = ["endpoints-controller"]
    subject.send(:remember_timer_routes, "ns/svc", ["endpointslice-controller"])

    subject.send(:promote_timer_routes, "ns/svc")

    assert_equal %w[endpoints-controller endpointslice-controller], subject.instance_variable_get(:@queue_routes)["ns/svc"]
  end

  def test_a_timer_is_promoted_once
    subject = manager
    subject.send(:remember_timer_routes, "ns/svc", ["endpointslice-controller"])
    subject.send(:promote_timer_routes, "ns/svc")
    subject.instance_variable_get(:@queue_routes).delete("ns/svc")

    subject.send(:promote_timer_routes, "ns/svc")

    assert_nil subject.instance_variable_get(:@queue_routes)["ns/svc"]
  end
end
