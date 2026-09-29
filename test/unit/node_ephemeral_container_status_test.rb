# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"

# An ephemeral container has a status list of its own upstream
# (status.ephemeralContainerStatuses).  Ours folded it in with the init
# containers, so the debug container was invisible to every client that waits
# for it -- "[sig-node] Ephemeral Containers will start an ephemeral container
# in an existing pod" watches exactly that list.
class NodeEphemeralContainerStatusTest < Minitest::Test
  Status = Rubernetes::Node::Status

  def setup
    @aggregator = Status.new(clock: -> { Time.at(1_700_000_000).utc })
  end

  def pod(ephemeral: [], init: [])
    spec = {"nodeName" => "node-a", "containers" => [{"name" => "app", "image" => "img"}]}
    spec["initContainers"] = init unless init.empty?
    spec["ephemeralContainers"] = ephemeral unless ephemeral.empty?
    {"apiVersion" => "v1", "kind" => "Pod",
     "metadata" => {"name" => "p", "namespace" => "ns", "uid" => "u"}, "spec" => spec}
  end

  def status_for(pod_object, state)
    @aggregator.aggregate(pod: pod_object, state: state, phase: "Running").to_h
  end

  def running
    {"state" => "running", "ready" => true, "started" => true}
  end

  def test_an_ephemeral_container_gets_its_own_status_list
    state = {"containers" => {"app" => running},
             "initContainers" => {},
             "ephemeralContainers" => {"debugger" => running}}
    result = status_for(pod(ephemeral: [{"name" => "debugger", "image" => "busybox"}]), state)

    assert_equal(%w[debugger], result.fetch("ephemeralContainerStatuses").map { |entry| entry.fetch("name") })
    assert_equal(%w[app], result.fetch("containerStatuses").map { |entry| entry.fetch("name") })
    assert_empty(result.fetch("initContainerStatuses"))
  end

  def test_a_pod_without_ephemeral_containers_reports_no_list
    state = {"containers" => {"app" => running}, "initContainers" => {}}

    refute(status_for(pod, state).key?("ephemeralContainerStatuses"))
  end

  def test_an_ephemeral_container_does_not_land_in_the_init_list
    state = {"containers" => {"app" => running},
             "initContainers" => {"setup" => {"state" => "terminated", "exitCode" => 0, "ready" => false}},
             "ephemeralContainers" => {"debugger" => running}}
    result = status_for(pod(init: [{"name" => "setup", "image" => "img"}],
                            ephemeral: [{"name" => "debugger", "image" => "busybox"}]), state)

    assert_equal(%w[setup], result.fetch("initContainerStatuses").map { |entry| entry.fetch("name") })
    assert_equal(%w[debugger], result.fetch("ephemeralContainerStatuses").map { |entry| entry.fetch("name") })
  end
end
