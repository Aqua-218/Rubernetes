# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"

# A restarted container that exits before the restarting thread records its
# start: the exit took its restart count from the previous run's status (0),
# and the Pod finished Succeeded with restartCount 0 where 1 was due
# ("Container Runtime blackbox test ... terminate-cmd-rpof", round 101).
class NodeRestartExitRaceTest < Minitest::Test
  Node = Rubernetes::Node

  class Runtime
    attr_accessor :on_start

    def initialize = @sequence = 0
    def run_sandbox(_pod, runtime_class: nil) = "sandbox-1"
    def create_container(_sandbox, _spec) = "container-#{@sequence += 1}"

    def start_container(id)
      on_start&.call(id)
      true
    end

    def stop_container(_id, timeout: nil) = true
    def remove_container(_id) = true
    def remove_sandbox(_id) = true
    def wait_container(_id) = {"state" => "terminated", "exitCode" => 0}
  end

  def pod
    {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "rpof", "namespace" => "ns", "uid" => "u1"},
     "spec" => {"nodeName" => "n", "restartPolicy" => "OnFailure", "containers" => [{"name" => "app", "image" => "img"}]}}
  end

  def test_an_exit_during_the_restart_keeps_the_new_restart_count
    now = 0.0
    runtime = Runtime.new
    restarts = Node::RestartManager.new(clock: -> { now }, sleeper: ->(seconds) { now += seconds })
    lifecycle = Node::Lifecycle.new(runtime: runtime, restart_manager: restarts,
                                    clock: -> { Time.at(now).utc }, sleeper: ->(seconds) { now += seconds })
    lifecycle.start(pod)
    runtime.on_start = lambda do |id|
      next unless id == "container-2"

      runtime.on_start = nil
      lifecycle.handle_container_exit(pod, container_name: "app", exit_code: 0, now: now)
    end
    now += 1
    lifecycle.handle_container_exit(pod, container_name: "app", exit_code: 1, now: now)

    status = lifecycle.record(pod).fetch(:status).fetch("containerStatuses").first

    assert_equal 1, status.fetch("restartCount")
    assert status.fetch("state").key?("terminated"), status.inspect
  end
end
