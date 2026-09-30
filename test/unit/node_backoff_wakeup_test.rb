# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"

# A backoff that ended between two periodic syncs waited for the next one,
# 2-5 s on top of each of kubelet's 10/20/40 s delays.  The Pod is woken when
# its backoff ends.
class NodeBackoffWakeupTest < Minitest::Test
  Node = Rubernetes::Node

  class Runtime
    def initialize = @sequence = 0
    def run_sandbox(_pod, runtime_class: nil) = "sandbox-1"
    def create_container(_sandbox, _spec) = "container-#{@sequence += 1}"
    def start_container(_id) = true
    def stop_container(_id, timeout: nil) = true
    def remove_container(_id) = true
    def remove_sandbox(_id) = true
    def wait_container(_id) = {"state" => "terminated", "exitCode" => 0}
  end

  def pod
    {"apiVersion" => "v1", "kind" => "Pod",
     "metadata" => {"name" => "crasher", "namespace" => "ns", "uid" => "u1"},
     "spec" => {"nodeName" => "n", "restartPolicy" => "Always", "containers" => [{"name" => "app", "image" => "img"}]}}
  end

  def test_a_backoff_asks_for_a_wakeup_when_it_ends
    now = 0.0
    restarts = Node::RestartManager.new(clock: -> { now }, sleeper: ->(seconds) { now += seconds })
    lifecycle = Node::Lifecycle.new(runtime: Runtime.new, restart_manager: restarts,
                                    clock: -> { Time.at(now).utc }, sleeper: ->(seconds) { now += seconds })
    wakeups = []
    lifecycle.wakeup = ->(uid, delay) { wakeups << [uid, delay] }
    lifecycle.start(pod)

    now += 1
    lifecycle.handle_container_exit(pod, container_name: "app", exit_code: 1, now: now)

    assert_empty wakeups, "the first failure restarts at once"
    lifecycle.reconcile(pod)
    now += 1
    lifecycle.handle_container_exit(pod, container_name: "app", exit_code: 1, now: now)

    assert_equal [["u1", restarts.backoff("u1/app").to_f]], wakeups
    assert_operator wakeups.first.last, :>, 0
  end
end
