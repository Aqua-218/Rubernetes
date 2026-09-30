# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"

# A started ephemeral container was only published by the next probe pass;
# once unchanged probe passes stopped republishing status, the debug
# container never showed as running ("Ephemeral Containers ... will start an
# ephemeral container in an existing pod", round 103).
class NodeEphemeralStatusPublishTest < Minitest::Test
  Node = Rubernetes::Node

  class Runtime
    def initialize = @sequence = 0
    def run_sandbox(_pod, runtime_class: nil) = "sandbox-1"
    def create_container(_sandbox, _spec) = "container-#{@sequence += 1}"
    def start_container(_id) = true
    def stop_container(_id, timeout: nil) = true
    def remove_container(_id) = true
    def remove_sandbox(_id) = true
    def wait_container(_id) = {"state" => "running"}
  end

  def pod(ephemeral: false)
    spec = {"nodeName" => "n", "containers" => [{"name" => "app", "image" => "img"}]}
    spec["ephemeralContainers"] = [{"name" => "debugger", "image" => "busybox"}] if ephemeral
    {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "p", "namespace" => "ns", "uid" => "u1"}, "spec" => spec}
  end

  def test_a_started_ephemeral_container_is_published_at_once
    published = []
    lifecycle = Node::Lifecycle.new(runtime: Runtime.new)
    lifecycle.start(pod)
    lifecycle.define_singleton_method(:update_status) do |object, record|
      published << record[:containers].map { |entry| entry[:name] }
      super(object, record)
    end
    lifecycle.reconcile(pod(ephemeral: true))

    assert(published.any? { |names| names.include?("debugger") }, "the debug container's start was published")
    statuses = lifecycle.record(pod).fetch(:status).fetch("ephemeralContainerStatuses", [])

    assert(statuses.any? { |status| status["name"] == "debugger" && status.dig("state", "running") }, statuses.inspect)
  end
end
