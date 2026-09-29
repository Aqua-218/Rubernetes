# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"

# spec.ephemeralContainers is restart-neutral on purpose: adding one must not
# restart the Pod, so the field is stripped from the config digest.  The sync
# that starts the new container was nevertheless nested inside the "config
# digest changed" branch, which that same stripping guarantees is never taken
# for an ephemeral-only update -- the branch was unreachable and the container
# sat in ContainerCreating for ever.  Conformance: "[sig-node] Ephemeral
# Containers will start an ephemeral container in an existing pod" and
# "... should update the ephemeral containers in an existing pod".
class NodeEphemeralContainerStartTest < Minitest::Test
  class Runtime
    attr_reader :created

    def initialize
      @created = []
      @counter = 0
    end

    def run_sandbox(_pod, runtime_class: nil) = "sandbox-1"

    def create_container(_sandbox, spec)
      @created << spec.fetch("name")
      @counter += 1
      "container-#{@counter}"
    end

    def start_container(_id) = true
    def wait_container(_id) = {"state" => "running"}
    def stop_container(_id, timeout:) = true
    def kill_container(_id, signal:) = true
    def remove_container(_id) = true
    def remove_sandbox(_id) = true
  end

  def pod(ephemeral: [])
    spec = {"nodeName" => "node-1", "containers" => [{"name" => "app", "image" => "example/app"}]}
    spec["ephemeralContainers"] = ephemeral unless ephemeral.empty?
    {"apiVersion" => "v1", "kind" => "Pod",
     "metadata" => {"name" => "demo", "namespace" => "default", "uid" => "pod-1"},
     "spec" => spec}
  end

  def lifecycle(runtime)
    Rubernetes::Node::Lifecycle.new(runtime: runtime, sleeper: ->(_seconds) {})
  end

  def test_an_ephemeral_container_added_to_a_running_pod_is_started_in_place
    runtime = Runtime.new
    subject = lifecycle(runtime)
    subject.start(pod)
    runtime.created.clear

    subject.sync(pod(ephemeral: [{"name" => "debugger", "image" => "example/debug"}]))

    assert_includes runtime.created, "debugger"
  end

  def test_a_second_ephemeral_container_is_started_without_restarting_the_first
    runtime = Runtime.new
    subject = lifecycle(runtime)
    subject.start(pod)
    first = [{"name" => "debugger", "image" => "example/debug"}]
    subject.sync(pod(ephemeral: first))
    runtime.created.clear

    subject.sync(pod(ephemeral: first + [{"name" => "debugger-2", "image" => "example/debug"}]))

    assert_equal ["debugger-2"], runtime.created
  end

  def test_re_syncing_the_same_spec_starts_nothing_again
    runtime = Runtime.new
    subject = lifecycle(runtime)
    subject.start(pod)
    desired = pod(ephemeral: [{"name" => "debugger", "image" => "example/debug"}])
    subject.sync(desired)
    runtime.created.clear

    subject.sync(desired)

    assert_empty runtime.created
  end
end
