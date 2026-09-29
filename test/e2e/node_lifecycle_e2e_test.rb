# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"

class NodeLifecycleE2ETest < Minitest::Test
  class API
    attr_reader :nodes, :leases

    def initialize
      @nodes = []
      @leases = []
    end

    def register_node(node)
      @nodes << node
      node
    end

    def renew_lease(lease)
      @leases << lease
      lease
    end

    def list(**_options)
      {"items" => [], "metadata" => {"resourceVersion" => "0"}}
    end

    def watch(**_options)
      []
    end
  end

  class Runtime
    def initialize
      @counter = 0
    end

    def run_sandbox(_pod, runtime_class: nil)
      "sandbox-#{runtime_class || "native"}"
    end

    def create_container(_sandbox, _spec)
      @counter += 1
      "container-#{@counter}"
    end

    def start_container(_id)
      true
    end

    def signal(_id, _signal)
      true
    end

    def stop_container(_id, timeout:)
      @last_timeout = timeout
      true
    end

    def remove_container(_id)
      true
    end

    def remove_sandbox(_id)
      true
    end
  end

  def test_agent_registers_renews_and_completes_one_pod_lifecycle
    api = API.new
    agent = Rubernetes::Node::Agent.new(
      node_name: "node-1",
      api: api,
      runtime: Runtime.new,
      sleeper: ->(_seconds) {}
    )
    pod = {
      "apiVersion" => "v1",
      "kind" => "Pod",
      "metadata" => {"name" => "demo", "namespace" => "default", "uid" => "pod-1"},
      "spec" => {"nodeName" => "node-1", "containers" => [{"name" => "app", "image" => "example/app"}]}
    }

    agent.register
    agent.run_once(events: [{"type" => "ADDED", "object" => pod, "resourceVersion" => "1"}], resync: false)
    agent.sync_loop.instance_variable_get(:@workers).drain(timeout: 1)

    assert agent.registered?
    assert agent.ready?
    assert_equal "node-1", api.nodes.first.dig("metadata", "name")
    assert_equal "node-1", api.leases.last.dig("spec", "holderIdentity")
    assert_equal "Running", agent.lifecycle.state("pod-1")

    result = agent.lifecycle.terminate(pod)
    assert_equal "Succeeded", result.phase
  end
end
