# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"
require "rubernetes/runtime/cri/client"

# kubelet_cri_losing_support: a CRI runtime without RuntimeConfig is flagged
# with the release that drops it.
class CRISupportCheckTest < Minitest::Test
  Node = Rubernetes::Node

  Backend = Struct.new(:client, :handler)

  class Client
    def initialize(answer) = @answer = answer

    def runtime(_method, _request = {}, timeout: nil)
      raise @answer if @answer.is_a?(Exception)

      @answer
    end
  end

  def test_unimplemented_runtime_config_sets_the_gauge
    metrics = Node::KubeletMetrics.new(node_name: "worker-0")
    old = Backend.new(Client.new(Rubernetes::Runtime::CRI::Client::Error.new("unknown method RuntimeConfig", code: 12)), "runc")
    fresh = Backend.new(Client.new({"linux" => {"cgroup_driver" => "SYSTEMD"}}), "kata")
    runtime = Struct.new(:backends).new({"runc" => old, "kata" => fresh})
    flagged = Node::CRISupportCheck.run(runtime: runtime, metrics: metrics)

    assert_equal ["runc"], flagged.map(&:handler)
    assert_match(/kubelet_cri_losing_support\{version="1.37.0"\} 1/, metrics.registry.render_own)
    refute_match(/kubelet_cri_losing_support/, Node::KubeletMetrics.new(node_name: "w").registry.render_own,
                 "absent until a runtime is flagged")
    down = Backend.new(Client.new(Rubernetes::Runtime::CRI::Client::Error.new("connection refused")), "runc")

    assert_empty Node::CRISupportCheck.run(runtime: Struct.new(:backends).new({"runc" => down}), metrics: Node::KubeletMetrics.new(node_name: "w")),
                 "a transport failure is not a deprecation"
  end
end
