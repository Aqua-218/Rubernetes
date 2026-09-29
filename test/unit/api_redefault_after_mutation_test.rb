# frozen_string_literal: true

require "json"
require_relative "../test_helper"
require File.expand_path("../../generated/ruby/kubernetes_types", __dir__)
require "rubernetes/api"

# A mutating webhook adds fields the client never sent -- a whole container, in
# the conformance spec "AdmissionWebhook should mutate pod and apply defaults
# after mutation" -- and upstream defaults the patched object again before
# anything else looks at it (admission/plugin/webhook/mutating/patch.go applies
# the scheme defaulter to the patched versioned object).  Ours defaulted only
# what the client sent, so a webhook-added container reached the store with no
# terminationMessagePolicy, no imagePullPolicy and no resources.
class APIRedefaultAfterMutationTest < Minitest::Test
  API = Rubernetes::API

  def resource
    API::Resource.new(group: "", version: "v1", resource: "pods", kind: "Pod", scope: :namespaced,
                      schema: Rubernetes::Generated.definition_for("io.k8s.api.core.v1.Pod"))
  end

  def server
    @server ||= API::Server.allocate
  end

  def pod(containers)
    {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "p", "namespace" => "dev"},
     "spec" => {"containers" => containers}}
  end

  def test_a_container_added_after_defaulting_is_defaulted_again
    before = server.send(:apply_defaults_only, resource, pod([{"name" => "app", "image" => "busybox:1.36"}]))
    mutated = JSON.parse(JSON.generate(before))
    mutated["spec"]["initContainers"] = [{"name" => "webhook-added-init-container",
                                          "image" => "webhook-added-image"}]

    result = server.send(:redefault_after_mutation, resource, mutated, before)
    added = result.dig("spec", "initContainers", 0)

    assert_equal("File", added.fetch("terminationMessagePolicy"))
    assert_equal("/dev/termination-log", added.fetch("terminationMessagePath"))
    assert_equal("Always", added.fetch("imagePullPolicy"))
    assert_equal({}, added.fetch("resources"))
  end

  def test_an_untouched_object_is_returned_as_is
    before = server.send(:apply_defaults_only, resource, pod([{"name" => "app", "image" => "busybox:1.36"}]))

    assert_same(before, server.send(:redefault_after_mutation, resource, before, before))
  end

  def test_the_original_container_keeps_its_defaults
    before = server.send(:apply_defaults_only, resource, pod([{"name" => "app", "image" => "busybox:1.36"}]))
    mutated = JSON.parse(JSON.generate(before))
    mutated["spec"]["initContainers"] = [{"name" => "added", "image" => "img"}]

    result = server.send(:redefault_after_mutation, resource, mutated, before)

    assert_equal("IfNotPresent", result.dig("spec", "containers", 0, "imagePullPolicy"))
  end
end
