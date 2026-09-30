# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/security"

# AuthorizePodWebsocketUpgradeCreatePermission (Beta, on): kubectl exec,
# attach and port-forward over a WebSocket are GET requests, and a "get"
# grant on pods/exec was enough to run commands in a Pod.  The request is now
# authorized for "create" too, as the pod REST handlers' ensureAuthorizedForVerb does.
class WebsocketUpgradeCreatePermissionTest < Minitest::Test
  S = Rubernetes::Security
  Attributes = S::Authorization::Attributes

  class Recorder
    attr_reader :asked

    def initialize(allowed) = (@allowed = allowed) && (@asked = [])

    def authorize(attributes)
      @asked << [attributes.verb, attributes.subresource]
      allowed = @allowed.include?(attributes.verb)
      Struct.new(:allowed?, :reason).new(allowed, allowed ? nil : "no #{attributes.verb}")
    end
  end

  def attributes(verb, subresource)
    Attributes.new(user: S::UserInfo.new(name: "alice"), verb: verb, namespace: "ns", resource: "pods", subresource: subresource, name: "p",
                   resource_request: true)
  end

  def test_get_on_a_streaming_subresource_also_needs_create
    only_get = Recorder.new(%w[get])
    pipeline = S::Pipeline.new(authorizer: only_get)
    error = assert_raises(S::Pipeline::Forbidden) { pipeline.send(:authorize!, attributes("get", "exec")) }
    assert_equal "create", error.attributes.verb
    assert_equal [%w[get exec], %w[create exec]], only_get.asked

    both = Recorder.new(%w[get create])
    S::Pipeline.new(authorizer: both).send(:authorize!, attributes("get", "portforward"))

    assert_equal [%w[get portforward], %w[create portforward]], both.asked
  end

  def test_other_requests_are_asked_once
    recorder = Recorder.new(%w[get create])
    pipeline = S::Pipeline.new(authorizer: recorder)
    pipeline.send(:authorize!, attributes("create", "exec"))
    pipeline.send(:authorize!, attributes("get", "log"))
    pipeline.send(:authorize!, attributes("get", ""))

    assert_equal [%w[create exec], %w[get log], ["get", ""]], recorder.asked
  end
end
