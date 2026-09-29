# frozen_string_literal: true

require "json"
require_relative "../test_helper"
require "rubernetes/api"

# pods/exec, pods/attach and pods/portforward go through admission upstream as
# CONNECT operations (pkg/registry/core/pod/rest/subresources.go): the webhook
# is handed the options object built from the query string.  Ours
# dispatched straight to the streaming bridge, so a webhook that denies an
# attach was never called and the client hung on an open stream instead of
# seeing the denial -- "[sig-api-machinery] AdmissionWebhook should be able to
# deny attaching pod" reported a kubectl timeout.
class StreamingSubresourceAdmissionTest < Minitest::Test
  API = Rubernetes::API

  def server
    @server ||= API::Server.allocate
  end

  def options_for(kind, query)
    request = API::Request.new(method: "POST", path: "/api/v1/namespaces/ns/pods/p/attach", query: query)
    server.send(:streaming_options, request, kind)
  end

  def test_attach_options_carry_the_stream_flags_a_webhook_inspects
    options = options_for("PodAttachOptions",
                          {"stdin" => "true", "stdout" => "true", "container" => "container1"})

    assert_equal("PodAttachOptions", options.fetch("kind"))
    assert_equal("v1", options.fetch("apiVersion"))
    assert(options.fetch("stdin"))
    assert(options.fetch("stdout"))
    assert_equal("container1", options.fetch("container"))
    refute(options.key?("tty"))
  end

  def test_exec_options_carry_the_command
    options = options_for("PodExecOptions", {"command" => %w[/bin/sh -c date], "tty" => "true"})

    assert_equal(%w[/bin/sh -c date], options.fetch("command"))
    assert(options.fetch("tty"))
  end

  def test_port_forward_options_carry_the_ports_as_integers
    options = options_for("PodPortForwardOptions", {"ports" => "80,443"})

    assert_equal([80, 443], options.fetch("ports"))
  end

  # Records what the admission hooks are called with.
  def admitted_for(method)
    calls = []
    subject = API::Server.allocate
    subject.define_singleton_method(:admit_mutating) { |_request, _route, operation, *_rest, **_kw| calls << [:mutating, operation] }
    subject.define_singleton_method(:admit_validating) { |_request, _route, operation, *_rest, **_kw| calls << [:validating, operation] }
    route = Struct.new(:subresource, :namespace, :name).new("attach", "ns", "p")
    request = API::Request.new(method: method, path: "/api/v1/namespaces/ns/pods/p/attach", query: {"stdin" => "true"})
    subject.send(:admit_streaming_subresource, request, route)
    calls
  end

  # The e2e webhook is registered for Operations: [CONNECT]; a CREATE matched
  # no rule and the attach went ahead.
  def test_a_streaming_request_is_admitted_as_connect
    assert_equal [[:mutating, :connect], [:validating, :connect]], admitted_for("POST")
  end

  # kubectl 1.36 opens exec and attach over a WebSocket, which is a GET.
  def test_a_websocket_get_is_admitted_too
    assert_equal [[:mutating, :connect], [:validating, :connect]], admitted_for("GET")
  end

  def test_a_non_streaming_subresource_is_not_admitted_as_a_stream
    assert_nil(API::Server::STREAMING_ADMISSION_KINDS["log"])
    assert_equal("PodAttachOptions", API::Server::STREAMING_ADMISSION_KINDS.fetch("attach"))
  end
end
