# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/api"

# k8s.io/apiserver defaults an empty request Content-Type to application/json,
# and kube-apiserver proxies the request verbatim.  The e2e Aggregator spec's
# flunder POST carries a JSON body with NO Content-Type; Net::HTTP would stamp
# it application/x-www-form-urlencoded and the backend answers 415.
class AggregatorBodyContentTypeTest < Minitest::Test
  def test_a_body_without_content_type_is_proxied_as_json
    sent = {}
    factory = lambda do |_uri, _backend|
      http = Object.new
      http.define_singleton_method(:request) do |req|
        sent[:content_type] = req["content-type"]
        sent[:body] = req.body
        r = Net::HTTPCreated.new("1.1", "201", "Created")
        r.instance_variable_set(:@body, "{}"); r.instance_variable_set(:@read, true)
        r["content-type"] = "application/json"
        r
      end
      http
    end
    aggregator = Rubernetes::API::Aggregator.new(http_factory: factory, service_resolver: ->(_n, _s, _p) { ["10.0.0.5", 443] })
    aggregator.sync({"metadata" => {"name" => "v1alpha1.wardle.example.com"},
                     "spec" => {"group" => "wardle.example.com", "version" => "v1alpha1",
                                "service" => {"name" => "s", "namespace" => "ns", "port" => 443}, "insecureSkipTLSVerify" => true}})
    aggregator.mark_available("v1alpha1.wardle.example.com", true)
    request = Struct.new(:method, :path, :query, :body, :identity, :headers) { def header(name) = (headers || {})[name] }.new(
      "POST", "/apis/wardle.example.com/v1alpha1/namespaces/default/flunders", {}, '{"kind":"Flunder"}', nil, {"accept" => "application/json"}
    )

    response = aggregator.proxy(request, group: "wardle.example.com", version: "v1alpha1")

    assert_equal 201, response.status
    assert_equal "application/json", sent[:content_type]
    assert_equal '{"kind":"Flunder"}', sent[:body]
  end

  def test_an_explicit_content_type_is_preserved
    sent = {}
    factory = lambda do |_uri, _backend|
      http = Object.new
      http.define_singleton_method(:request) do |req|
        sent[:content_type] = req["content-type"]
        r = Net::HTTPCreated.new("1.1", "201", "Created")
        r.instance_variable_set(:@body, "{}"); r.instance_variable_set(:@read, true)
        r["content-type"] = "application/json"
        r
      end
      http
    end
    aggregator = Rubernetes::API::Aggregator.new(http_factory: factory, service_resolver: ->(_n, _s, _p) { ["10.0.0.5", 443] })
    aggregator.sync({"metadata" => {"name" => "v1alpha1.wardle.example.com"},
                     "spec" => {"group" => "wardle.example.com", "version" => "v1alpha1",
                                "service" => {"name" => "s", "namespace" => "ns", "port" => 443}, "insecureSkipTLSVerify" => true}})
    aggregator.mark_available("v1alpha1.wardle.example.com", true)
    request = Struct.new(:method, :path, :query, :body, :identity, :headers) { def header(name) = (headers || {})[name] }.new(
      "POST", "/apis/wardle.example.com/v1alpha1/namespaces/default/flunders", {}, "encoded", nil,
      {"content-type" => "application/vnd.kubernetes.protobuf"}
    )

    aggregator.proxy(request, group: "wardle.example.com", version: "v1alpha1")
    assert_equal "application/vnd.kubernetes.protobuf", sent[:content_type]
  end
end
