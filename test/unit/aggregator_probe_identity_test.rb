# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/api"

# kube-aggregator's availability check and discovery requests authenticate
# to the extension API server through the front proxy: its client
# certificate plus X-Remote-User system:kube-aggregator in system:masters
# (remote_available_controller SetAuthProxyHeaders).  Without the headers the
# sample API server answered the availability check 401.
class AggregatorProbeIdentityTest < Minitest::Test
  class RecordingHTTP
    attr_reader :calls

    def initialize(calls) = @calls = calls
    def use_ssl=(_value); end
    def open_timeout=(_value); end
    def read_timeout=(_value); end
    def verify_mode=(_value); end
    def cert_store=(_value); end
    def cert=(_value); end
    def key=(_value); end

    def get(path, headers = {})
      @calls << [path, headers]
      Struct.new(:code, :body).new(headers["X-Remote-User"] == "system:kube-aggregator" ? "200" : "401", "{}")
    end
  end

  def test_availability_and_discovery_probes_carry_the_aggregator_identity
    calls = []
    aggregator = Rubernetes::API::Aggregator.new(http_factory: ->(_uri, _backend) { RecordingHTTP.new(calls) })
    aggregator.sync({"metadata" => {"name" => "v1alpha1.wardle.example.com"},
                     "spec" => {"group" => "wardle.example.com", "version" => "v1alpha1", "insecureSkipTLSVerify" => true,
                                "service" => {"namespace" => "aggregator", "name" => "sample-api", "port" => 7443}}})
    backend = aggregator.backend("v1alpha1.wardle.example.com")
    condition = aggregator.availability_condition(backend, skip_endpoint_checks: true)
    assert_equal "True", condition["status"], condition.inspect
    assert aggregator.available?(backend)
    aggregator.resource_list("wardle.example.com", "v1alpha1")
    assert_equal 3, calls.length
    calls.each do |path, headers|
      assert_equal "/apis/wardle.example.com/v1alpha1", path
      assert_equal "system:kube-aggregator", headers["X-Remote-User"]
      assert_equal "system:masters", headers["X-Remote-Group"]
    end
  end
end
