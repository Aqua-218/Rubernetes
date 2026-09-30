# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/api"
require "rubernetes/api/crd/structural_schema"
require "rubernetes/observability/metrics"

# WithTimeoutForNonLongRunningRequests and CRDValidationRatcheting.
class ApiserverTimeoutAndRatchetingTest < Minitest::Test
  API = Rubernetes::API

  def server
    @server ||= API::Server.new(registry: API::Registry.new, store: API::MemoryStore.new, namespace_lifecycle: true)
  end

  def value(text, name, **labels)
    found = text.lines.map(&:chomp).find do |entry|
      entry.start_with?("#{name}{", "#{name} ") && labels.all? { |key, item| entry.include?("#{key}=\"#{item}\"") }
    end
    found && found.split[1]
  end

  def test_a_slow_non_long_running_request_is_aborted_with_504
    request = server.send(:normalize_request, {method: "GET", path: "/api/v1/namespaces?timeout=200ms", headers: {}})
    route = server.instance_variable_get(:@router).route(request)
    error = assert_raises(API::Status::Error) do
      server.send(:with_request_timeout, request, route) { sleep 5; :never }
    end
    assert_equal 504, error.code
    assert_equal "Timeout", error.reason
    text = server.instance_variable_get(:@metrics).render_own
    assert_equal "1", value(text, "apiserver_request_aborts_total", verb: "LIST", resource: "namespaces")
    assert_equal "1", value(text, "apiserver_request_post_timeout_total", source: "timeout-handler", status: "pending")
    sleep 5.2
    text = server.instance_variable_get(:@metrics).render_own
    assert_equal "1", value(text, "apiserver_request_post_timeout_total", source: "rest-handler", status: "ok")
  end

  def test_fast_requests_and_long_running_ones_pass_through
    request = server.send(:normalize_request, {method: "GET", path: "/api/v1/namespaces", headers: {}})
    route = server.instance_variable_get(:@router).route(request)
    assert_equal :done, server.send(:with_request_timeout, request, route) { :done }
    watch = server.send(:normalize_request, {method: "GET", path: "/api/v1/namespaces?watch=true", headers: {}})
    assert_nil server.send(:request_timeout_seconds, watch, server.instance_variable_get(:@router).route(watch))
    assert_in_delta 0.2, server.send(:request_timeout_seconds, request.with(path: "/api/v1/namespaces?timeout=200ms"), route), 0.001 if request.respond_to?(:with)
    assert_equal 60.0, server.send(:request_timeout_seconds, request, route)
    assert_in_delta 1.5, server.send(:parse_go_duration_seconds, "1m30s") / 60.0, 0.001
  end

  def test_an_update_ratchets_errors_in_unchanged_subtrees
    schema = {"type" => "object", "properties" => {
      "spec" => {"type" => "object", "properties" => {
        "size" => {"type" => "integer", "minimum" => 1},
        "name" => {"type" => "string", "maxLength" => 3}
      }}
    }}
    validator = API::CRD::StructuralSchema.new(schema)
    old = {"spec" => {"size" => 0, "name" => "ok"}}
    # size is unchanged and invalid: ratcheted; the changed name is checked.
    assert validator.validate({"spec" => {"size" => 0, "name" => "new"}}, old: old)
    error = assert_raises(API::CRD::StructuralSchema::Invalid) { validator.validate({"spec" => {"size" => 0, "name" => "toolong"}}, old: old) }
    assert_equal ["spec.name"], error.causes.map { |cause| cause["field"] }
    # A changed invalid value is never ratcheted; a create validates everything.
    assert_raises(API::CRD::StructuralSchema::Invalid) { validator.validate({"spec" => {"size" => -1, "name" => "ok"}}, old: old) }
    assert_raises(API::CRD::StructuralSchema::Invalid) { validator.validate({"spec" => {"size" => 0, "name" => "ok"}}) }
    text = Rubernetes::Observability::Metrics.global.render_own
    assert_match(/apiextensions_apiserver_validation_ratcheting_seconds_count \d+/, text)
  end
end
