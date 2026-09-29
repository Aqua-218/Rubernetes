# frozen_string_literal: true

# CRD conversion webhook metrics (apiextensions-apiserver conversion/metrics.go):
# apiserver_conversion_webhook_request_total / _duration_seconds by result and
# failure type, and apiserver_crd_conversion_webhook_duration_seconds by CRD
# and versions for single-object conversions.

require_relative "../test_helper"
require "rubernetes/api"

class APIServerConversionWebhookMetricsTest < Minitest::Test
  CRD_OBJECT = {
    "metadata" => {"name" => "widgets.example.com"},
    "spec" => {"group" => "example.com",
               "conversion" => {"strategy" => "Webhook",
                                "webhook" => {"conversionReviewVersions" => ["v1"], "clientConfig" => {"url" => "https://hook"}}}}
  }.freeze

  class Hook
    attr_accessor :mode

    def initialize = @mode = :ok

    def call(_config, review, timeout_seconds:)
      raise Errno::ECONNREFUSED, "hook" if @mode == :refused

      request = review["request"]
      objects = request["objects"].map { |object| object.merge("apiVersion" => request["desiredAPIVersion"]) }
      objects = objects.drop(1) if @mode == :partial
      objects = objects.map { |object| object.merge("apiVersion" => "example.com/v9") } if @mode == :wrong_version
      uid = @mode == :bad_uid ? "other" : request["uid"]
      [200, {"response" => {"uid" => uid, "result" => {"status" => "Success"}, "convertedObjects" => objects}}]
    end
  end

  def setup
    @metrics = Rubernetes::Observability::Metrics.new
    @previous = Rubernetes::API::CRD.metrics
    Rubernetes::API::CRD.metrics = @metrics
    @hook = Hook.new
    @converter = Rubernetes::API::CRD::Manager::Converter.new(crd: CRD_OBJECT, storage_version: "v1", webhook_client: @hook,
                                                              clock: -> { Time.now.utc })
  end

  def teardown
    Rubernetes::API::CRD.metrics = @previous
  end

  def widget(version, name = "w") = {"apiVersion" => "example.com/#{version}", "kind" => "Widget", "metadata" => {"name" => name, "uid" => name}}

  def value(line) = @metrics.render[/^#{Regexp.escape(line)} (\S+)$/, 1].to_f

  def test_successes_failures_and_per_crd_durations
    @converter.convert([widget("v1")], to_version: "v2")
    @converter.convert([widget("v1", "a"), widget("v2", "b")], to_version: "v2", list: true)
    # Nothing to convert still counts as a successful call.
    @converter.convert([widget("v2")], to_version: "v2")
    {refused: "call", bad_uid: "malformed_response", partial: "partial_response", wrong_version: "invalid_converted_object"}.each do |mode, _|
      @hook.mode = mode
      assert_raises(Rubernetes::API::CRD::Manager::ConversionError) { @converter.convert([widget("v1"), widget("v1", "x")], to_version: "v2") }
    end

    assert_equal 3, value('apiserver_conversion_webhook_request_total{failure_type="",result="success"}')
    %w[call malformed_response partial_response invalid_converted_object].each do |kind|
      assert_equal 1, value(%(apiserver_conversion_webhook_request_total{failure_type="conversion_webhook_#{kind}_failure",result="failure"}))
      assert_equal 1, value(%(apiserver_conversion_webhook_duration_seconds_count{failure_type="conversion_webhook_#{kind}_failure",result="failure"}))
    end
    crd = 'crd_name="widgets.example.com",from_version="v1"'
    # The single-object conversion; the list and the no-op are not observed.
    assert_equal 1, value("apiserver_crd_conversion_webhook_duration_seconds_count{#{crd},succeeded=\"true\",to_version=\"v2\"}")
    assert_equal 4, value("apiserver_crd_conversion_webhook_duration_seconds_count{#{crd},succeeded=\"false\",to_version=\"v2\"}")
    text = @metrics.render
    assert_match(/^apiserver_crd_conversion_webhook_duration_seconds_bucket\{#{crd},succeeded="true",to_version="v2",le="16\.384"\} 1$/, text)
    assert_match(/^apiserver_conversion_webhook_duration_seconds_bucket\{failure_type="",result="success",le="45"\} 3$/, text)
  end

  def test_none_strategy_records_nothing
    converter = Rubernetes::API::CRD::Manager::Converter.new(crd: CRD_OBJECT.merge("spec" => {"group" => "example.com"}), storage_version: "v1",
                                                             webhook_client: nil, clock: -> { Time.now.utc })
    converter.convert([widget("v1")], to_version: "v2")
    refute_match(/^apiserver_conversion_webhook_request_total/, @metrics.render)
  end
end
