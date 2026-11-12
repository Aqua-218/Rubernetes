# frozen_string_literal: true

require "test_helper"
require "rubernetes/bootstrap"

# kube_api_qps / kube_api_burst: a component's own limit on its API requests.
class BootstrapApiRateConfigTest < Minitest::Test
  Assembler = Rubernetes::Bootstrap::Assembler

  def builder
    Assembler.allocate
  end

  def test_the_configured_rate_reaches_the_client
    client = builder.send(:build_api_client, {"api_server" => "https://127.0.0.1:6443", "kube_api_qps" => 20, "kube_api_burst" => 30})
    limiter = client.rest_client.instance_variable_get(:@rate_limiter)

    assert_equal [20.0, 30], [limiter.qps, limiter.burst]
  end

  def test_no_rate_means_no_client_side_limit
    client = builder.send(:build_api_client, {"api_server" => "https://127.0.0.1:6443"})

    assert_nil client.rest_client.instance_variable_get(:@rate_limiter)
  end

  def test_the_keys_are_validated_for_every_component
    config = Rubernetes::Bootstrap::Config.allocate

    config.send(:validate_api_rate!, {"kube_api_qps" => 50, "kube_api_burst" => 100}, "rubernetes-scheduler")
    assert_raises(Rubernetes::Bootstrap::Config::Error) { config.send(:validate_api_rate!, {"kube_api_qps" => 0}, "rubernetes-scheduler") }
    assert_raises(Rubernetes::Bootstrap::Config::Error) { config.send(:validate_api_rate!, {"kube_api_burst" => 10}, "rubernetes-scheduler") }
    C_KEYS.each { |keys| assert_includes keys, "kube_api_qps" }
  end

  C_KEYS = [Rubernetes::Bootstrap::Config::CONTROL_PLANE_KEYS, Rubernetes::Bootstrap::Config::SCHEDULER_KEYS,
            Rubernetes::Bootstrap::Config::PROXY_KEYS, Rubernetes::Bootstrap::Config::AGENT_KEYS].freeze
end
