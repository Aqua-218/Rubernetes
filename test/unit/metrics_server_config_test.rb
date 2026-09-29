# frozen_string_literal: true

require "tempfile"
require_relative "../test_helper"
require "rubernetes/bootstrap/config"

# rubernetes-controller-manager.metrics_server: the optional metrics.k8s.io
# component's settings are validated like every other process key.
class MetricsServerConfigTest < Minitest::Test
  Config = Rubernetes::Bootstrap::Config

  def load(metrics_server)
    file = Tempfile.new(["cm", ".yml"])
    file.write(<<~YAML)
      version: 1
      logging:
        level: info
      processes:
        rubernetes-controller-manager:
          api_server: http://127.0.0.1:6443
          metrics_server: #{metrics_server.to_json}
    YAML
    file.flush
    Config.load(process_name: "rubernetes-controller-manager", path: file.path)
  ensure
    file&.close
  end

  def test_valid_settings_load
    config = load({"enabled" => true, "port" => 4443, "metric_resolution_seconds" => 15, "kubelet_scheme" => "http",
                   "register" => true, "advertise_address" => "10.0.0.1"})
    assert_equal true, config.process.dig("metrics_server", "enabled")
  end

  def test_invalid_settings_are_rejected
    assert_raises(Config::Error) { load({"enabled" => "yes"}) }
    assert_raises(Config::Error) { load({"port" => 70_000}) }
    assert_raises(Config::Error) { load({"kubelet_scheme" => "ftp"}) }
    assert_raises(Config::Error) { load({"register" => true}) }
    assert_raises(Config::Error) { load({"surprise" => 1}) }
  end
end
