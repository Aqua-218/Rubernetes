# frozen_string_literal: true

require "test_helper"

module Dashboard
  class ConfigTest < ActiveSupport::TestCase
    def with_env(pairs)
      saved = pairs.keys.to_h { |k| [k, ENV.fetch(k, nil)] }
      pairs.each { |k, v| v.nil? ? ENV.delete(k) : ENV[k] = v }
      yield
    ensure
      saved.each { |k, v| v.nil? ? ENV.delete(k) : ENV[k] = v }
    end

    test "allowed hosts default to local names plus the external URL host" do
      with_env("DASHBOARD_HOSTS" => nil, "DASHBOARD_EXTERNAL_URL" => "https://dashboard.dev.provn-vm.jp/",
               "DASHBOARD_BIND" => "10.240.0.1") do
        hosts = Dashboard::Config.allowed_hosts

        assert_includes hosts, "localhost"
        assert_includes hosts, "10.240.0.1"
        assert_includes hosts, "dashboard.dev.provn-vm.jp"
        assert_includes hosts, Socket.gethostname
      end
    end

    test "DASHBOARD_HOSTS overrides the default list and empty disables the check" do
      with_env("DASHBOARD_HOSTS" => "a.example.com, .b.example.com", "DASHBOARD_EXTERNAL_URL" => "https://x.example.com/") do
        assert_equal ["a.example.com", ".b.example.com"], Dashboard::Config.allowed_hosts
      end
      with_env("DASHBOARD_HOSTS" => "") do
        assert_equal [], Dashboard::Config.allowed_hosts
      end
    end
    with_env("DASHBOARD_HOSTS" => "") do
      assert_equal [], Dashboard::Config.allowed_hosts
    end
  end

  test "a malformed external URL does not break the host list" do
    with_env("DASHBOARD_HOSTS" => nil, "DASHBOARD_EXTERNAL_URL" => "http://bad url") do
      assert_includes Dashboard::Config.allowed_hosts, "localhost"
    end
  end
end
