# frozen_string_literal: true

require "test_helper"
require "tmpdir"

class Dashboard::RuntimeTest < ActiveSupport::TestCase
  test "components are built once, lazily, and nested builds do not deadlock" do
    Dir.mktmpdir do |dir|
      saved = ENV.slice("DASHBOARD_DATA_DIR", "RUBERNETES_CLUSTER_JSON")
      ENV["DASHBOARD_DATA_DIR"] = dir
      ENV["RUBERNETES_CLUSTER_JSON"] = File.join(dir, "absent.json") # no host cluster leaks in
      client = Object.new
      client.define_singleton_method(:get) { |*| {"items" => []} }
      runtime = Dashboard::Runtime.new(client: client, kubeconfig_context: {server: "https://api"})
      collector = runtime.collector # builds store, scraper, engine, rules, targets inside one lock

      assert_same collector, runtime.collector
      assert_same runtime.store, runtime.engine.store
      assert_same runtime.scraper, collector.scraper
      # Concurrent first access yields one store, never two writers.
      threads = 8.times.map { Thread.new { runtime.store } }

      assert_equal 1, threads.map(&:value).uniq.length
      assert_kind_of Prom::Rules, runtime.rules
      collector.round

      assert_equal 1, collector.targets.length, "the built-in kube-state target"
      runtime.stop
    ensure
      %w[DASHBOARD_DATA_DIR RUBERNETES_CLUSTER_JSON].each { |k| saved[k].nil? ? ENV.delete(k) : ENV[k] = saved[k] }
    end
  end
end
